//! Optional host custody for Solana x402 V2 exact payments.
//!
//! Pay still fetches/classifies the initial response, consults SpendingAuthority,
//! builds with pay-kit and interprets the result. The controller owns signatures,
//! durable evidence, final credential-bearing HTTP and original-result recovery.
use crate::authority::SpendRequest;
use pay_core::client::{
    fetch::{RawResponse, raw_to_outcome},
    x402::Challenge,
};
use pay_kit::x402::exact::{PaymentRequiredEnvelope, PaymentRequirements};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;

/// Additional custody facts, kept separate so existing SpendingAuthority
/// providers and SpendRequest struct literals remain source-compatible.
#[derive(Clone, Serialize)]
pub struct ControlledRequest {
    pub spend: SpendRequest,
    /// Original SDK-selected envelope, including alternatives and extensions.
    /// Sensitive application/quote data: implementations must not log it.
    pub payment_required: Value,
}

#[derive(Serialize, Deserialize)]
pub struct ControlledResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct ControlledLifetime {
    pub recent_blockhash: String,
    pub last_valid_block_height: u64,
}

#[derive(Serialize, Deserialize)]
pub enum ExecutionPlan {
    /// Trusted host configuration, never accepted as curl tool arguments. Missing
    /// decimals are resolved through this RPC; blockhashes are always fetched or
    /// checked for validity on this endpoint.
    Build {
        payer: String,
        rpc_url: String,
        lifetime: Option<ControlledLifetime>,
    },
    /// Return a previously verified, credential-free result without rebuilding.
    Replay { response: ControlledResponse },
}

#[derive(Serialize, Deserialize)]
pub struct UnsignedPayment {
    pub transaction: String,
    pub lifetime: Option<ControlledLifetime>,
}

/// Configured alongside SpendingAuthority by the trusted PayContext. Methods run
/// on curl's blocking worker, not its async executor. Host errors are terminal:
/// Pay never falls back to its own wallet or credential-bearing HTTP.
///
/// The host must bind caller + operation + attempt + immutable request/offer,
/// inspect unsigned bytes before signing, persist original evidence and send
/// through its own controlled transport. Only verified delivery may be returned;
/// signed bytes, signatures and payment headers must never be returned to Pay.
/// A lost reply does not authorize a replacement payment. Replay and restart
/// safety belong to the host's durable state, not Pay's connection-local guard.
pub trait ControlledExecution: Send + Sync {
    fn plan(&self, request: &ControlledRequest) -> pay_core::Result<ExecutionPlan>;
    fn execute(
        &self,
        request: &ControlledRequest,
        unsigned: UnsignedPayment,
    ) -> pay_core::Result<ControlledResponse>;
}

fn rejected(code: &str) -> pay_core::Error {
    pay_core::Error::PaymentRejected(format!("Controlled execution: {code}"))
}

pub(crate) fn run(
    controller: &dyn ControlledExecution,
    spend: SpendRequest,
    payment_required: Option<Value>,
    challenge: &Challenge,
) -> pay_core::Result<pay_core::client::runner::RunOutcome> {
    let payment_required =
        payment_required.ok_or_else(|| rejected("ORIGINAL_ENVELOPE_REQUIRED"))?;
    let accepts = payment_required
        .get("accepts")
        .and_then(Value::as_array)
        .ok_or_else(|| rejected("ORIGINAL_ENVELOPE_REQUIRED"))?;
    if accepts
        .iter()
        .filter(|offer| **offer == spend.accepted)
        .count()
        != 1
    {
        return Err(rejected("SELECTED_OFFER_MISMATCH"));
    }
    let request = ControlledRequest {
        spend,
        payment_required,
    };
    let response = match controller.plan(&request)? {
        ExecutionPlan::Replay { response } => response,
        ExecutionPlan::Build {
            payer,
            rpc_url,
            lifetime,
        } => {
            let payer =
                solana_pubkey::Pubkey::from_str(&payer).map_err(|_| rejected("INVALID_PAYER"))?;
            let mut requirements = challenge.requirements.clone();
            if let Some(value) = &lifetime {
                if value.last_valid_block_height == 0
                    || requirements
                        .recent_blockhash
                        .as_ref()
                        .is_some_and(|expected| expected != &value.recent_blockhash)
                {
                    return Err(rejected("INVALID_LIFETIME"));
                }
                requirements.recent_blockhash = Some(value.recent_blockhash.clone());
            }
            let rpc = pay_kit::x402::solana_rpc_client::rpc_client::RpcClient::new_with_timeout(
                rpc_url,
                std::time::Duration::from_secs(5),
            );
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| rejected("RUNTIME_UNAVAILABLE"))?;
            let transaction = runtime
                .block_on(pay_kit::x402::client::exact::prepare_unsigned_payment(
                    &payer,
                    &rpc,
                    &requirements,
                    None,
                ))
                .map_err(|_| rejected("UNSIGNED_PREPARE_FAILED"))?;
            if transaction
                .signatures
                .iter()
                .any(|signature| signature.as_ref().iter().any(|byte| *byte != 0))
            {
                return Err(rejected("SIGNED_TRANSACTION_FORBIDDEN"));
            }
            let transaction = pay_kit::core::tx::encode(&transaction)
                .map_err(|_| rejected("WIRE_ENCODING_FAILED"))?;
            controller.execute(
                &request,
                UnsignedPayment {
                    transaction,
                    lifetime,
                },
            )?
        }
    };
    if !(100..=599).contains(&response.status) || response.body.len() > 65_536 {
        return Err(rejected("INVALID_RESPONSE"));
    }
    Ok(raw_to_outcome(RawResponse {
        url: request.spend.request.url,
        status: response.status,
        headers: response.headers,
        body: response.body,
    }))
}

/// Preserve the source chosen by the SDK: valid v2 header, valid legacy header,
/// then body. A legacy selection cannot be represented as a v2 custody envelope.
pub(crate) fn source_envelope(headers: &[(String, String)], body: Option<&str>) -> Option<Value> {
    use base64::Engine;
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    };
    let envelope = |bytes: &[u8]| {
        let raw: Value = serde_json::from_slice(bytes).ok()?;
        serde_json::from_value::<PaymentRequiredEnvelope>(raw.clone()).ok()?;
        Some(raw)
    };
    if let Some(value) = header(pay_kit::x402::PAYMENT_REQUIRED_HEADER)
        .and_then(|raw| base64::engine::general_purpose::STANDARD.decode(raw).ok())
        .and_then(|bytes| envelope(&bytes))
    {
        return Some(value);
    }
    if header(pay_kit::x402::X402_V1_PAYMENT_REQUIRED_HEADER)
        .is_some_and(|value| serde_json::from_str::<PaymentRequirements>(value).is_ok())
    {
        return None;
    }
    body.and_then(|value| envelope(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde_json::json;

    fn envelope(amount: &str) -> Value {
        json!({"x402Version":2,"resource":{"url":"https://example.com/data","description":"route metadata"},
            "accepts":[{"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "asset":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","amount":amount,
                "payTo":"11111111111111111111111111111111","maxTimeoutSeconds":60,"extra":{"decimals":6}}],
            "extensions":{"bazaar":{"info":{"input":{"queryParams":{"q":"sample"}}}}}})
    }

    #[test]
    fn preserves_full_sdk_selected_header_over_conflicting_body() {
        let mut selected = envelope("1000");
        let mut alternative = selected["accepts"][0].clone();
        alternative["amount"] = json!("2000");
        selected["accepts"]
            .as_array_mut()
            .unwrap()
            .push(alternative);
        let headers = vec![(
            "payment-required".into(),
            STANDARD.encode(selected.to_string()),
        )];
        assert_eq!(
            source_envelope(&headers, Some(&envelope("9000").to_string())),
            Some(selected)
        );
    }

    #[test]
    fn follows_sdk_fallback_and_never_replaces_a_valid_legacy_selection() {
        let body = envelope("3000");
        let headers = vec![("payment-required".into(), "malformed".into())];
        assert_eq!(
            source_envelope(&headers, Some(&body.to_string())),
            Some(body.clone())
        );
        let headers = vec![(
            pay_kit::x402::X402_V1_PAYMENT_REQUIRED_HEADER.into(),
            body["accepts"][0].to_string(),
        )];
        assert!(source_envelope(&headers, Some(&body.to_string())).is_none());
    }

    #[test]
    fn body_source_retains_route_metadata_and_extensions() {
        let body = envelope("1000");
        assert_eq!(source_envelope(&[], Some(&body.to_string())), Some(body));
        assert!(source_envelope(&[], Some("{} invalid")).is_none());
    }
}
