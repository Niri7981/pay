//! Optional custody boundary for exact x402. The controller owns signatures,
//! original-payment persistence, final HTTP, and economic reconciliation.
use crate::authority::SpendRequest;
use pay_kit::x402::exact::{PaymentRequirements, SOLANA_DEVNET, SOLANA_MAINNET};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{io::Read, str::FromStr, time::Duration};
const MAX_RESPONSE: usize = 65_536;
const MAINNET_USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const DEVNET_USDC: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
type SafeResult<T> = Result<T, &'static str>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "lowercase", deny_unknown_fields)]
pub enum ExecutionPlan {
    Build {
        payer: String,
        rpc_url: String,
        #[serde(default)]
        lifetime: Option<ControlledLifetime>,
    },
    Replay {
        response: ControlledResponse,
    },
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlledLifetime {
    pub recent_blockhash: String,
    pub last_valid_block_height: String,
}
/// Configured by the trusted host alongside SpendingAuthority. Implementations
/// must return only credential-free delivery after independently checking the
/// original payment. Errors and lost replies never authorize a replacement.
/// Called on the same blocking worker as do_paid_fetch, never the async executor.
pub trait ControlledExecution: Send + Sync {
    fn plan(&self, request: &SpendRequest) -> pay_core::Result<ExecutionPlan>;
    fn execute(
        &self,
        request: &SpendRequest,
        unsigned: Value,
    ) -> pay_core::Result<ControlledResponse>;
}

pub(crate) fn run(
    controller: &dyn ControlledExecution,
    facts: &SpendRequest,
) -> pay_core::Result<pay_core::client::runner::RunOutcome> {
    crate::authority::trace_execution(facts, "controlled_started");
    let response = match controller.plan(facts)? {
        ExecutionPlan::Replay { response } => {
            crate::authority::trace_execution(facts, "controlled_replay");
            response
        }
        ExecutionPlan::Build {
            payer,
            rpc_url,
            lifetime,
        } => {
            // A host-supplied lifetime avoids RPC entirely; the legacy isolated
            // profile retains its strictly loopback-only blockhash transport.
            let unsigned = prepare_with_lifetime(payer, rpc_url, facts.accepted.clone(), lifetime)
                .map_err(|code| pay_core::Error::PaymentRejected(code.into()))?;
            crate::authority::trace_execution(facts, "unsigned_prepared");
            controller.execute(facts, unsigned)?
        }
    };
    crate::authority::trace_execution(facts, "controlled_response");
    if !(100..=599).contains(&response.status) || response.body.len() > MAX_RESPONSE {
        return Err(pay_core::Error::PaymentRejected(
            "INVALID_CONTROLLED_RESPONSE".into(),
        ));
    }
    // Use the existing HTTP outcome classifier and original retry interpreter.
    Ok(pay_core::client::fetch::raw_to_outcome(
        pay_core::client::fetch::RawResponse {
            url: facts.request.url.clone(),
            status: response.status,
            headers: response.headers,
            body: response.body,
        },
    ))
}

fn loopback_url(raw: &str) -> SafeResult<reqwest::Url> {
    let url = reqwest::Url::parse(raw).map_err(|_| "INVALID_URL")?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port().is_none_or(|port| port == 0)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("LOOPBACK_ONLY");
    }
    Ok(url)
}

fn client() -> SafeResult<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| "HTTP_CLIENT_UNAVAILABLE")
}

fn read_bounded(response: reqwest::blocking::Response) -> SafeResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE as u64)
    {
        return Err("RESPONSE_TOO_LARGE");
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "RESPONSE_UNREADABLE")?;
    if bytes.len() > MAX_RESPONSE {
        return Err("RESPONSE_TOO_LARGE");
    }
    Ok(bytes)
}

fn validate_requirement(requirement: &PaymentRequirements) -> SafeResult<()> {
    let mint = match requirement.network.as_str() {
        SOLANA_MAINNET => MAINNET_USDC,
        SOLANA_DEVNET => DEVNET_USDC,
        _ => return Err("UNSUPPORTED_NETWORK"),
    };
    let amount = requirement
        .amount
        .parse::<u64>()
        .map_err(|_| "INVALID_AMOUNT")?;
    if amount == 0 || amount.to_string() != requirement.amount {
        return Err("INVALID_AMOUNT");
    }
    let accepted = requirement.to_accepted_value();
    let extra = accepted
        .get("extra")
        .and_then(Value::as_object)
        .ok_or("INVALID_REQUIREMENT_EXTRA")?;
    for (key, supported) in [
        ("paymentFlow", "authorization"),
        ("assetTransferMethod", "default"),
    ] {
        if extra
            .get(key)
            .is_some_and(|value| !value.is_null() && value.as_str() != Some(supported))
        {
            return Err("UNSUPPORTED_PAYMENT_TERMS");
        }
    }
    if requirement
        .token_program
        .as_deref()
        .is_some_and(|value| value != TOKEN_PROGRAM)
    {
        return Err("UNSUPPORTED_TOKEN_PROGRAM");
    }
    if requirement.max_age.is_none_or(|age| age == 0 || age > 600) {
        return Err("INVALID_QUOTE_TIMEOUT");
    }
    if extra.get("memo").is_some_and(|value| {
        value
            .as_str()
            .is_none_or(|memo| memo.is_empty() || memo.len() > 256)
    }) {
        return Err("INVALID_QUOTE_MEMO");
    }
    let fee_payer = extra
        .get("feePayer")
        .and_then(Value::as_str)
        .ok_or("INVALID_FEE_PAYER")?;
    solana_pubkey::Pubkey::from_str(fee_payer).map_err(|_| "INVALID_FEE_PAYER")?;
    // Reject legacy alias fields that would make the Rust builder consume
    // different terms from the exact canonical accepted object Yosh authorizes.
    if requirement.fee_payer != Some(true)
        || requirement.fee_payer_key.as_deref() != Some(fee_payer)
        || accepted.get("network").and_then(Value::as_str) != Some(requirement.network.as_str())
        || accepted.get("amount").and_then(Value::as_str) != Some(requirement.amount.as_str())
        || accepted.get("asset").and_then(Value::as_str) != Some(requirement.currency.as_str())
        || accepted.get("payTo").and_then(Value::as_str) != Some(requirement.recipient.as_str())
    {
        return Err("NONCANONICAL_REQUIREMENT");
    }
    if requirement.currency != mint
        // Both admitted native-USDC mints have six decimals. The canonical
        // offer may omit this optional hint; the SDK also defaults it to six.
        // An explicit conflicting hint must still fail before construction.
        || requirement.decimals.is_some_and(|decimals| decimals != 6)
        || requirement
            .to_accepted_value()
            .get("scheme")
            .and_then(Value::as_str)
            != Some("exact")
        || requirement
            .transaction_versions
            .as_ref()
            .is_some_and(|versions| !versions.contains(&pay_kit::core::tx::TxVersion::V0))
    {
        return Err("UNSUPPORTED_EXACT_USDC_REQUIREMENT");
    }
    solana_pubkey::Pubkey::from_str(&requirement.recipient).map_err(|_| "INVALID_RECIPIENT")?;
    Ok(())
}

#[cfg(test)]
fn prepare(payer: String, rpc_url: String, requirement: Value) -> SafeResult<Value> {
    prepare_with_lifetime(payer, rpc_url, requirement, None)
}

fn prepare_with_lifetime(
    payer: String,
    rpc_url: String,
    requirement: Value,
    lifetime: Option<ControlledLifetime>,
) -> SafeResult<Value> {
    let mut requirement: PaymentRequirements =
        serde_json::from_value(requirement).map_err(|_| "INVALID_REQUIREMENT")?;
    validate_requirement(&requirement)?;
    let payer = solana_pubkey::Pubkey::from_str(&payer).map_err(|_| "INVALID_PAYER")?;
    // The host may provide a lifetime obtained through its own pinned transport.
    // The SDK then receives a blockhash and cannot perform a hidden RPC call.
    let (blockhash, height) = if let Some(lifetime) = lifetime {
        let url = reqwest::Url::parse(&rpc_url).map_err(|_| "INVALID_RPC_URL")?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err("INVALID_RPC_URL");
        }
        solana_pubkey::Pubkey::from_str(&lifetime.recent_blockhash)
            .map_err(|_| "INVALID_BLOCKHASH")?;
        let height: u64 = lifetime
            .last_valid_block_height
            .parse()
            .map_err(|_| "INVALID_BLOCK_HEIGHT")?;
        if height == 0
            || height > 9_007_199_254_740_991
            || height.to_string() != lifetime.last_valid_block_height
        {
            return Err("INVALID_BLOCK_HEIGHT");
        }
        (lifetime.recent_blockhash, height)
    } else {
        let target = loopback_url(&rpc_url)?;
        let response = client()?.post(target).json(&json!({"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{"commitment":"confirmed"}]}))
            .send().map_err(|_| "BLOCKHASH_FETCH_FAILED")?;
        if !response.status().is_success() {
            return Err("BLOCKHASH_FETCH_FAILED");
        }
        let result: Value =
            serde_json::from_slice(&read_bounded(response)?).map_err(|_| "INVALID_RPC_RESPONSE")?;
        if result.get("error").is_some() {
            return Err("RPC_REJECTED");
        }
        let value = result
            .get("result")
            .and_then(|value| value.get("value"))
            .ok_or("INVALID_RPC_RESPONSE")?;
        (
            value
                .get("blockhash")
                .and_then(Value::as_str)
                .ok_or("INVALID_RPC_RESPONSE")?
                .to_string(),
            value
                .get("lastValidBlockHeight")
                .and_then(Value::as_u64)
                .ok_or("INVALID_RPC_RESPONSE")?,
        )
    };
    if requirement
        .recent_blockhash
        .as_deref()
        .is_some_and(|expected| expected != blockhash.as_str())
    {
        return Err("CHALLENGE_BLOCKHASH_MISMATCH");
    }
    requirement.recent_blockhash = Some(blockhash.to_string());
    let rpc = pay_kit::x402::solana_rpc_client::rpc_client::RpcClient::new_with_timeout(
        rpc_url,
        Duration::from_secs(5),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "RUNTIME_UNAVAILABLE")?;
    let transaction = runtime
        .block_on(pay_kit::x402::client::exact::prepare_unsigned_payment(
            &payer,
            &rpc,
            &requirement,
            Some(pay_kit::core::tx::TxVersion::V0),
        ))
        .map_err(|_| "UNSIGNED_PREPARE_FAILED")?;
    if transaction
        .signatures
        .iter()
        .any(|signature| signature.as_ref().iter().any(|byte| *byte != 0))
    {
        return Err("SIGNED_TRANSACTION_FORBIDDEN");
    }
    let transaction =
        pay_kit::core::tx::encode(&transaction).map_err(|_| "WIRE_ENCODING_FAILED")?;
    Ok(
        json!({"transaction":transaction,"recentBlockhash":blockhash,"lastValidBlockHeight":height.to_string()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mainnet_offer() -> Value {
        json!({"scheme":"exact","network":SOLANA_MAINNET,"asset":MAINNET_USDC,"amount":"1000",
            "payTo":"J7aN3PLJnTCF5qpEnvJHJsnCjcGuqC2rYtEM8Gv3xwg","maxTimeoutSeconds":300,
            "extra":{"feePayer":"BENrLoUbndxoNMUS5JXApGMtNykLjFXXixMtpDwDR9SP"}})
    }

    #[test]
    fn native_mainnet_usdc_does_not_require_optional_decimals_or_seller_memo() {
        let requirement: PaymentRequirements = serde_json::from_value(mainnet_offer()).unwrap();
        assert_eq!(requirement.decimals, None);
        assert_eq!(validate_requirement(&requirement), Ok(()));
    }

    #[test]
    fn host_lifetime_uses_the_unsigned_sdk_without_any_rpc_or_signer() {
        let result = prepare_with_lifetime(
            "11111111111111111111111111111111".into(),
            "https://no-egress.invalid/".into(),
            mainnet_offer(),
            Some(ControlledLifetime {
                recent_blockhash: "11111111111111111111111111111111".into(),
                last_valid_block_height: "5000".into(),
            }),
        )
        .unwrap();
        let wire = pay_kit::core::tx::decode(result["transaction"].as_str().unwrap()).unwrap();
        assert!(
            wire.signatures
                .iter()
                .all(|signature| signature.as_ref().iter().all(|byte| *byte == 0))
        );
        assert_eq!(
            result["recentBlockhash"],
            "11111111111111111111111111111111"
        );
        assert_eq!(result["lastValidBlockHeight"], "5000");
        assert!(
            prepare_with_lifetime(
                "11111111111111111111111111111111".into(),
                "https://no-egress.invalid/".into(),
                mainnet_offer(),
                Some(ControlledLifetime {
                    recent_blockhash: "bad".into(),
                    last_valid_block_height: "5000".into()
                })
            )
            .is_err()
        );
    }

    #[test]
    fn conflicting_decimals_and_assets_still_fail_closed() {
        let mut offer = mainnet_offer();
        offer["extra"]["decimals"] = json!(9);
        assert!(validate_requirement(&serde_json::from_value(offer).unwrap()).is_err());
        let mut offer = mainnet_offer();
        offer["asset"] = json!(DEVNET_USDC);
        assert!(validate_requirement(&serde_json::from_value(offer).unwrap()).is_err());
        assert!(loopback_url("https://api.mainnet-beta.solana.com/").is_err());
    }

    #[test]
    fn mainnet_terms_prepare_only_unsigned_sdk_wire_with_a_fixture_blockhash() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let rpc = format!("http://{}", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut input = Vec::new();
            while !String::from_utf8_lossy(&input).contains("getLatestBlockhash") {
                let mut chunk = [0; 4096];
                let size = stream.read(&mut chunk).unwrap();
                assert!(size > 0 && input.len() + size <= 8192);
                input.extend_from_slice(&chunk[..size]);
            }
            let body = json!({"jsonrpc":"2.0","id":1,"result":{"value":{
                "blockhash":"11111111111111111111111111111111","lastValidBlockHeight":1000}}})
            .to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        });
        // Public fixture key only. No signing key, real RPC, or submission.
        let result = prepare(
            "11111111111111111111111111111111".into(),
            rpc,
            mainnet_offer(),
        )
        .unwrap();
        let transaction =
            pay_kit::core::tx::decode(result["transaction"].as_str().unwrap()).unwrap();
        assert_eq!(transaction.signatures.len(), 2);
        assert!(
            transaction
                .signatures
                .iter()
                .all(|s| s.as_ref().iter().all(|b| *b == 0))
        );
        assert!(
            transaction
                .message
                .static_account_keys()
                .contains(&solana_pubkey::Pubkey::from_str(MAINNET_USDC).unwrap())
        );
        thread.join().unwrap();
    }
}
