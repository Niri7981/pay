//! Optional spending-policy consultation, not signature custody or controlled egress.

use pay_core::client::fetch::RequestBody;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

/// Frozen application request, before any payment credential is attached.
/// Contains potentially sensitive application input: implementations must not log it.
#[derive(Clone, Serialize)]
pub struct ImmutableRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

/// Facts obtained from the real SDK-decoded x402 exact offer.
#[derive(Clone, Serialize)]
pub struct SpendRequest {
    pub operation_id: String,
    /// Unique to this execution attempt, even across MCP process restarts.
    pub attempt_id: String,
    /// Asserted by the trusted PayContext, never by tool arguments/clientInfo.
    pub caller_id: String,
    pub request: ImmutableRequest,
    pub amount_atomic: String,
    pub asset: String,
    pub network: String,
    pub execution_network: String,
    pub recipient: String,
    /// Full canonical accepted offer, including decimals/fee payer/memo/blockhash.
    pub accepted: serde_json::Value,
    /// Original SDK-selected v2 envelope, required only by controlled custody.
    /// Kept separate from request.url: a merchant may advertise a route-level
    /// resource while the immutable request includes concrete query inputs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_required: Option<serde_json::Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityDecision {
    Allow,
    Deny,
}

/// Provider failures are deliberately opaque to the agent (no raw transport errors).
#[derive(Debug)]
pub struct AuthorityUnavailable;

/// Runtime policy provider. It must not block its future's executor thread.
///
/// Providers requiring durable idempotency must atomically bind caller + operation
/// to immutable request/offer facts and one attempt_id. A new attempt for an already
/// claimed operation must fail closed. Repeating an allow without this check does
/// NOT provide at-most-once execution across process restarts.
pub trait SpendingAuthority: Send + Sync {
    fn authorize(
        &self,
        request: SpendRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorityDecision, AuthorityUnavailable>> + Send + '_>>;
}

/// Trusted, per-caller configuration supplied by PayContext. It is additive to YAML
/// permissions and wallet approval, and cannot be configured via a tool request.
#[derive(Clone)]
pub struct AuthorityBinding {
    pub(crate) caller_id: String,
    authority: Arc<dyn SpendingAuthority>,
    timeout: Duration,
    pub(crate) controlled: Option<Arc<dyn crate::controlled::ControlledExecution>>,
}

impl AuthorityBinding {
    pub fn new(caller_id: impl Into<String>, authority: Arc<dyn SpendingAuthority>) -> Self {
        Self {
            caller_id: caller_id.into(),
            authority,
            timeout: Duration::from_secs(5),
            controlled: None,
        }
    }

    /// Keep signed credentials and final HTTP under the host controller's custody.
    pub fn with_controlled_execution(
        mut self,
        controller: Arc<dyn crate::controlled::ControlledExecution>,
    ) -> Self {
        self.controlled = Some(controller);
        self
    }

    /// Invalid (zero or >60s) deadlines fail closed when the call starts.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

// A bounded connection-local replay guard, not an economic ledger. Entries never
// expire/evict: a failed/unknown attempt must not silently become a fresh payment.
#[derive(Default)]
pub(crate) struct Operations(Mutex<HashMap<(String, String), [u8; 32]>>);

pub(crate) struct AuthorityAttempt {
    binding: AuthorityBinding,
    operation_id: String,
    attempt_id: String,
    request: ImmutableRequest,
}

fn rejected(code: &str) -> pay_core::Error {
    pay_core::Error::PaymentRejected(format!("External spending authority: {code}"))
}

impl Operations {
    pub(crate) fn start(
        &self,
        binding: AuthorityBinding,
        operation_id: Option<&str>,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&RequestBody>,
    ) -> Result<AuthorityAttempt, pay_core::Error> {
        let id = operation_id
            .filter(|id| {
                !id.is_empty()
                    && id.len() <= 128
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
            })
            .ok_or_else(|| rejected("OPERATION_ID_REQUIRED"))?;
        if binding.caller_id.trim().is_empty()
            || binding.caller_id.len() > 256
            || binding.timeout.is_zero()
            || binding.timeout > Duration::from_secs(60)
        {
            return Err(rejected("INVALID_TRUSTED_CONFIGURATION"));
        }
        let mut canonical_headers = headers
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
            .collect::<Vec<_>>();
        canonical_headers.sort();
        if canonical_headers.iter().any(|(name, _)| {
            matches!(
                name.as_str(),
                "authorization"
                    | "cookie"
                    | "payment-signature"
                    | "x-payment"
                    | "sign-in-with-x"
                    | "x-sign-in-with-x"
            )
        }) || canonical_headers
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0)
        {
            return Err(rejected("PREFILLED_CREDENTIAL_OR_AMBIGUOUS_HEADER"));
        }
        let request = ImmutableRequest {
            method: method.to_string(),
            url: url.to_string(),
            headers: canonical_headers,
            body: body.map(|b| b.as_bytes().to_vec()),
        };
        let bytes = serde_json::to_vec(&request).map_err(|_| rejected("INVALID_REQUEST"))?;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let key = (binding.caller_id.clone(), id.to_string());
        let mut operations = self
            .0
            .lock()
            .map_err(|_| rejected("REPLAY_GUARD_UNAVAILABLE"))?;
        if let Some(previous) = operations.get(&key) {
            return Err(rejected(if *previous == digest {
                "OPERATION_ALREADY_STARTED"
            } else {
                "OPERATION_CONFLICT"
            }));
        }
        if operations.len() >= 1024 {
            return Err(rejected("REPLAY_GUARD_FULL"));
        }
        operations.insert(key, digest);
        Ok(AuthorityAttempt {
            binding,
            operation_id: id.to_string(),
            attempt_id: uuid::Uuid::new_v4().to_string(),
            request,
        })
    }
}

impl AuthorityAttempt {
    /// Diagnostic facts only: never log request data, offers or payment credentials.
    pub(crate) fn trace(&self, stage: &'static str) {
        tracing::info!(target: "pay_execution", version = 1, caller_id = %self.binding.caller_id,
            operation_id = %self.operation_id, attempt_id = %self.attempt_id, stage);
    }
    pub(crate) fn controller(&self) -> Option<&dyn crate::controlled::ControlledExecution> {
        self.binding.controlled.as_deref()
    }
    pub(crate) fn authorize(
        &self,
        challenge: &pay_core::client::x402::Challenge,
        execution_network: &str,
    ) -> Result<SpendRequest, pay_core::Error> {
        let accepted = challenge.requirements.to_accepted_value();
        // Keep this first seam narrow. Other schemes/authentication flows must not
        // fall through to a free signer, including those advertised beside exact.
        if challenge.x402_version != 2
            || challenge.siwx.is_some()
            || !accepted
                .get("network")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.starts_with("solana:"))
        {
            return Err(rejected("UNSUPPORTED_PAYMENT"));
        }
        let amount = challenge
            .requirements
            .amount
            .parse::<u64>()
            .map_err(|_| rejected("INVALID_AMOUNT"))?;
        let field = |name: &str| {
            accepted
                .get(name)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or_else(|| rejected("INVALID_OFFER"))
        };
        let facts = SpendRequest {
            operation_id: self.operation_id.clone(),
            attempt_id: self.attempt_id.clone(),
            caller_id: self.binding.caller_id.clone(),
            request: self.request.clone(),
            amount_atomic: amount.to_string(),
            asset: field("asset")?,
            network: field("network")?,
            execution_network: execution_network.to_string(),
            recipient: field("payTo")?,
            accepted,
            payment_required: self
                .binding
                .controlled
                .as_ref()
                .map(|_| controlled_envelope(challenge, &self.request))
                .transpose()?,
        };
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| rejected("AUTHORITY_RUNTIME_UNAVAILABLE"))?;
        self.trace("authority_requested");
        let decision = runtime.block_on(async {
            tokio::time::timeout(
                self.binding.timeout,
                self.binding.authority.authorize(facts.clone()),
            )
            .await
        });
        match decision {
            Ok(Ok(AuthorityDecision::Allow)) => {
                self.trace("authority_allowed");
                Ok(facts)
            }
            Ok(Ok(AuthorityDecision::Deny)) => {
                self.trace("authority_denied");
                Err(rejected("DENIED"))
            }
            Ok(Err(_)) => {
                self.trace("authority_unavailable");
                Err(rejected("UNAVAILABLE"))
            }
            Err(_) => {
                self.trace("authority_timeout");
                Err(rejected("TIMEOUT"))
            }
        }
    }
}

fn controlled_envelope(
    challenge: &pay_core::client::x402::Challenge,
    request: &ImmutableRequest,
) -> Result<serde_json::Value, pay_core::Error> {
    use pay_kit::x402::exact::PaymentExtensions;
    use serde_json::Value;
    let envelope = challenge
        .payment_required
        .as_ref()
        .ok_or_else(|| rejected("MISSING_PAYMENT_REQUIRED"))?;
    if envelope.get("x402Version").and_then(Value::as_u64) != Some(2) {
        return Err(rejected("UNSUPPORTED_PAYMENT"));
    }
    let bytes =
        serde_json::to_string(envelope).map_err(|_| rejected("INVALID_PAYMENT_REQUIRED"))?;
    let parsed = pay_core::client::x402::parse(&[], Some(&bytes))
        .ok_or_else(|| rejected("INVALID_PAYMENT_REQUIRED"))?;
    let accepted = challenge.requirements.to_accepted_value();
    let offers = envelope
        .get("accepts")
        .and_then(Value::as_array)
        .ok_or_else(|| rejected("INVALID_PAYMENT_REQUIRED"))?;
    if parsed.x402_version != 2
        || parsed.siwx.is_some()
        || parsed.requirements.to_accepted_value() != accepted
        || parsed.requirements.resource != challenge.requirements.resource
        || parsed.requirements.resource_info() != challenge.requirements.resource_info()
        || parsed.extensions != challenge.extensions
        || offers.iter().filter(|offer| **offer == accepted).count() != 1
    {
        return Err(rejected("PAYMENT_REQUIRED_BINDING_MISMATCH"));
    }
    let resource = envelope
        .get("resource")
        .and_then(|value| value.get("url"))
        .and_then(Value::as_str)
        .ok_or_else(|| rejected("INVALID_RESOURCE_BINDING"))?;
    let resource =
        reqwest::Url::parse(resource).map_err(|_| rejected("INVALID_RESOURCE_BINDING"))?;
    let target =
        reqwest::Url::parse(&request.url).map_err(|_| rejected("INVALID_RESOURCE_BINDING"))?;
    if !matches!(resource.scheme(), "http" | "https")
        || resource.origin() != target.origin()
        || resource.path() != target.path()
        || !resource.username().is_empty()
        || resource.password().is_some()
        || resource.fragment().is_some()
        || resource
            .query()
            .is_some_and(|query| Some(query) != target.query())
        || resource.as_str() != challenge.requirements.resource
    {
        return Err(rejected("INVALID_RESOURCE_BINDING"));
    }
    // Validate with the SDK, but retain the raw object: typed serialization can
    // discard unknown nested fields. This profile echoes existing information
    // only; required client-generated identifiers remain explicitly unsupported.
    let extensions = PaymentExtensions::echoing(challenge.extensions.as_ref())
        .map_err(|_| rejected("INVALID_PAYMENT_EXTENSIONS"))?;
    if let Some(extensions) = extensions {
        if extensions.requires_payment_identifier() {
            return Err(rejected("UNSUPPORTED_REQUIRED_PAYMENT_IDENTIFIER"));
        }
        if serde_json::to_value(extensions).ok().as_ref() != challenge.extensions.as_ref() {
            return Err(rejected("UNSUPPORTED_NORMALIZING_PAYMENT_EXTENSIONS"));
        }
    }
    Ok(envelope.clone())
}

pub(crate) fn trace_execution(facts: &SpendRequest, stage: &'static str) {
    tracing::info!(target: "pay_execution", version = 1, caller_id = %facts.caller_id,
        operation_id = %facts.operation_id, attempt_id = %facts.attempt_id, stage);
}

pub(crate) fn unsupported() -> pay_core::Error {
    rejected("UNSUPPORTED_PAYMENT")
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Deny;
    impl SpendingAuthority for Deny {
        fn authorize(
            &self,
            _: SpendRequest,
        ) -> Pin<
            Box<dyn Future<Output = Result<AuthorityDecision, AuthorityUnavailable>> + Send + '_>,
        > {
            Box::pin(async { Ok(AuthorityDecision::Deny) })
        }
    }
    fn binding(caller: &str) -> AuthorityBinding {
        AuthorityBinding::new(caller, Arc::new(Deny))
    }
    #[test]
    fn replay_and_mutation_are_fenced_without_an_economic_ledger() {
        let operations = Operations::default();
        let request = RequestBody::text("original");
        assert!(
            operations
                .start(
                    binding("agent-a"),
                    Some("op-1"),
                    "POST",
                    "https://example.com",
                    &[],
                    Some(&request)
                )
                .is_ok()
        );
        let duplicate = operations
            .start(
                binding("agent-a"),
                Some("op-1"),
                "POST",
                "https://example.com",
                &[],
                Some(&request),
            )
            .err()
            .unwrap();
        assert!(duplicate.to_string().contains("OPERATION_ALREADY_STARTED"));
        let changed = RequestBody::text("changed");
        assert!(
            operations
                .start(
                    binding("agent-a"),
                    Some("op-1"),
                    "POST",
                    "https://example.com",
                    &[],
                    Some(&changed)
                )
                .err()
                .unwrap()
                .to_string()
                .contains("OPERATION_CONFLICT")
        );
        assert!(
            operations
                .start(
                    binding("agent-b"),
                    Some("op-1"),
                    "POST",
                    "https://example.com",
                    &[],
                    Some(&request)
                )
                .is_ok()
        );
    }
    #[test]
    fn simultaneous_claim_has_one_winner() {
        let operations = Arc::new(Operations::default());
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let operations = operations.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    operations
                        .start(
                            binding("agent-a"),
                            Some("same"),
                            "GET",
                            "https://example.com",
                            &[],
                            None,
                        )
                        .is_ok()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        assert_eq!(
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum::<usize>(),
            1
        );
    }
    #[test]
    fn header_case_and_order_cannot_change_replay_identity() {
        let operations = Operations::default();
        let first = vec![("X-B".into(), "b".into()), ("X-A".into(), "a".into())];
        let second = vec![("x-a".into(), "a".into()), ("x-b".into(), "b".into())];
        assert!(
            operations
                .start(
                    binding("agent-a"),
                    Some("op"),
                    "GET",
                    "https://example.com",
                    &first,
                    None
                )
                .is_ok()
        );
        assert!(
            operations
                .start(
                    binding("agent-a"),
                    Some("op"),
                    "GET",
                    "https://example.com",
                    &second,
                    None
                )
                .err()
                .unwrap()
                .to_string()
                .contains("OPERATION_ALREADY_STARTED")
        );
    }
    #[test]
    fn credentials_and_invalid_configuration_fail_closed() {
        let operations = Operations::default();
        for name in [
            "Authorization",
            "COOKIE",
            "Payment-Signature",
            "X-Payment",
            "SIGN-IN-WITH-X",
        ] {
            assert!(
                operations
                    .start(
                        binding("agent"),
                        Some(name),
                        "GET",
                        "https://example.com",
                        &[(name.into(), "opaque".into())],
                        None
                    )
                    .is_err()
            );
        }
        assert!(
            operations
                .start(
                    binding(""),
                    Some("op"),
                    "GET",
                    "https://example.com",
                    &[],
                    None
                )
                .is_err()
        );
        assert!(
            operations
                .start(binding("a"), None, "GET", "https://example.com", &[], None)
                .is_err()
        );
        assert!(
            operations
                .start(
                    binding("a").with_timeout(Duration::ZERO),
                    Some("op"),
                    "GET",
                    "https://example.com",
                    &[],
                    None
                )
                .is_err()
        );
    }
    #[test]
    fn replay_guard_never_evicts_an_old_attempt_to_allow_a_new_payment() {
        let operations = Operations::default();
        for i in 0..1024 {
            assert!(
                operations
                    .start(
                        binding("a"),
                        Some(&format!("op-{i}")),
                        "GET",
                        "https://example.com",
                        &[],
                        None
                    )
                    .is_ok()
            );
        }
        assert!(
            operations
                .start(
                    binding("a"),
                    Some("overflow"),
                    "GET",
                    "https://example.com",
                    &[],
                    None
                )
                .err()
                .unwrap()
                .to_string()
                .contains("REPLAY_GUARD_FULL")
        );
        assert!(
            operations
                .start(
                    binding("a"),
                    Some("op-0"),
                    "GET",
                    "https://example.com",
                    &[],
                    None
                )
                .err()
                .unwrap()
                .to_string()
                .contains("OPERATION_ALREADY_STARTED")
        );
    }
}
