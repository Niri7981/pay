//! Trusted Yosh custody host for the real PayMcp. No account or signer exists.
use pay_mcp::{
    ApprovalPolicy, CallScope, PayContext, PayMcp,
    authority::{
        AuthorityBinding, AuthorityDecision, AuthorityUnavailable, SpendRequest, SpendingAuthority,
    },
    controlled::{ControlledExecution, ControlledResponse, ExecutionPlan},
};
use rmcp::{
    ServiceExt,
    service::{Peer, RequestContext, RoleServer},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{future::Future, io::Read, pin::Pin, sync::Arc, time::Duration};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    origin: String,
    token: String,
    caller: String,
    timeout_ms: u64,
}
struct Bridge(Config);
impl Bridge {
    fn post(&self, path: &str, body: Value) -> pay_core::Result<Value> {
        let response = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|_| rejected())?
            .post(format!("{}{path}", self.0.origin))
            .bearer_auth(&self.0.token)
            .json(&body)
            .send()
            .map_err(|_| rejected())?;
        if !response.status().is_success() {
            return Err(rejected());
        }
        let mut bytes = Vec::new();
        response
            .take(131_073)
            .read_to_end(&mut bytes)
            .map_err(|_| rejected())?;
        if bytes.len() > 131_072 {
            return Err(rejected());
        }
        serde_json::from_slice(&bytes).map_err(|_| rejected())
    }
}
fn rejected() -> pay_core::Error {
    pay_core::Error::PaymentRejected("CONTROLLED_EXECUTION_UNAVAILABLE".into())
}
impl SpendingAuthority for Bridge {
    fn authorize(
        &self,
        request: SpendRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorityDecision, AuthorityUnavailable>> + Send + '_>>
    {
        Box::pin(async move {
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .map_err(|_| AuthorityUnavailable)?;
            let response = client
                .post(format!("{}/pay/authorize", self.0.origin))
                .bearer_auth(&self.0.token)
                .json(&request)
                .send()
                .await
                .map_err(|_| AuthorityUnavailable)?;
            if !response.status().is_success() {
                return Err(AuthorityUnavailable);
            }
            let mut response = response;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| AuthorityUnavailable)? {
                if bytes.len() + chunk.len() > 1024 {
                    return Err(AuthorityUnavailable);
                }
                bytes.extend_from_slice(&chunk);
            }
            let value: Value = serde_json::from_slice(&bytes).map_err(|_| AuthorityUnavailable)?;
            Ok(
                if value.get("allow").and_then(Value::as_bool) == Some(true) {
                    AuthorityDecision::Allow
                } else {
                    AuthorityDecision::Deny
                },
            )
        })
    }
}
impl ControlledExecution for Bridge {
    fn plan(&self, facts: &SpendRequest) -> pay_core::Result<ExecutionPlan> {
        serde_json::from_value(self.post("/pay/plan", json!({"facts":facts}))?)
            .map_err(|_| rejected())
    }
    fn execute(
        &self,
        facts: &SpendRequest,
        unsigned: Value,
    ) -> pay_core::Result<ControlledResponse> {
        serde_json::from_value(
            self.post("/pay/execute", json!({"facts":facts,"unsigned":unsigned}))?,
        )
        .map_err(|_| rejected())
    }
}
struct NoSigner;
impl ApprovalPolicy for NoSigner {
    fn gate(&self, _: Option<&Peer<RoleServer>>) -> pay_core::signer::AuthOverride {
        panic!("PAY_SIGNER_FORBIDDEN")
    }
}
impl PayContext for Bridge {
    fn scope(&self, _: &RequestContext<RoleServer>) -> Result<CallScope, rmcp::ErrorData> {
        Ok(CallScope {
            accounts: Arc::new(pay_core::accounts::MemoryAccountsStore::new()),
            network_override: None,
            account_override: None,
            rpc_url_override: None,
            approval: Arc::new(NoSigner),
            payment_permissions: None,
            body_files: false,
            outbound_policy: if std::env::var("YOSH_PAY_MCP_MAINNET").as_deref() == Ok("1") {
                pay_core::client::fetch::OutboundPolicy::PublicInternetOnly
            } else {
                pay_core::client::fetch::OutboundPolicy::Unrestricted
            },
        })
    }
    fn spending_authority(
        &self,
        _: &RequestContext<RoleServer>,
    ) -> Result<Option<AuthorityBinding>, rmcp::ErrorData> {
        let bridge = Arc::new(Bridge(Config {
            origin: self.0.origin.clone(),
            token: self.0.token.clone(),
            caller: self.0.caller.clone(),
            timeout_ms: self.0.timeout_ms,
        }));
        Ok(Some(
            AuthorityBinding::new(&self.0.caller, bridge.clone())
                .with_timeout(Duration::from_millis(self.0.timeout_ms))
                .with_controlled_execution(bridge),
        ))
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).as_deref() == Some("--unsigned-preflight") {
        if std::env::args().len() != 2 {
            return Err("INVALID_PREFLIGHT_ARGUMENTS".into());
        }
        let result = tokio::task::spawn_blocking(|| {
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(131_073)
                .read_to_end(&mut bytes)
                .map_err(|_| "PREFLIGHT_INPUT_UNAVAILABLE")?;
            if bytes.len() > 131_072 {
                return Err("PREFLIGHT_INPUT_TOO_LARGE");
            }
            let input = serde_json::from_slice(&bytes).map_err(|_| "INVALID_PREFLIGHT_INPUT")?;
            pay_mcp::controlled::unsigned_preflight(input)
        })
        .await?;
        let output = match result {
            Ok(value) => json!({"ok": true, "result": value}),
            Err(code) => json!({"ok": false, "code": code}),
        };
        println!("{output}");
        return Ok(());
    }
    // Only the fixed execution-stage fields are exported; other libraries may
    // log requests or credentials and must remain disabled in this host.
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("off,pay_execution=info")
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    let development = std::env::var("YOSH_PAY_DEV").as_deref() == Ok("1");
    if std::env::var("NODE_ENV").as_deref() != Ok("test")
        && !development
        && std::env::var("YOSH_PAY_MCP_MAINNET").as_deref() != Ok("1")
    {
        return Err("ISOLATED_TEST_ONLY".into());
    }
    let config_path = std::env::args().nth(1).ok_or("CONFIG_REQUIRED")?;
    let metadata = std::fs::symlink_metadata(&config_path)?;
    if !metadata.is_file() || metadata.len() > 16_384 {
        return Err("PRIVATE_CONFIG_REQUIRED".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("PRIVATE_CONFIG_REQUIRED".into());
        }
    }
    let config: Config = serde_json::from_slice(&std::fs::read(config_path)?)?;
    let url = reqwest::Url::parse(&config.origin)?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("LOOPBACK_ONLY".into());
    }
    PayMcp::with_context(Arc::new(Bridge(config)))
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?
        .waiting()
        .await?;
    Ok(())
}
