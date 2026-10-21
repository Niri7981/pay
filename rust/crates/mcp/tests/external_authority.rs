//! Real MCP initialize/tools-call and loopback HTTP, with offline fixture signing only.
use base64::{Engine, engine::general_purpose::STANDARD};
use pay_core::accounts::{AccountsFile, AccountsStore, MemoryAccountsStore};
use pay_mcp::{
    ApprovalPolicy, CallScope, McpPermissions, PayContext, PayMcp, PermissionConfig,
    authority::{
        AuthorityBinding, AuthorityDecision, AuthorityUnavailable, SpendRequest, SpendingAuthority,
    },
};
use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, CallToolResult},
    service::{Peer, RequestContext, RoleServer},
};
use serde_json::{Value, json};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Notify,
};

const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const RECIPIENT: &str = "11111111111111111111111111111111";
#[derive(Clone, Copy)]
enum Decision {
    Allow,
    Deny,
    Unavailable,
    Pending,
    Barrier,
}
struct Authority {
    decision: Decision,
    calls: AtomicUsize,
    facts: Mutex<Vec<SpendRequest>>,
    entered: Notify,
    release: Notify,
}
impl Authority {
    fn new(decision: Decision) -> Arc<Self> {
        Arc::new(Self {
            decision,
            calls: AtomicUsize::new(0),
            facts: Mutex::new(Vec::new()),
            entered: Notify::new(),
            release: Notify::new(),
        })
    }
}
impl SpendingAuthority for Authority {
    fn authorize(
        &self,
        request: SpendRequest,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorityDecision, AuthorityUnavailable>> + Send + '_>>
    {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.facts.lock().unwrap().push(request);
            self.entered.notify_one();
            match self.decision {
                Decision::Allow => Ok(AuthorityDecision::Allow),
                Decision::Deny => Ok(AuthorityDecision::Deny),
                Decision::Unavailable => Err(AuthorityUnavailable),
                Decision::Pending => std::future::pending().await,
                Decision::Barrier => {
                    self.release.notified().await;
                    Ok(AuthorityDecision::Allow)
                }
            }
        })
    }
}
struct Store {
    inner: MemoryAccountsStore,
    reads: AtomicUsize,
}
impl AccountsStore for Store {
    fn load(&self) -> pay_core::Result<AccountsFile> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.load()
    }
    fn save(&self, file: &AccountsFile) -> pay_core::Result<()> {
        self.inner.save(file)
    }
}
struct Approval(Arc<AtomicUsize>);
impl ApprovalPolicy for Approval {
    fn gate(&self, _: Option<&Peer<RoleServer>>) -> pay_core::signer::AuthOverride {
        self.0.fetch_add(1, Ordering::SeqCst);
        None
    }
}
struct Context {
    authority: Option<Arc<Authority>>,
    controller: Option<Arc<dyn pay_mcp::controlled::ControlledExecution>>,
    store: Arc<Store>,
    approval: Arc<AtomicUsize>,
    permissions: Option<Arc<McpPermissions>>,
    timeout: Duration,
    config_error: bool,
}
impl Context {
    fn new(authority: Option<Arc<Authority>>) -> Self {
        // Existing SDK account helper generates a one-time fixture in memory only.
        let ephemeral = pay_core::accounts::load_or_create_ephemeral_for_network(
            "localnet",
            &MemoryAccountsStore::new(),
        )
        .unwrap();
        let mut file = AccountsFile::default();
        file.accounts
            .entry("mainnet".into())
            .or_default()
            .insert("fixture".into(), ephemeral.account);
        Self {
            authority,
            controller: None,
            store: Arc::new(Store {
                inner: MemoryAccountsStore::with_file(file),
                reads: AtomicUsize::new(0),
            }),
            approval: Arc::new(AtomicUsize::new(0)),
            permissions: None,
            timeout: Duration::from_secs(2),
            config_error: false,
        }
    }
}
impl PayContext for Context {
    fn scope(&self, _: &RequestContext<RoleServer>) -> Result<CallScope, rmcp::ErrorData> {
        Ok(CallScope {
            accounts: self.store.clone(),
            network_override: None,
            account_override: Some("fixture".into()),
            rpc_url_override: None,
            approval: Arc::new(Approval(self.approval.clone())),
            payment_permissions: self.permissions.clone(),
            body_files: false,
            outbound_policy: pay_core::client::fetch::OutboundPolicy::Unrestricted,
        })
    }
    fn spending_authority(
        &self,
        _: &RequestContext<RoleServer>,
    ) -> Result<Option<AuthorityBinding>, rmcp::ErrorData> {
        if self.config_error {
            return Err(rmcp::ErrorData::internal_error(
                "authority configuration unavailable",
                None,
            ));
        }
        Ok(self.authority.as_ref().map(|a| {
            let binding =
                AuthorityBinding::new("trusted-agent-42", a.clone()).with_timeout(self.timeout);
            match &self.controller {
                Some(controller) => binding.with_controlled_execution(controller.clone()),
                None => binding,
            }
        }))
    }
}
struct Merchant {
    url: String,
    probes: Arc<AtomicUsize>,
    paid: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Merchant {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Merchant {
    async fn new(mode: &str) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/data", listener.local_addr().unwrap());
        let probes = Arc::new(AtomicUsize::new(0));
        let paid = Arc::new(AtomicUsize::new(0));
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let (p, q, b, u, mode) = (
            probes.clone(),
            paid.clone(),
            bodies.clone(),
            url.clone(),
            mode.to_string(),
        );
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut raw = Vec::new();
                let end = loop {
                    let mut buf = [0; 4096];
                    let n = stream.read(&mut buf).await.unwrap();
                    assert_ne!(n, 0);
                    raw.extend_from_slice(&buf[..n]);
                    if let Some(i) = raw.windows(4).position(|x| x == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let head = String::from_utf8(raw[..end].to_vec()).unwrap();
                let headers = head
                    .lines()
                    .skip(1)
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
                    .collect::<std::collections::HashMap<_, _>>();
                let length = headers
                    .get("content-length")
                    .map(|s| s.parse::<usize>().unwrap())
                    .unwrap_or(0);
                while raw.len() - end < length {
                    let mut buf = [0; 4096];
                    let n = stream.read(&mut buf).await.unwrap();
                    assert_ne!(n, 0);
                    raw.extend_from_slice(&buf[..n]);
                }
                b.lock().unwrap().push(raw[end..].to_vec());
                assert!(
                    !headers.contains_key("authorization"),
                    "cached authorization escaped the authority path"
                );
                let (status, extra, body) = if let Some(header) = headers.get("payment-signature") {
                    let envelope: Value =
                        serde_json::from_slice(&STANDARD.decode(header).unwrap()).unwrap();
                    assert_eq!(envelope["accepted"]["asset"], MINT);
                    assert_eq!(envelope["accepted"]["amount"], "10000");
                    assert_eq!(envelope["accepted"]["payTo"], RECIPIENT);
                    let tx = pay_kit::core::tx::decode(
                        envelope["payload"]["transaction"].as_str().unwrap(),
                    )
                    .unwrap();
                    assert_eq!(
                        tx.signatures
                            .iter()
                            .filter(|s| s.as_ref().iter().any(|b| *b != 0))
                            .count(),
                        1
                    );
                    q.fetch_add(1, Ordering::SeqCst);
                    (
                        "200 OK",
                        String::new(),
                        "{\"fixture\":\"delivered\"}".into(),
                    )
                } else {
                    p.fetch_add(1, Ordering::SeqCst);
                    if mode == "redirect" {
                        (
                            "302 Found",
                            format!("Location: {u}?redirected=1\r\n"),
                            "redirect".into(),
                        )
                    } else if mode == "free" {
                        ("200 OK", String::new(), "free fixture".into())
                    } else if mode == "mpp" {
                        let request = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json!({"amount":"10000","currency":MINT,"recipient":RECIPIENT,"methodDetails":{"network":"mainnet"}}).to_string());
                        let header = format!(
                            "Payment id=\"fixture\", realm=\"test\", method=\"solana\", intent=\"charge\", request=\"{request}\""
                        );
                        assert!(pay_core::client::mpp::parse(&header).is_some());
                        (
                            "402 Payment Required",
                            format!("WWW-Authenticate: {header}\r\n"),
                            "{}".into(),
                        )
                    } else {
                        let version = if mode == "v1" { 1 } else { 2 };
                        let mut challenge = json!({"x402Version":version,"resource":{"url":u,"mimeType":"application/json"},"accepts":[{"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","asset":MINT,"amount":"10000","maxAmountRequired":"10000","payTo":RECIPIENT,"maxTimeoutSeconds":60,"extra":{"feePayer":"SysvarRent111111111111111111111111111111111","recentBlockhash":"11111111111111111111111111111111","decimals":6,"memo":"offline-authority-test"}}]});
                        // The pre-existing YAML parser needs an explicit mainnet slug.
                        // Canonical CAIP-2-only rejection is tested separately, not hidden.
                        if mode == "exact-with-cluster" {
                            challenge["accepts"][0]["cluster"] = json!("mainnet");
                        }
                        if mode == "mainnet-metadata" {
                            // Public Agent402 quote shape observed 2026-10-20:
                            // canonical Mainnet USDC, optional memo absent, and
                            // metadata extensions. No public network is used here.
                            challenge["accepts"] = json!([
                                {"scheme":"exact","network":"eip155:8453","asset":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                                 "amount":"1000","payTo":"0xaBF4FAbd7c416fB67202E5f9002389Fc75e2a9D0","maxTimeoutSeconds":300,"extra":{"name":"USD Coin","version":"2"}},
                                {"scheme":"exact","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                                "asset":MINT,"amount":"1000","payTo":"J7aN3PLJnTCF5qpEnvJHJsnCjcGuqC2rYtEM8Gv3xwg",
                                "maxTimeoutSeconds":300,"extra":{"feePayer":"BENrLoUbndxoNMUS5JXApGMtNykLjFXXixMtpDwDR9SP"}}]);
                            challenge["extensions"] = json!({"bazaar":{},"builder-code":{},"payment-identifier":{"info":{"required":false}}});
                        }
                        if mode.starts_with("agent402-") {
                            challenge = serde_json::from_str(include_str!(
                                "fixtures/agent402-mainnet-quote.json"
                            ))
                            .unwrap();
                            // The response is served by the isolated merchant,
                            // while preserving the public route-level shape.
                            challenge["resource"]["url"] = json!(u);
                            if mode == "agent402-required-id" {
                                challenge["extensions"]["payment-identifier"]["info"]["required"] =
                                    json!(true);
                            }
                            if mode == "agent402-invalid-required" {
                                challenge["extensions"]["payment-identifier"]["info"]["required"] =
                                    json!("false");
                            }
                            if mode == "agent402-normalizing-extension" {
                                challenge["extensions"]["payment-identifier"]["info"]["unrecognized"] =
                                    json!("must not disappear");
                            }
                            if mode == "agent402-same-query" {
                                challenge["resource"]["url"] =
                                    json!(format!("{u}?coins=BTC%2CETH%2CSOL&currency=usd"));
                            }
                            if mode == "agent402-other-origin" {
                                challenge["resource"]["url"] = json!("https://other.example/data");
                            }
                            if mode == "agent402-other-query" {
                                challenge["resource"]["url"] = json!(format!("{u}?coins=ETH"));
                            }
                            if mode == "agent402-other-path" {
                                challenge["resource"]["url"] = json!(format!("{u}/other"));
                            }
                            if mode == "agent402-duplicate-offer" {
                                let selected = challenge["accepts"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .find(|offer| {
                                        offer["network"]
                                            == "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
                                    })
                                    .unwrap()
                                    .clone();
                                challenge["accepts"].as_array_mut().unwrap().push(selected);
                            }
                        }
                        (
                            "402 Payment Required",
                            if version == 1 {
                                String::new()
                            } else {
                                format!(
                                    "Payment-Required: {}\r\n",
                                    STANDARD.encode(challenge.to_string())
                                )
                            },
                            challenge.to_string(),
                        )
                    }
                };
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
        });
        Self {
            url,
            probes,
            paid,
            bodies,
            task,
        }
    }
}
fn args(url: &str, id: Option<&str>) -> Value {
    let mut v = json!({"url":url,"method":"POST","body":{"query":"fixture"}});
    if let Some(id) = id {
        v["operation_id"] = json!(id);
    }
    v
}
async fn call(context: Arc<Context>, arguments: Value) -> CallToolResult {
    let (a, b) = tokio::io::duplex(65536);
    let (server, client) = tokio::join!(PayMcp::with_context(context).serve(a), ().serve(b));
    let server = server.unwrap();
    let client = client.unwrap();
    let result = client
        .call_tool(
            CallToolRequestParams::new("curl")
                .with_arguments(arguments.as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    client.cancel().await.unwrap();
    server.cancel().await.unwrap();
    result
}
fn text(result: &CallToolResult) -> String {
    serde_json::to_string(result).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn deny_after_real_quote_prevents_wallet_approval_and_paid_http() {
    let m = Merchant::new("exact").await;
    let a = Authority::new(Decision::Deny);
    let c = Arc::new(Context::new(Some(a.clone())));
    let result = call(c.clone(), args(&m.url, Some("deny-1"))).await;
    assert!(text(&result).contains("DENIED"));
    assert_eq!(m.probes.load(Ordering::SeqCst), 1);
    assert_eq!(m.paid.load(Ordering::SeqCst), 0);
    assert_eq!(c.store.reads.load(Ordering::SeqCst), 0);
    assert_eq!(c.approval.load(Ordering::SeqCst), 0);
    let facts = a.facts.lock().unwrap();
    let f = &facts[0];
    assert_eq!(f.operation_id, "deny-1");
    assert_eq!(f.caller_id, "trusted-agent-42");
    assert_eq!(f.request.url, m.url);
    assert_eq!(f.request.method, "POST");
    assert_eq!(f.request.body, Some(b"{\"query\":\"fixture\"}".to_vec()));
    assert_eq!(f.amount_atomic, "10000");
    assert_eq!(f.asset, MINT);
    assert_eq!(f.recipient, RECIPIENT);
    assert_eq!(f.execution_network, "mainnet");
    assert_eq!(f.network, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp");
    assert!(!f.attempt_id.is_empty());
    assert_eq!(f.accepted["extra"]["memo"], "offline-authority-test");
}
#[tokio::test(flavor = "multi_thread")]
async fn provider_error_and_timeout_fail_closed() {
    for (decision, code) in [
        (Decision::Unavailable, "UNAVAILABLE"),
        (Decision::Pending, "TIMEOUT"),
    ] {
        let m = Merchant::new("exact").await;
        let a = Authority::new(decision);
        let mut c = Context::new(Some(a.clone()));
        c.timeout = Duration::from_millis(20);
        let c = Arc::new(c);
        let result = call(c.clone(), args(&m.url, Some(code))).await;
        assert!(text(&result).contains(code));
        assert_eq!(a.calls.load(Ordering::SeqCst), 1);
        assert_eq!(m.paid.load(Ordering::SeqCst), 0);
        assert_eq!(c.store.reads.load(Ordering::SeqCst), 0);
        assert_eq!(c.approval.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn allow_uses_original_sdk_sign_and_retry_with_immutable_request() {
    let m = Merchant::new("exact").await;
    let a = Authority::new(Decision::Allow);
    let c = Arc::new(Context::new(Some(a.clone())));
    let result = call(c.clone(), args(&m.url, Some("allow-1"))).await;
    assert_eq!(result.is_error, Some(false));
    assert_eq!(a.calls.load(Ordering::SeqCst), 1);
    assert_eq!(c.approval.load(Ordering::SeqCst), 1);
    assert_eq!(m.probes.load(Ordering::SeqCst), 1);
    assert_eq!(m.paid.load(Ordering::SeqCst), 1);
    let bodies = m.bodies.lock().unwrap();
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0], bodies[1]);
}
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_duplicate_and_later_mutation_never_reexecute() {
    let m = Merchant::new("exact").await;
    let a = Authority::new(Decision::Barrier);
    let c = Arc::new(Context::new(Some(a.clone())));
    let (x, y) = tokio::io::duplex(65536);
    let (server, client) = tokio::join!(PayMcp::with_context(c.clone()).serve(x), ().serve(y));
    let server = server.unwrap();
    let client = client.unwrap();
    let params = CallToolRequestParams::new("curl")
        .with_arguments(args(&m.url, Some("same")).as_object().unwrap().clone());
    let first = client.call_tool(params.clone());
    let duplicate = async {
        a.entered.notified().await;
        let second = client.call_tool(params.clone()).await.unwrap();
        assert!(text(&second).contains("OPERATION_ALREADY_STARTED"));
        a.release.notify_one();
    };
    let (result, ()) = tokio::join!(first, duplicate);
    assert_eq!(result.unwrap().is_error, Some(false));
    let reads = c.store.reads.load(Ordering::SeqCst);
    let replay = client.call_tool(params).await.unwrap();
    assert!(text(&replay).contains("OPERATION_ALREADY_STARTED"));
    let mut changed = args(&m.url, Some("same"));
    changed["body"] = json!({"query":"changed"});
    let conflict = client
        .call_tool(
            CallToolRequestParams::new("curl").with_arguments(changed.as_object().unwrap().clone()),
        )
        .await
        .unwrap();
    assert!(text(&conflict).contains("OPERATION_CONFLICT"));
    assert_eq!(a.calls.load(Ordering::SeqCst), 1);
    assert_eq!(m.probes.load(Ordering::SeqCst), 1);
    assert_eq!(m.paid.load(Ordering::SeqCst), 1);
    assert_eq!(c.store.reads.load(Ordering::SeqCst), reads);
    client.cancel().await.unwrap();
    server.cancel().await.unwrap();
}
#[tokio::test(flavor = "multi_thread")]
async fn missing_id_and_prefilled_payment_credentials_fail_before_probe() {
    for header in [
        None,
        Some("Authorization"),
        Some("Payment-Signature"),
        Some("X-Payment"),
        Some("Cookie"),
    ] {
        let m = Merchant::new("exact").await;
        let a = Authority::new(Decision::Allow);
        let c = Arc::new(Context::new(Some(a.clone())));
        let mut arguments = args(&m.url, header.map(|_| "op"));
        if let Some(h) = header {
            arguments["headers"] = json!({h:"untrusted"});
        }
        let result = call(c, arguments).await;
        assert_eq!(result.is_error, Some(true));
        assert_eq!(m.probes.load(Ordering::SeqCst), 0);
        assert_eq!(a.calls.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn yaml_permissions_remain_an_independent_gate() {
    for (cap, decision, calls, error) in [
        ("$0.000001", Decision::Allow, 0, "MCP permission denied"),
        ("$1.00", Decision::Deny, 1, "DENIED"),
    ] {
        let m = Merchant::new("exact-with-cluster").await;
        let a = Authority::new(decision);
        let mut c = Context::new(Some(a.clone()));
        let yaml: PermissionConfig = serde_yml::from_str(&format!("max_payment: '{cap}'")).unwrap();
        c.permissions = Some(Arc::new(McpPermissions::from_config(&yaml).unwrap()));
        let c = Arc::new(c);
        let result = call(c.clone(), args(&m.url, Some("yaml-and-authority"))).await;
        assert!(
            text(&result).contains(error),
            "expected {error}: {}",
            text(&result)
        );
        assert_eq!(a.calls.load(Ordering::SeqCst), calls);
        assert_eq!(c.store.reads.load(Ordering::SeqCst), 0);
        assert_eq!(c.approval.load(Ordering::SeqCst), 0);
        assert_eq!(m.paid.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn unsupported_version_and_redirect_cannot_find_a_free_path() {
    for mode in ["v1", "redirect", "mpp"] {
        let m = Merchant::new(mode).await;
        let a = Authority::new(Decision::Allow);
        let c = Arc::new(Context::new(Some(a.clone())));
        let _ = call(c.clone(), args(&m.url, Some(mode))).await;
        assert_eq!(m.probes.load(Ordering::SeqCst), 1);
        assert_eq!(m.paid.load(Ordering::SeqCst), 0);
        assert_eq!(c.store.reads.load(Ordering::SeqCst), 0);
        assert_eq!(a.calls.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn disabled_authority_preserves_existing_paid_path_without_operation_id() {
    let m = Merchant::new("exact").await;
    let c = Arc::new(Context::new(None));
    let result = call(c.clone(), args(&m.url, None)).await;
    assert_eq!(result.is_error, Some(false));
    assert_eq!(m.probes.load(Ordering::SeqCst), 1);
    assert_eq!(m.paid.load(Ordering::SeqCst), 1);
    assert_eq!(c.approval.load(Ordering::SeqCst), 1);
}
#[tokio::test(flavor = "multi_thread")]
async fn free_response_does_not_consult_authority() {
    let m = Merchant::new("free").await;
    let a = Authority::new(Decision::Deny);
    let result = call(
        Arc::new(Context::new(Some(a.clone()))),
        args(&m.url, Some("free")),
    )
    .await;
    assert_eq!(result.is_error, Some(false));
    assert_eq!(a.calls.load(Ordering::SeqCst), 0);
    assert_eq!(m.paid.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_context_and_forged_caller_are_not_authorization_fallbacks() {
    for configuration_failure in [true, false] {
        let m = Merchant::new("exact").await;
        let a = Authority::new(Decision::Allow);
        let mut c = Context::new(Some(a.clone()));
        c.config_error = configuration_failure;
        let (x, y) = tokio::io::duplex(65536);
        let (server, client) =
            tokio::join!(PayMcp::with_context(Arc::new(c)).serve(x), ().serve(y));
        let server = server.unwrap();
        let client = client.unwrap();
        let mut arguments = args(&m.url, Some("trusted-only"));
        if !configuration_failure {
            arguments["caller_id"] = json!("impersonated-agent");
        }
        let outcome = client
            .call_tool(
                CallToolRequestParams::new("curl")
                    .with_arguments(arguments.as_object().unwrap().clone()),
            )
            .await;
        // rmcp may map handler/parameter errors to tool errors rather than JSON-RPC.
        let error = match outcome {
            Ok(result) => {
                assert_eq!(result.is_error, Some(true));
                text(&result)
            }
            Err(error) => error.to_string(),
        };
        assert!(error.contains(if configuration_failure {
            "authority configuration unavailable"
        } else {
            "unknown field"
        }));
        assert_eq!(a.calls.load(Ordering::SeqCst), 0);
        assert_eq!(m.probes.load(Ordering::SeqCst), 0);
        assert_eq!(m.paid.load(Ordering::SeqCst), 0);
        client.cancel().await.unwrap();
        server.cancel().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn canonical_yaml_rejection_remains_fail_closed_without_a_fallback() {
    let m = Merchant::new("exact").await;
    let a = Authority::new(Decision::Allow);
    let mut c = Context::new(Some(a.clone()));
    c.permissions = Some(Arc::new(
        McpPermissions::from_config(&serde_yml::from_str("max_payment: '$1.00'").unwrap()).unwrap(),
    ));
    let c = Arc::new(c);
    let result = call(c.clone(), args(&m.url, Some("existing-yaml-rejection"))).await;
    assert!(text(&result).contains("invalid Solana network"));
    assert_eq!(a.calls.load(Ordering::SeqCst), 0);
    assert_eq!(c.store.reads.load(Ordering::SeqCst), 0);
    assert_eq!(c.approval.load(Ordering::SeqCst), 0);
    assert_eq!(m.paid.load(Ordering::SeqCst), 0);
}

struct CustodyBoundary {
    fail: bool,
}
impl pay_mcp::controlled::ControlledExecution for CustodyBoundary {
    fn plan(&self, _: &SpendRequest) -> pay_core::Result<pay_mcp::controlled::ExecutionPlan> {
        if self.fail {
            return Err(pay_core::Error::PaymentRejected(
                "CONTROLLER_UNAVAILABLE".into(),
            ));
        }
        Ok(pay_mcp::controlled::ExecutionPlan::Replay {
            response: pay_mcp::controlled::ControlledResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: b"{\"fixture\":\"controller-delivery\"}".to_vec(),
            },
        })
    }
    fn execute(
        &self,
        _: &SpendRequest,
        _: Value,
    ) -> pay_core::Result<pay_mcp::controlled::ControlledResponse> {
        panic!("replay cannot enter preparation or execution")
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn controlled_execution_never_loads_an_account_or_falls_back_to_pay_signing() {
    for fail in [false, true] {
        let m = Merchant::new("exact").await;
        let mut c = Context::new(Some(Authority::new(Decision::Allow)));
        c.controller = Some(Arc::new(CustodyBoundary { fail }));
        let c = Arc::new(c);
        let result = call(c.clone(), args(&m.url, Some("controlled"))).await;
        assert_eq!(result.is_error, Some(fail));
        assert!(text(&result).contains(if fail {
            "CONTROLLER_UNAVAILABLE"
        } else {
            "controller-delivery"
        }));
        assert_eq!(m.probes.load(Ordering::SeqCst), 1);
        assert_eq!(m.paid.load(Ordering::SeqCst), 0);
        assert_eq!(c.store.reads.load(Ordering::SeqCst), 0);
        assert_eq!(c.approval.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mainnet_route_metadata_reaches_authority_without_account_or_signer_access() {
    for mode in [
        "exact",
        "mainnet-metadata",
        "agent402-public",
        "agent402-same-query",
    ] {
        let m = Merchant::new(mode).await;
        let authority = Authority::new(Decision::Allow);
        let mut c = Context::new(Some(authority.clone()));
        c.controller = Some(Arc::new(CustodyBoundary { fail: false }));
        let c = Arc::new(c);
        let url = format!("{}?coins=BTC%2CETH%2CSOL&currency=usd", m.url);
        let result = call(
            c.clone(),
            json!({"url":url,"method":"GET","operation_id":mode}),
        )
        .await;
        assert_eq!(result.is_error, Some(false));
        assert!(text(&result).contains("controller-delivery"));
        assert_eq!(authority.calls.load(Ordering::SeqCst), 1);
        let facts = authority.facts.lock().unwrap();
        assert_eq!(facts[0].request.url, url);
        let envelope = facts[0].payment_required.as_ref().unwrap();
        assert_eq!(
            envelope["resource"]["url"].as_str().unwrap(),
            if mode == "agent402-same-query" {
                url.as_str()
            } else {
                m.url.as_str()
            }
        );
        assert!(facts[0].request.url.contains("?coins="));
        assert_eq!(
            envelope["accepts"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|offer| **offer == facts[0].accepted)
                .count(),
            1
        );
        if mode == "agent402-public" {
            let mut public_quote: Value =
                serde_json::from_str(include_str!("fixtures/agent402-mainnet-quote.json")).unwrap();
            public_quote["resource"]["url"] = json!(m.url);
            assert_eq!(
                envelope, &public_quote,
                "no route metadata, alternatives or extension fields may disappear"
            );
            assert_eq!(facts[0].amount_atomic, "1000");
            assert_eq!(facts[0].asset, MINT);
        }
        assert_eq!(m.probes.load(Ordering::SeqCst), 1);
        assert_eq!(m.paid.load(Ordering::SeqCst), 0);
        assert_eq!(c.store.reads.load(Ordering::SeqCst), 0);
        assert_eq!(c.approval.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn controlled_quote_constraints_remain_terminal_before_authority() {
    for mode in [
        "agent402-required-id",
        "agent402-invalid-required",
        "agent402-normalizing-extension",
        "agent402-other-origin",
        "agent402-other-query",
        "agent402-other-path",
        "agent402-duplicate-offer",
    ] {
        let m = Merchant::new(mode).await;
        let authority = Authority::new(Decision::Allow);
        let mut context = Context::new(Some(authority.clone()));
        context.controller = Some(Arc::new(CustodyBoundary { fail: false }));
        let context = Arc::new(context);
        let result = call(
            context.clone(),
            json!({"url":format!("{}?coins=BTC", m.url),"method":"GET","operation_id":mode}),
        )
        .await;
        assert_eq!(result.is_error, Some(true), "{mode}");
        assert_eq!(authority.calls.load(Ordering::SeqCst), 0, "{mode}");
        assert_eq!(m.paid.load(Ordering::SeqCst), 0);
        assert_eq!(context.store.reads.load(Ordering::SeqCst), 0);
        assert_eq!(context.approval.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mainnet_multichain_quote_selects_native_solana_before_a_deny_only_probe() {
    let m = Merchant::new("mainnet-metadata").await;
    let authority = Authority::new(Decision::Deny);
    let context = Arc::new(Context::new(Some(authority.clone())));
    // No controller in this classifier-only probe. Deny is terminal; it is
    // not an authority success or a Mainnet purchase integration claim.
    let result = call(
        context.clone(),
        json!({"url":m.url,"method":"GET","operation_id":"quote-probe"}),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    assert!(text(&result).contains("DENIED"));
    let facts = authority.facts.lock().unwrap();
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].network, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp");
    assert_eq!(facts[0].asset, MINT);
    assert_eq!(facts[0].amount_atomic, "1000");
    assert!(facts[0].payment_required.is_none());
    assert!(
        serde_json::to_value(&facts[0])
            .unwrap()
            .get("payment_required")
            .is_none(),
        "the optional authority hook without custody keeps its existing wire facts"
    );
    assert!(facts[0].accepted["extra"].get("decimals").is_none());
    assert_eq!(context.store.reads.load(Ordering::SeqCst), 0);
    assert_eq!(context.approval.load(Ordering::SeqCst), 0);
    assert_eq!(m.paid.load(Ordering::SeqCst), 0);
}
