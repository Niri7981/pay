//! Lifecycle regressions against a stateful Scheduler/Functions REST fixture
//! and a real Redis budget store.
use std::collections::BTreeMap;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use super::*;
use crate::trigger_types::TriggerTarget;

pub(super) const TENANT: &str = "0123456789abcdef";
pub(super) const FUNCTION: &str = "gcf-0123456789abcdef-weather";

#[derive(Default)]
pub(super) struct MockState {
    pub(super) jobs: BTreeMap<String, Value>,
    pub(super) functions: BTreeMap<String, Value>,
    pub(super) invocations: Vec<String>,
    pub(super) fail_job_delete: Option<String>,
}

struct RedisProcess(Child);

impl Drop for RedisProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TlsListener {
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, address) = self.listener.accept().await.unwrap();
            if let Ok(stream) = self.acceptor.accept(stream).await {
                return (stream, address);
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

pub(super) struct Harness {
    pub(super) driver: GoogleTriggerDriver,
    pub(super) state: Arc<Mutex<MockState>>,
    pub(super) origin: String,
    redis: redis::aio::MultiplexedConnection,
    servers: Vec<tokio::task::JoinHandle<()>>,
    _redis: RedisProcess,
}

impl Drop for Harness {
    fn drop(&mut self) {
        for server in &self.servers {
            server.abort();
        }
    }
}

fn json_response(status: StatusCode, value: Value) -> Response {
    (status, axum::Json(value)).into_response()
}

fn handle(state: &Mutex<MockState>, method: &str, path: &str, body: Value) -> Response {
    let mut state = state.lock().unwrap();
    if path == "/instance/service-accounts/default/identity" {
        return Response::new(Body::from("fixture-identity-token"));
    }
    if let Some(resource) = path.strip_prefix("/v2/") {
        return match state.functions.get(resource) {
            Some(function) => json_response(StatusCode::OK, function.clone()),
            None => json_response(StatusCode::NOT_FOUND, json!({})),
        };
    }
    let resource = path.strip_prefix("/v1/").unwrap_or(path).to_string();
    if let Some((job, verb)) = resource.split_once(':') {
        let Some(current) = state.jobs.get_mut(job) else {
            return json_response(StatusCode::NOT_FOUND, json!({}));
        };
        match verb {
            "pause" => current["state"] = json!("PAUSED"),
            "resume" => current["state"] = json!("ENABLED"),
            _ => {}
        }
        return json_response(StatusCode::OK, current.clone());
    }
    if resource.ends_with("/jobs") {
        return match method {
            "GET" => json_response(
                StatusCode::OK,
                json!({ "jobs": state.jobs.values().cloned().collect::<Vec<_>>() }),
            ),
            "POST" => {
                let name = body["name"].as_str().unwrap().to_string();
                if state.jobs.contains_key(&name) {
                    return json_response(StatusCode::CONFLICT, json!({}));
                }
                state.jobs.insert(name, body.clone());
                json_response(StatusCode::OK, body)
            }
            _ => panic!("unexpected {method} {path}"),
        };
    }
    match method {
        "GET" => match state.jobs.get(&resource) {
            Some(job) => json_response(StatusCode::OK, job.clone()),
            None => json_response(StatusCode::NOT_FOUND, json!({})),
        },
        "PATCH" => match state.jobs.get_mut(&resource) {
            Some(job) => {
                *job = body;
                json_response(StatusCode::OK, job.clone())
            }
            None => json_response(StatusCode::NOT_FOUND, json!({})),
        },
        "DELETE" if state.fail_job_delete.as_deref() == Some(resource.as_str()) => {
            json_response(StatusCode::SERVICE_UNAVAILABLE, json!({}))
        }
        "DELETE" => match state.jobs.remove(&resource) {
            Some(_) => json_response(StatusCode::OK, json!({})),
            None => json_response(StatusCode::NOT_FOUND, json!({})),
        },
        _ => panic!("unexpected {method} {path}"),
    }
}

impl Harness {
    pub(super) async fn new() -> Self {
        let state = Arc::new(Mutex::new(MockState::default()));
        let handler_state = state.clone();
        let api = Router::new().fallback(move |request: Request<Body>| {
            let state = handler_state.clone();
            async move {
                let (parts, body) = request.into_parts();
                let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
                let body = if bytes.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes).unwrap()
                };
                handle(&state, parts.method.as_str(), parts.uri.path(), body)
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let api_server = tokio::spawn(async move { axum::serve(listener, api).await.unwrap() });

        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = reqwest::Certificate::from_der(generated.cert.der()).unwrap();
        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![generated.cert.der().clone()],
                tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(
                    generated.signing_key.serialize_der(),
                )
                .into(),
            )
            .unwrap();
        let tls = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://localhost:{}", tls.local_addr().unwrap().port());
        let origin_state = state.clone();
        let function = Router::new().fallback(move |request: Request<Body>| {
            let state = origin_state.clone();
            async move {
                state
                    .lock()
                    .unwrap()
                    .invocations
                    .push(request.uri().path().to_string());
                json_response(StatusCode::OK, json!({ "ok": true }))
            }
        });
        let tls_server = tokio::spawn(async move {
            axum::serve(
                TlsListener {
                    listener: tls,
                    acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
                },
                function,
            )
            .await
            .unwrap()
        });

        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let mut redis_process = RedisProcess(
            Command::new("redis-server")
                .args([
                    "--bind",
                    "127.0.0.1",
                    "--port",
                    &port.to_string(),
                    "--save",
                    "",
                    "--appendonly",
                    "no",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("redis-server must be installed"),
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                assert!(
                    redis_process.0.try_wait().unwrap().is_none(),
                    "Redis exited before startup"
                );
                if tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let redis_url = format!("redis://127.0.0.1:{port}");
        let redis = redis::Client::open(redis_url.clone())
            .unwrap()
            .get_multiplexed_async_connection()
            .await
            .unwrap();
        let mut driver = GoogleTriggerDriver::new(GoogleTriggerConfig {
            project: "project".into(),
            default_region: "us-central1".into(),
            scheduler_api_base: base.clone(),
            functions_api_base: base.clone(),
            metadata_base: base.clone(),
            access_token: Some("management-token".into()),
            redis_url,
            executor_url: format!("{base}/executor"),
            executor_proof: "fixture-proof-long-enough-for-validation".into(),
        })
        .await
        .unwrap();
        driver.client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(certificate)
            .build()
            .unwrap();
        Self {
            driver,
            state,
            origin,
            redis,
            servers: vec![api_server, tls_server],
            _redis: redis_process,
        }
    }

    pub(super) fn function_resource(name: &str) -> String {
        format!("projects/project/locations/us-central1/functions/{name}")
    }

    /// Install a budget-compatible function leased to `channel_id`.
    pub(super) fn add_function(&self, name: &str, channel_id: &str, created_at: &str) {
        let resource = Self::function_resource(name);
        let function = json!({
            "name": resource,
            "createTime": created_at,
            "labels": {
                "managed-by": "mcp-compute",
                "pay-tenant": TENANT,
                "pay-channel": function_lease(channel_id),
            },
            "serviceConfig": {
                "uri": self.origin,
                "timeoutSeconds": 60,
                "availableMemory": "256M",
                "availableCpu": "1"
            }
        });
        self.state
            .lock()
            .unwrap()
            .functions
            .insert(resource, function);
    }

    pub(super) fn remove_function(&self, name: &str) {
        self.state
            .lock()
            .unwrap()
            .functions
            .remove(&Self::function_resource(name));
    }

    pub(super) async fn remaining(&mut self, resource: &str) -> Option<i64> {
        redis::cmd("HGET")
            .arg(GoogleTriggerDriver::budget_key(resource))
            .arg("remaining")
            .query_async(&mut self.redis)
            .await
            .unwrap()
    }

    pub(super) async fn set_remaining(&mut self, resource: &str, remaining: i64) {
        redis::cmd("HSET")
            .arg(GoogleTriggerDriver::budget_key(resource))
            .arg("remaining")
            .arg(remaining)
            .query_async::<()>(&mut self.redis)
            .await
            .unwrap();
    }

    /// Decode the trusted executor payload stored in a Scheduler job.
    pub(super) fn executor_request(&self, resource: &str) -> ExecuteTriggerRequest {
        let state = self.state.lock().unwrap();
        let body = state.jobs[resource]["httpTarget"]["body"].as_str().unwrap();
        serde_json::from_slice(
            &base64::engine::general_purpose::STANDARD
                .decode(body)
                .unwrap(),
        )
        .unwrap()
    }

    pub(super) fn invocations(&self) -> usize {
        self.state.lock().unwrap().invocations.len()
    }
}

pub(super) fn function_lease(channel_id: &str) -> String {
    Sha256::digest(channel_id.as_bytes())[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(super) fn tenant(channel_id: &str) -> Tenant {
    Tenant {
        payer: "payer".into(),
        key: TENANT.into(),
        channel_id: channel_id.into(),
    }
}

pub(super) fn create_request(name: &str, target: &str, cron: &str) -> CreateTriggerRequest {
    CreateTriggerRequest {
        driver: DRIVER_ID.into(),
        name: name.into(),
        region: None,
        configuration: TriggerConfiguration::Schedule {
            cron: cron.into(),
            timezone: "Etc/UTC".into(),
        },
        target: TriggerTarget {
            provider: "google-cloud-functions".into(),
            id: target.into(),
            region: None,
            path: "/refresh".into(),
        },
        input: json!({ "units": "metric" }),
        headers: BTreeMap::new(),
    }
}

#[tokio::test]
#[ignore = "requires redis-server on PATH; run with --ignored"]
async fn trigger_updates_preserve_the_remaining_prepaid_budget() {
    let mut harness = Harness::new().await;
    harness.add_function(FUNCTION, "channelA", "2026-01-01T00:00:00Z");
    let owner = tenant("channelA");
    let created = harness
        .driver
        .create(&owner, create_request("refresh", "weather", "*/5 * * * *"))
        .await
        .unwrap();
    assert_eq!(
        harness.remaining(&created.id).await,
        Some(PREPAID_RUNS.into())
    );

    // Exhaust the funded allowance, then update the trigger.
    harness.set_remaining(&created.id, 0).await;
    let updated = harness
        .driver
        .create(&owner, create_request("refresh", "weather", "*/10 * * * *"))
        .await
        .unwrap();
    assert_eq!(updated.id, created.id);
    assert_eq!(
        harness.remaining(&created.id).await,
        Some(0),
        "an ordinary update must not refill the prepaid budget"
    );
    let request = harness.executor_request(&created.id);
    assert!(harness.driver.execute(request).await.is_err());
    assert_eq!(harness.invocations(), 0);

    // A partially used budget is preserved exactly across updates.
    harness.set_remaining(&created.id, 7).await;
    harness
        .driver
        .create(&owner, create_request("refresh", "weather", "*/15 * * * *"))
        .await
        .unwrap();
    assert_eq!(harness.remaining(&created.id).await, Some(7));

    // A deleted trigger has no budget; recreating it is a new incarnation.
    harness
        .driver
        .delete(
            &owner,
            TriggerRequest {
                driver: DRIVER_ID.into(),
                id: created.id.clone(),
                region: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(harness.remaining(&created.id).await, None);
    harness
        .driver
        .create(&owner, create_request("refresh", "weather", "*/5 * * * *"))
        .await
        .unwrap();
    assert_eq!(
        harness.remaining(&created.id).await,
        Some(PREPAID_RUNS.into())
    );
}

#[tokio::test]
#[ignore = "requires redis-server on PATH; run with --ignored"]
async fn trigger_creation_retries_after_a_funding_fault_are_funded() {
    let mut harness = Harness::new().await;
    harness.add_function(FUNCTION, "channelA", "2026-01-01T00:00:00Z");
    let owner = tenant("channelA");
    let physical = harness.driver.physical_name(&owner, "refresh").unwrap();
    let resource = harness.driver.resource("us-central1", &physical).unwrap();

    // A non-hash value makes the budget write fail like a transient Redis fault.
    redis::cmd("SET")
        .arg(GoogleTriggerDriver::budget_key(&resource))
        .arg("fault")
        .query_async::<()>(&mut harness.redis)
        .await
        .unwrap();
    assert!(
        harness
            .driver
            .create(&owner, create_request("refresh", "weather", "*/5 * * * *"))
            .await
            .is_err()
    );
    assert!(
        harness.state.lock().unwrap().jobs.is_empty(),
        "no Scheduler job may exist without a funded budget"
    );

    redis::cmd("DEL")
        .arg(GoogleTriggerDriver::budget_key(&resource))
        .query_async::<()>(&mut harness.redis)
        .await
        .unwrap();
    let created = harness
        .driver
        .create(&owner, create_request("refresh", "weather", "*/5 * * * *"))
        .await
        .unwrap();
    assert_eq!(created.id, resource);
    assert_eq!(
        harness.remaining(&resource).await,
        Some(PREPAID_RUNS.into()),
        "the healthy retry must fund the new job"
    );
    let request = harness.executor_request(&resource);
    harness.driver.execute(request).await.unwrap();
    assert_eq!(harness.invocations(), 1);

    // Once created, an exhausted budget stays exhausted across updates.
    harness.set_remaining(&resource, 0).await;
    harness
        .driver
        .create(&owner, create_request("refresh", "weather", "*/10 * * * *"))
        .await
        .unwrap();
    assert_eq!(harness.remaining(&resource).await, Some(0));
}

#[tokio::test]
#[ignore = "requires redis-server on PATH; run with --ignored"]
async fn trigger_control_is_scoped_to_the_funding_channel() {
    let mut harness = Harness::new().await;
    harness.add_function(FUNCTION, "channelA", "2026-01-01T00:00:00Z");
    let owner = tenant("channelA");
    let sibling = tenant("channelB");
    let trigger = harness
        .driver
        .create(&owner, create_request("refresh", "weather", "*/5 * * * *"))
        .await
        .unwrap();
    let request = || TriggerRequest {
        driver: DRIVER_ID.into(),
        id: trigger.id.clone(),
        region: None,
    };
    assert!(harness.driver.get(&sibling, request()).await.is_err());
    assert!(harness.driver.pause(&sibling, request()).await.is_err());
    assert!(harness.driver.resume(&sibling, request()).await.is_err());
    assert!(harness.driver.run_now(&sibling, request()).await.is_err());
    assert!(harness.driver.delete(&sibling, request()).await.is_err());
    let listed = |tenant: Tenant| {
        let driver = harness.driver.clone();
        async move {
            driver
                .list(
                    &tenant,
                    ListTriggersRequest {
                        driver: DRIVER_ID.into(),
                        region: None,
                        page_size: 50,
                        page_token: None,
                    },
                )
                .await
                .unwrap()
                .triggers
                .len()
        }
    };
    assert_eq!(listed(sibling.clone()).await, 0);
    assert_eq!(listed(owner.clone()).await, 1);
    assert!(harness.state.lock().unwrap().jobs.contains_key(&trigger.id));
    assert_eq!(
        harness.remaining(&trigger.id).await,
        Some(PREPAID_RUNS.into())
    );

    assert_eq!(
        harness.driver.get(&owner, request()).await.unwrap().id,
        trigger.id
    );
    assert_eq!(
        harness.driver.pause(&owner, request()).await.unwrap().state,
        "PAUSED"
    );
    harness.driver.run_now(&owner, request()).await.unwrap();
    harness.driver.delete(&owner, request()).await.unwrap();
    assert!(!harness.state.lock().unwrap().jobs.contains_key(&trigger.id));
}

#[tokio::test]
#[ignore = "requires redis-server on PATH; run with --ignored"]
async fn triggers_cannot_target_another_channels_deployment() {
    let mut harness = Harness::new().await;
    harness.add_function(FUNCTION, "channelA", "2026-01-01T00:00:00Z");
    let sibling = tenant("channelB");
    assert!(
        harness
            .driver
            .create(
                &sibling,
                create_request("refresh", "weather", "*/5 * * * *")
            )
            .await
            .is_err()
    );
    assert!(harness.state.lock().unwrap().jobs.is_empty());

    let trigger = harness
        .driver
        .create(
            &tenant("channelA"),
            create_request("refresh", "weather", "*/5 * * * *"),
        )
        .await
        .unwrap();
    let request = harness.executor_request(&trigger.id);
    assert_eq!(request.target_channel_lease, function_lease("channelA"));
    harness.driver.execute(request.clone()).await.unwrap();
    assert_eq!(harness.invocations(), 1);
    assert_eq!(
        harness.remaining(&trigger.id).await,
        Some(i64::from(PREPAID_RUNS) - 1)
    );

    // The target now belongs to another channel: execution fails closed
    // before consuming budget or invoking it.
    harness.add_function(FUNCTION, "channelB", "2026-01-01T00:00:00Z");
    assert!(harness.driver.execute(request).await.is_err());
    assert_eq!(harness.invocations(), 1);
    assert_eq!(
        harness.remaining(&trigger.id).await,
        Some(i64::from(PREPAID_RUNS) - 1)
    );
}

#[tokio::test]
#[ignore = "requires redis-server on PATH; run with --ignored"]
async fn stale_schedules_cannot_invoke_a_recreated_function() {
    let mut harness = Harness::new().await;
    harness.add_function(FUNCTION, "channelA", "2026-01-01T00:00:00Z");
    let owner = tenant("channelA");
    let trigger = harness
        .driver
        .create(&owner, create_request("refresh", "weather", "*/5 * * * *"))
        .await
        .unwrap();
    let request = harness.executor_request(&trigger.id);
    assert_eq!(request.target_created_at, "2026-01-01T00:00:00Z");
    harness.driver.execute(request.clone()).await.unwrap();
    assert_eq!(harness.invocations(), 1);

    // Same payer, same channel, same name: a different incarnation.
    harness.remove_function(FUNCTION);
    harness.add_function(FUNCTION, "channelA", "2026-02-01T00:00:00Z");
    assert!(harness.driver.execute(request.clone()).await.is_err());
    let mut legacy = request;
    legacy.target_created_at = String::new();
    assert!(harness.driver.execute(legacy).await.is_err());
    assert_eq!(harness.invocations(), 1);
    assert_eq!(
        harness.remaining(&trigger.id).await,
        Some(i64::from(PREPAID_RUNS) - 1)
    );
}

#[tokio::test]
#[ignore = "requires redis-server on PATH; run with --ignored"]
async fn channel_cleanup_revokes_every_budget_despite_job_deletion_failures() {
    let mut harness = Harness::new().await;
    harness.add_function(FUNCTION, "channelA", "2026-01-01T00:00:00Z");
    let owner = tenant("channelA");
    let first = harness
        .driver
        .create(&owner, create_request("first", "weather", "*/5 * * * *"))
        .await
        .unwrap();
    let second = harness
        .driver
        .create(&owner, create_request("second", "weather", "*/5 * * * *"))
        .await
        .unwrap();
    harness.state.lock().unwrap().fail_job_delete = Some(first.id.clone());
    assert!(harness.driver.cleanup_channel("channelA").await.is_err());
    assert_eq!(harness.remaining(&first.id).await, None);
    assert_eq!(harness.remaining(&second.id).await, None);
    assert!(!harness.state.lock().unwrap().jobs.contains_key(&second.id));
    // The surviving job has no budget left to execute with.
    let request = harness.executor_request(&first.id);
    assert!(harness.driver.execute(request).await.is_err());
    assert_eq!(harness.invocations(), 0);

    harness.state.lock().unwrap().fail_job_delete = None;
    assert_eq!(harness.driver.cleanup_channel("channelA").await.unwrap(), 1);
    assert!(harness.state.lock().unwrap().jobs.is_empty());
}
