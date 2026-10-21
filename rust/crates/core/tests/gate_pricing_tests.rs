//! Payment-gate pricing: the amounts and splits the gate challenges for.
//!
//! Run: `cargo test -p pay-core --features server --test gate_pricing_tests`

#![cfg(feature = "server")]

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use pay_core::PaymentState;
use pay_core::server::gate::{GateDecision, GateRequest, PaymentGate};
use pay_kit::mpp::server::{Config, Mpp};
use pay_kit::mpp::{ChargeRequest, parse_www_authenticate};
use pay_types::metering::ApiSpec;

#[derive(Clone)]
struct State {
    apis: Arc<Vec<ApiSpec>>,
    mpp: Mpp,
}

impl PaymentState for State {
    fn apis(&self) -> &[ApiSpec] {
        &self.apis
    }

    fn mpp(&self) -> Option<&Mpp> {
        Some(&self.mpp)
    }
}

/// SOL at 9 decimals: $1 in the spec is 1_000_000_000 base units on the wire.
fn sol_mpp() -> Mpp {
    Mpp::new(Config {
        recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
        currency: "SOL".to_string(),
        decimals: 9,
        network: "localnet".to_string(),
        rpc_url: Some("http://127.0.0.1:8899".to_string()),
        challenge_binding_secret: Some("test-secret-key-do-not-use-32b-pad".to_string()),
        realm: Some("test-realm".to_string()),
        store: Some(std::sync::Arc::new(pay_kit::mpp::store::MemoryStore::new())),
        ..Default::default()
    })
    .expect("local MPP backend")
}

fn spec(yaml: &str) -> ApiSpec {
    let mut api: ApiSpec = serde_yml::from_str(yaml).expect("spec parses");
    api.apply_scheme_defaults();
    api
}

struct Challenge {
    status: StatusCode,
    charge: Option<ChargeRequest>,
    body: serde_json::Value,
}

async fn challenge(api: &ApiSpec, path: &str, content_length: Option<u64>) -> Challenge {
    let state = State {
        apis: Arc::new(vec![api.clone()]),
        mpp: sol_mpp(),
    };
    let host = format!("{}.localhost", api.subdomain);
    let decision = PaymentGate::new(state)
        .evaluate(&GateRequest {
            method: &Method::POST,
            path,
            host: Some(&host),
            accept: None,
            authorization: None,
            content_length,
            query: None,
            x402_payment: None,
        })
        .await;
    let GateDecision::Respond(response) = decision else {
        panic!("an unpaid metered request must not be forwarded");
    };
    let charge = response
        .headers
        .iter()
        .filter(|(name, _)| name == axum::http::header::WWW_AUTHENTICATE)
        .filter_map(|(_, value)| parse_www_authenticate(value.to_str().ok()?).ok())
        .find(|c| c.intent.as_str() == "charge")
        .map(|c| c.request.decode::<ChargeRequest>().expect("charge request"));
    Challenge {
        status: response.status,
        charge,
        body: serde_json::from_slice(&response.body).unwrap_or_default(),
    }
}

async fn charge_amount(api: &ApiSpec, path: &str, content_length: Option<u64>) -> String {
    let challenge = challenge(api, path, content_length).await;
    assert_eq!(
        challenge.status,
        StatusCode::PAYMENT_REQUIRED,
        "{}",
        challenge.body
    );
    challenge.charge.expect("MPP charge challenge").amount
}

// ── Body-selected variants (SOLA1-60) ───────────────────────────────────────

const BODY_VARIANTS: &str = r#"
name: body-variant
subdomain: body-variant
title: Body variant
description: Body-selected pricing variants
category: ai_ml
version: v1
routing:
  type: respond
endpoints:
  - method: POST
    path: v1/generate
    metering:
      variants:
        - param: model
          value: cheap
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers: [{price_usd: 0.01}]
        - param: model
          value: premium
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers: [{price_usd: 0.10}]
  - method: POST
    path: v1/models/{modelId}:generate
    metering:
      variants:
        - param: model
          value: cheap
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers: [{price_usd: 0.01}]
        - param: model
          value: premium
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers: [{price_usd: 0.10}]
        - param: model
          value: default
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers: [{price_usd: 0.05}]
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_selectable_variant_is_charged_at_the_most_expensive_candidate() {
    let api = spec(BODY_VARIANTS);
    assert!(pay_types::metering::validate_api_spec(&api).is_empty());
    // The body may select `premium`; a fixed charge cannot see it, so it must
    // not settle for the first (cheap) variant.
    assert_eq!(
        charge_amount(&api, "v1/generate", Some(64)).await,
        "100000000"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_selected_variant_keeps_its_own_price() {
    let api = spec(BODY_VARIANTS);
    assert_eq!(
        charge_amount(&api, "v1/models/cheap:generate", None).await,
        "10000000"
    );
    assert_eq!(
        charge_amount(&api, "v1/models/premium:generate", None).await,
        "100000000"
    );
    // An unlisted path model uses the explicit `default` variant.
    assert_eq!(
        charge_amount(&api, "v1/models/other:generate", None).await,
        "50000000"
    );
}

// ── Overlapping variant values (SOLA1-62) ──────────────────────────────────

const OVERLAPPING_VARIANTS: &str = r#"
name: collision
subdomain: collision
title: Collision
description: Overlapping model variants
category: ai_ml
version: v1
routing:
  type: respond
endpoints:
  - method: POST
    path: v1/models/{modelId}:generate
    metering:
      schemes: [mpp-charge]
      variants:
        - param: model
          value: gpt-4
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers: [{price_usd: 0.01}]
        - param: model
          value: gpt-4o
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers: [{price_usd: 1.00}]
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_variant_is_priced_by_the_forwarded_model() {
    let api = spec(OVERLAPPING_VARIANTS);
    assert!(pay_types::metering::validate_api_spec(&api).is_empty());
    assert_eq!(
        charge_amount(&api, "v1/models/gpt-4o:generate", None).await,
        "1000000000"
    );
    assert_eq!(
        charge_amount(&api, "v1/models/gpt-4:generate", None).await,
        "10000000"
    );
}

// ── Per-tier split beneficiaries (SOLA1-70) ────────────────────────────────

const AFFILIATE_A: &str = "CNR1b172rotbSG6kCpfR76KB2ios2y7X4p8yEEc7pjLu";
const AFFILIATE_B: &str = "F82JMeQmD7Lfbh6vCJWsz2ABJ5AAthhVjUyqzgHyUtog";

fn tier_split_spec() -> ApiSpec {
    spec(&format!(
        r#"
name: tier-split
subdomain: tier-split
title: Tier split
description: Conditional tiers with tier-specific split beneficiaries
category: ai_ml
version: v1
routing:
  type: respond
recipients:
  affiliate_a:
    account: "{AFFILIATE_A}"
  affiliate_b:
    account: "{AFFILIATE_B}"
endpoints:
  - method: POST
    path: v1/tier
    metering:
      schemes: [mpp-charge]
      dimensions:
        - direction: usage
          unit: requests
          scale: 1
          tiers:
            - price_usd: 0.01
              condition: {{field: body_size, op: "<=", value: 1000}}
              splits:
                - {{recipient: affiliate_a, amount: 0.001, memo: first-tier}}
            - price_usd: 1.00
              condition: {{field: body_size, op: ">", value: 1000}}
              splits:
                - {{recipient: affiliate_b, percent: 20, memo: second-tier}}
  - method: POST
    path: v1/models/{{modelId}}:generate
    metering:
      schemes: [mpp-charge]
      variants:
        - param: model
          value: cheap
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers:
                - price_usd: 0.01
                  splits: [{{recipient: affiliate_a, amount: 0.001}}]
        - param: model
          value: premium
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers:
                - price_usd: 1.00
                  splits: [{{recipient: affiliate_b, percent: 20}}]
"#
    ))
}

fn splits(charge: &ChargeRequest) -> Vec<(String, String)> {
    charge
        .method_details
        .as_ref()
        .and_then(|details| details.get("splits"))
        .and_then(|splits| splits.as_array())
        .map(|splits| {
            splits
                .iter()
                .map(|split| {
                    (
                        split["recipient"].as_str().unwrap().to_string(),
                        split["amount"].as_str().unwrap().to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn charge(api: &ApiSpec, path: &str, content_length: Option<u64>) -> ChargeRequest {
    let challenge = challenge(api, path, content_length).await;
    assert_eq!(
        challenge.status,
        StatusCode::PAYMENT_REQUIRED,
        "{}",
        challenge.body
    );
    challenge.charge.expect("MPP charge challenge")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selected_conditional_tier_carries_its_own_splits() {
    let api = tier_split_spec();
    assert!(
        pay_types::metering::validate_api_spec(&api).is_empty(),
        "{:?}",
        pay_types::metering::validate_api_spec(&api)
    );

    let large = charge(&api, "v1/tier", Some(1001)).await;
    assert_eq!(large.amount, "1000000000");
    assert_eq!(
        splits(&large),
        vec![(AFFILIATE_B.to_string(), "200000000".to_string())]
    );

    let small = charge(&api, "v1/tier", Some(1000)).await;
    assert_eq!(small.amount, "10000000");
    assert_eq!(
        splits(&small),
        vec![(AFFILIATE_A.to_string(), "1000000".to_string())]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selected_variant_tier_carries_its_own_splits() {
    let api = tier_split_spec();
    let premium = charge(&api, "v1/models/premium:generate", None).await;
    assert_eq!(premium.amount, "1000000000");
    assert_eq!(
        splits(&premium),
        vec![(AFFILIATE_B.to_string(), "200000000".to_string())]
    );
    let cheap = charge(&api, "v1/models/cheap:generate", None).await;
    assert_eq!(
        splits(&cheap),
        vec![(AFFILIATE_A.to_string(), "1000000".to_string())]
    );
}

// ── Body-size tiers without Content-Length (SOLA1-82) ──────────────────────

fn upload_api() -> ApiSpec {
    spec(&std::fs::read_to_string("tests/fixtures/test-paywall.yml").unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_body_size_is_charged_at_the_large_tier() {
    let api = upload_api();
    assert_eq!(charge_amount(&api, "v1/upload", None).await, "100000000");
    assert_eq!(
        charge_amount(&api, "v1/upload", Some(1_048_577)).await,
        "100000000"
    );
    assert_eq!(
        charge_amount(&api, "v1/upload", Some(1_048_576)).await,
        "10000000"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chunked_request_through_middleware_is_quoted_at_the_large_tier() {
    use axum::{Router, middleware, routing::any};

    let state = State {
        apis: Arc::new(vec![upload_api()]),
        mpp: sol_mpp(),
    };
    let app = Router::new()
        .fallback(any(|| async { "protected" }))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            pay_core::server::payment::payment_middleware::<State>,
        ))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Send only the chunked request head: the gate must quote without reading
    // the body, so its 402 never races the upload.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"POST /v1/upload HTTP/1.1\r\nhost: testapi.localhost\r\n\
              transfer-encoding: chunked\r\nconnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let raw = String::from_utf8_lossy(&raw);
    assert!(raw.starts_with("HTTP/1.1 402"), "{raw}");
    let header = raw
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("www-authenticate")
                .then(|| value.trim())
        })
        .unwrap();
    let charge: ChargeRequest = parse_www_authenticate(header)
        .unwrap()
        .request
        .decode()
        .unwrap();
    assert_eq!(charge.amount, "100000000");
    server.abort();
}

// ── Multi-dimension fixed charges (SOLA1-155) ──────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_charge_covers_every_request_dimension() {
    let mut api = upload_api();
    let endpoint = api
        .endpoints
        .iter_mut()
        .find(|endpoint| endpoint.path == "v1/simple/echo")
        .unwrap();
    let metering = endpoint.metering.as_mut().unwrap();
    metering.schemes = Some(vec![pay_types::metering::Scheme::MppCharge]);
    let mut second = metering.dimensions[0].clone();
    second.tiers[0].price_usd = 0.5;
    metering.dimensions.push(second);

    // $0.001 + $0.500 in SOL base units.
    assert_eq!(
        charge_amount(&api, "v1/simple/echo", Some(2)).await,
        "501000000"
    );
}

// ── Aggregate token pricing on fixed schemes (SOLA1-210) ───────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_priced_endpoint_is_never_charged_per_call() {
    let api = spec(
        r#"
name: token-priced
subdomain: token-priced
title: Token priced
description: Token priced endpoint
category: ai_ml
version: v1
routing:
  type: respond
endpoints:
  - method: POST
    path: v1/generate
    metering:
      dimensions:
        - direction: input
          unit: tokens
          scale: 1000000
          tiers: [{price_usd: 1.0}]
"#,
    );
    assert!(!pay_types::metering::validate_api_spec(&api).is_empty());

    let challenge = challenge(&api, "v1/generate", Some(2)).await;
    assert!(
        challenge.charge.is_none(),
        "no per-call charge may be offered"
    );
    assert_eq!(challenge.status, StatusCode::INTERNAL_SERVER_ERROR);
}
