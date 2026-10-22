//! Real Pay middleware and SDK credentials against a local, canned Solana RPC.
//! No validator, external service, or funded wallet is used.
#![cfg(feature = "server")]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use axum::{Router, middleware, routing::any};
use pay_core::PaymentState;
use pay_kit::core::payment_channels_v2::ChannelHooks;
use pay_kit::mpp::server::{ChannelChargeConfig, Config, Mpp};
use pay_kit::solana_keychain::{MemorySigner, SolanaSigner};
use pay_types::metering::ApiSpec;
use solana_keypair::Keypair;

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

fn signer() -> MemorySigner {
    MemorySigner::from_bytes(&Keypair::new().to_bytes()).unwrap()
}

fn token_balances(encoded: &str, owner: &solana_pubkey::Pubkey, amount: &str) -> serde_json::Value {
    let transaction = pay_kit::mpp::program::payment_channels::decode_transaction(encoded).unwrap();
    let mint = pay_kit::mpp::mints::USDC_DEVNET.parse().unwrap();
    let token_program = pay_kit::mpp::programs::TOKEN_PROGRAM.parse().unwrap();
    let (ata, _) = pay_kit::mpp::program::payment_channels::find_associated_token_address(
        owner,
        &mint,
        &token_program,
    );
    let index = transaction
        .message
        .static_account_keys()
        .iter()
        .position(|key| *key == ata)
        .unwrap();
    serde_json::json!([{
        "accountIndex": index,
        "mint": mint.to_string(),
        "owner": owner.to_string(),
        "programId": token_program.to_string(),
        "uiTokenAmount": {"amount": amount, "decimals": 6, "uiAmount": null, "uiAmountString": "0"}
    }])
}

#[tokio::test]
async fn generic_payment_state_rejects_unavailable_credit_provider() {
    use pay_core::server::gate::{GateDecision, GateRequest, PaymentGate};

    let mut api: ApiSpec = serde_yml::from_str(include_str!("fixtures/test-paywall.yml")).unwrap();
    api.operator = Some(
        serde_json::from_value(serde_json::json!({"credit_providers": ["coinflow"]})).unwrap(),
    );
    let gate = PaymentGate::new(State {
        apis: Arc::new(vec![api]),
        mpp: Mpp::new(Config {
            recipient: signer().pubkey().to_string(),
            currency: pay_kit::mpp::mints::USDC_DEVNET.to_string(),
            network: "devnet".into(),
            challenge_binding_secret: Some("credit-provider-gate-test-secret".into()),
            realm: Some("test-realm".to_string()),
            store: Some(std::sync::Arc::new(pay_kit::mpp::store::MemoryStore::new())),
            ..Default::default()
        })
        .unwrap(),
    });
    for authorization in [None, Some("Payment invalid")] {
        let decision = gate
            .evaluate(&GateRequest {
                method: &axum::http::Method::POST,
                path: "v1/simple/echo",
                host: Some("testapi.localhost"),
                accept: None,
                authorization,
                content_length: None,
                query: None,
                x402_payment: None,
            })
            .await;
        let GateDecision::Respond(response) = decision else {
            panic!("unavailable provider must not advertise or authorize payments");
        };
        assert_eq!(
            response.status,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["error"], "payment_configuration_error");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channel_charge_handler_receipt_replay_and_preflight() {
    let operator = Arc::new(signer());
    let merchant = signer();
    let beneficiary = merchant.pubkey();
    let sends = Arc::new(AtomicUsize::new(0));
    let reject_preflight = Arc::new(AtomicBool::new(false));
    let rpc_sends = sends.clone();
    let rpc_reject = reject_preflight.clone();
    let submitted = Arc::new(Mutex::new(None::<String>));
    let rpc = Router::new().route(
        "/",
        axum::routing::post(move |body: axum::Json<serde_json::Value>| {
            let sends = rpc_sends.clone();
            let reject = rpc_reject.clone();
            let submitted = submitted.clone();
            async move {
                let result = match body["method"].as_str().unwrap() {
                    "simulateTransaction" => {
                        let encoded = body["params"][0].as_str().unwrap();
                        assert_eq!(body["params"][1]["sigVerify"], false);
                        serde_json::json!({
                            "context": {"slot": 43},
                            "value": {
                                "err": null, "logs": [], "unitsConsumed": 100000,
                                "preTokenBalances": token_balances(encoded, &beneficiary, "0"),
                                "postTokenBalances": token_balances(encoded, &beneficiary, "1000")
                            }
                        })
                    }
                    "sendTransaction" => {
                        sends.fetch_add(1, Ordering::SeqCst);
                        assert_ne!(body["params"][1]["skipPreflight"], true);
                        if reject.load(Ordering::SeqCst) {
                            return axum::Json(serde_json::json!({
                                "jsonrpc": "2.0", "id": body["id"],
                                "error": {
                                    "code": -32002,
                                    "message": "Transaction simulation failed: Blockhash not found",
                                    "data": { "err": "BlockhashNotFound", "logs": [] }
                                }
                            }));
                        }
                        let encoded = body["params"][0].as_str().unwrap();
                        *submitted.lock().unwrap() = Some(encoded.to_string());
                        let transaction =
                            pay_kit::mpp::program::payment_channels::decode_transaction(encoded)
                                .unwrap();
                        serde_json::json!(transaction.signatures[0].to_string())
                    }
                    "getTransaction" => {
                        let encoded = submitted.lock().unwrap().clone().unwrap();
                        serde_json::json!({
                            "slot": 43, "blockTime": null, "version": 0,
                            "transaction": [&encoded, "base64"],
                            "meta": {
                                "err": null, "fee": 5000,
                                "preBalances": [], "postBalances": [],
                                "preTokenBalances": token_balances(&encoded, &beneficiary, "0"),
                                "postTokenBalances": token_balances(&encoded, &beneficiary, "1000")
                            }
                        })
                    }
                    "getSignatureStatuses" => serde_json::json!({
                        "context": {"slot": 43},
                        "value": [{
                            "slot": 43, "confirmations": null, "err": null,
                            "confirmationStatus": "finalized", "status": {"Ok": null}
                        }]
                    }),
                    "getBalance" => serde_json::json!({
                        "context": {"slot": 43}, "value": 1_000_000_000_u64
                    }),
                    "getTokenAccountBalance" => serde_json::json!({
                        "context": {"slot": 43},
                        "value": {
                            "amount": "1000000", "decimals": 6,
                            "uiAmount": 1.0, "uiAmountString": "1"
                        }
                    }),
                    method => panic!("unexpected RPC method: {method}"),
                };
                axum::Json(serde_json::json!({
                    "jsonrpc": "2.0", "id": body["id"], "result": result
                }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_url = format!("http://{}", listener.local_addr().unwrap());
    let rpc_task = tokio::spawn(async move { axum::serve(listener, rpc).await.unwrap() });

    let cache = pay_kit::mpp::blockhash::BlockhashCache::new();
    cache.set(
        solana_hash::Hash::new_from_array([7; 32]).to_string(),
        1000,
        42,
    );
    let mpp = Mpp::new(Config {
        recipient: merchant.pubkey().to_string(),
        currency: pay_kit::mpp::mints::USDC_DEVNET.to_string(),
        decimals: 6,
        network: "devnet".into(),
        rpc_url: Some(rpc_url),
        challenge_binding_secret: Some("channel-charge-handler-test-secret".into()),
        fee_payer: true,
        fee_payer_signer: Some(operator.clone()),
        channel_charge: Some(ChannelChargeConfig {
            payee_signer: operator.clone(),
            hooks: ChannelHooks::default(),
        }),
        realm: Some("test-realm".to_string()),
        store: Some(std::sync::Arc::new(pay_kit::mpp::store::MemoryStore::new())),
        ..Default::default()
    })
    .unwrap()
    .with_blockhash_cache(cache.clone());
    let state = State {
        apis: Arc::new(vec![
            serde_yml::from_str(include_str!("fixtures/test-paywall.yml")).unwrap(),
        ]),
        mpp,
    };
    let app = Router::new()
        .fallback(any(|| async {
            axum::Json(serde_json::json!({"ok": true}))
        }))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            pay_core::server::payment::payment_middleware::<State>,
        ))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let app_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let request = |path: &str| {
        client
            .post(format!("{origin}{path}"))
            .header("host", "testapi.localhost")
            .body("{}")
    };
    let payer = signer();
    let voucher = signer();
    for (salt, reject) in [(1, false), (2, true)] {
        let response = request("/v1/simple/echo").send().await.unwrap();
        assert_eq!(response.status(), 402);
        let challenge = pay_kit::mpp::parse_www_authenticate(
            response.headers()["www-authenticate"].to_str().unwrap(),
        )
        .unwrap();
        let charge: pay_kit::mpp::ChargeRequest = challenge.request.decode().unwrap();
        assert_eq!(
            charge.method_details.as_ref().unwrap()["channelCharge"]["channelVersion"],
            2
        );
        let credential = pay_kit::mpp::client::build_channel_charge_credential(
            &payer,
            &voucher,
            &challenge,
            &ChannelHooks::default(),
            salt,
        )
        .await
        .unwrap();
        let authorization = pay_kit::mpp::format_authorization(&credential).unwrap();
        // Accept the original authenticated slot/hash after a cache refresh,
        // while still rebuilding the route's price and immutable hook policy.
        cache.set(
            solana_hash::Hash::new_from_array([8; 32]).to_string(),
            1001,
            43,
        );
        reject_preflight.store(reject, Ordering::SeqCst);
        let before = sends.load(Ordering::SeqCst);
        let response = request("/v1/simple/echo")
            .header("authorization", &authorization)
            .send()
            .await
            .unwrap();
        if reject {
            assert_eq!(
                response.status(),
                402,
                "preflight rejection must fail closed"
            );
            // Three bounded preflight attempts, never a fourth skip-preflight
            // fallback. Each send above asserts skipPreflight remains false.
            assert_eq!(sends.load(Ordering::SeqCst), before + 3);
        } else {
            let status = response.status();
            assert!(
                response.headers().contains_key("payment-receipt"),
                "missing receipt: {status}: {}",
                response.text().await.unwrap()
            );
            assert_eq!(status, 200);
            let response = request("/v1/simple/echo")
                .header("authorization", &authorization)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 402, "replayed charge must be rejected");
            let response = request("/v1/translate")
                .header("authorization", &authorization)
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                402,
                "charge cannot move to another route"
            );
            assert_eq!(sends.load(Ordering::SeqCst), before + 1);
        }
    }
    app_task.abort();
    rpc_task.abort();
    let _ = app_task.await;
    let _ = rpc_task.await;
}
