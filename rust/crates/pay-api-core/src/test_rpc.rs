//! In-process JSON-RPC stub for tests that exercise the async receipt path.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use serde_json::{Value, json};

#[derive(Default)]
pub(crate) struct Accounts {
    accounts: HashMap<String, (String, Vec<u8>)>,
    /// Every `getMultipleAccounts` request's address list.
    pub(crate) requests: Vec<Vec<String>>,
}

pub(crate) struct StubRpc {
    pub(crate) url: String,
    pub(crate) state: Arc<Mutex<Accounts>>,
}

impl StubRpc {
    pub(crate) async fn start() -> Self {
        let state = Arc::new(Mutex::new(Accounts::default()));
        let router = Router::new()
            .route("/", post(handle))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { url, state }
    }

    pub(crate) fn set_account(&self, address: &str, owner: &str, data: Vec<u8>) {
        self.state
            .lock()
            .unwrap()
            .accounts
            .insert(address.to_string(), (owner.to_string(), data));
    }

    pub(crate) fn requests(&self) -> Vec<Vec<String>> {
        self.state.lock().unwrap().requests.clone()
    }
}

async fn handle(State(state): State<Arc<Mutex<Accounts>>>, Json(body): Json<Value>) -> Json<Value> {
    let mut state = state.lock().unwrap();
    let result = match body["method"].as_str().unwrap_or_default() {
        "getMultipleAccounts" => {
            let addresses: Vec<String> = body["params"][0]
                .as_array()
                .unwrap()
                .iter()
                .map(|address| address.as_str().unwrap().to_string())
                .collect();
            let value: Vec<Value> = addresses
                .iter()
                .map(|address| match state.accounts.get(address) {
                    Some((owner, data)) => json!({
                        "owner": owner,
                        "lamports": 1,
                        "executable": false,
                        "data": [base64::engine::general_purpose::STANDARD.encode(data), "base64"],
                    }),
                    None => Value::Null,
                })
                .collect();
            state.requests.push(addresses);
            json!({ "context": { "slot": 1 }, "value": value })
        }
        other => {
            return Json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": { "code": -32601, "message": format!("unsupported {other}") }
            }));
        }
    };
    Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
}
