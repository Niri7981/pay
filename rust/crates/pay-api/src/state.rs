use std::collections::HashMap;
use std::time::Duration;

use pay_api_core::ata::TOKEN_2022_PROGRAM_ID;
use pay_api_core::{CreditProgram, Error, RpcClient, Stablecoin};
use pay_api_types::Network;

use pay_kit::mpp::server::{self, ConfidentialHandle, ConfidentialWorkerConfig};

use crate::config::{
    ChannelsConfig, Config, FeePayerConfig, MoonpayConfig, NetworkConfig, SendConfig,
    SubscriptionsConfig,
};
use crate::endpoints::redeem::RedemptionState;
use crate::endpoints::transfer_batches::PushState;
use crate::store::StoreBackend;

/// Application state — read-only after construction, so a plain `Arc<AppState>`
/// is enough; no `RwLock` is needed.
pub struct AppState {
    pub rpc: RpcClient,
    pub networks: HashMap<Network, NetworkConfig>,
    pub stablecoins: Vec<Stablecoin>,
    pub credit_programs: Vec<CreditProgram>,
    pub moonpay: MoonpayConfig,
    pub send: SendConfig,
    pub subscriptions: SubscriptionsConfig,
    /// Effective HMAC secret for the subscriptions handler — already
    /// resolved against the `send` fallback at boot.
    pub subscriptions_challenge_binding_secret: Option<String>,
    /// Effective fee-payer for `/v1/subscriptions/cancel`, resolved at
    /// boot from `subscriptions.fee_payer` and falling back to
    /// `send.fee_payer` so a single deployment shares one KMS-backed
    /// signer across both endpoints.
    pub subscriptions_fee_payer: FeePayerConfig,
    pub channels: ChannelsConfig,
    pub channels_challenge_binding_secret: Option<String>,
    pub channels_fee_payer: FeePayerConfig,
    /// Resolved `/v1/redeem` settings. `None` when `redemption.enabled`
    /// is false; the handler returns 503 in that case.
    pub redemption: Option<RedemptionState>,
    /// Handles to confidential-settlement worker run-loops, keyed by the
    /// request network they settle against. Empty when confidential settlement
    /// can't be configured (send disabled, no fee-payer signer, no network, or
    /// no Token-2022 coin).
    pub confidential: HashMap<Network, ConfidentialHandle>,
    /// Whether confidential settlement enforces the challenged amount. False
    /// only under the explicit `send.accept_unverified_confidential_amount`.
    pub confidential_amount_verified: bool,
    /// Resolved `POST /api/v1/transfer-batches` state. `None` when
    /// `push.enabled` is false. The endpoint is deliberately not routed until
    /// caller authentication and fee reimbursement collection are available.
    #[allow(dead_code)]
    pub push: Option<PushState>,
    /// Replay store shared by every per-request charge `Mpp` across replicas.
    pub charge_store: std::sync::Arc<dyn pay_kit::mpp::store::Store>,
    /// One in-flight cancellation per subscription PDA across replicas.
    pub cancel_reservations: crate::store::Reservations,
}

impl AppState {
    pub async fn new(config: &Config) -> Result<Self, Error> {
        // Resolve every spec at boot so per-request work is just lookups.
        let stablecoins = config
            .stablecoins
            .iter()
            .map(|s| s.resolve())
            .collect::<Result<Vec<_>, _>>()?;
        let credit_programs = config
            .credit_programs
            .iter()
            .map(|program| program.resolve())
            .collect::<Result<Vec<_>, _>>()?;

        let subscriptions_challenge_binding_secret = config
            .subscriptions_challenge_binding_secret()
            .map(str::to_string);
        let subscriptions_fee_payer = config.effective_subscriptions_fee_payer();
        let channels_challenge_binding_secret = config
            .channels_challenge_binding_secret()
            .map(str::to_string);
        let channels_fee_payer = config.effective_channels_fee_payer();

        let redemption = if config.redemption.enabled {
            Some(RedemptionState::from_config(&config.redemption)?)
        } else {
            None
        };

        let store_backend = match config.mpp_store_url() {
            Some(url) => Some(StoreBackend::connect(url).await?),
            None => None,
        };
        let confidential =
            build_confidential_workers(config, &stablecoins, store_backend.as_ref()).await?;
        let charges_enabled =
            config.send.enabled || config.subscriptions.enabled || config.channels.enabled;
        let (charge_store, cancel_reservations) = match &store_backend {
            Some(backend) => (
                backend.namespace("charge"),
                backend.reservations("subscription-cancel"),
            ),
            None if charges_enabled => {
                return Err(Error::SendNotConfigured(
                    "mpp_store_url is required while send, subscriptions or channels is enabled"
                        .into(),
                ));
            }
            // No charge endpoint can run, so nothing reads these.
            None => (
                StoreBackend::Memory.namespace("charge"),
                StoreBackend::Memory.reservations("subscription-cancel"),
            ),
        };

        let push = if config.push.enabled {
            Some(PushState::from_config(&config.push).await?)
        } else {
            None
        };

        Ok(Self {
            rpc: RpcClient::new(Duration::from_millis(config.rpc_timeout_ms))?,
            networks: config.networks.clone(),
            stablecoins,
            credit_programs,
            moonpay: config.moonpay.clone(),
            send: config.send.clone(),
            subscriptions: config.subscriptions.clone(),
            subscriptions_challenge_binding_secret,
            subscriptions_fee_payer,
            channels: config.channels.clone(),
            channels_challenge_binding_secret,
            channels_fee_payer,
            redemption,
            confidential,
            confidential_amount_verified: !config.send.accept_unverified_confidential_amount,
            push,
            charge_store,
            cancel_reservations,
        })
    }

    pub fn rpc_url_for(&self, network: Network) -> Result<&str, Error> {
        self.networks
            .get(&network)
            .map(|n| n.rpc_url.as_str())
            .ok_or_else(|| Error::NetworkNotConfigured(network.as_str().into()))
    }
}

/// Spin up confidential-settlement workers at boot, one per configured network.
/// Returns an empty map (logged) when any prerequisite is missing —
/// confidential settlement is then unavailable, but the rest of the API runs
/// normally. An invalid auditor keypair fails boot.
async fn build_confidential_workers(
    config: &Config,
    stablecoins: &[Stablecoin],
    store: Option<&StoreBackend>,
) -> Result<HashMap<Network, ConfidentialHandle>, Error> {
    if !config.send.enabled {
        return Ok(HashMap::new());
    }
    let Some(store) = store else {
        tracing::warn!("confidential worker disabled: no mpp_store_url");
        return Ok(HashMap::new());
    };
    let auditor = config
        .send
        .confidential_auditor_bytes()
        .map_err(Error::SendNotConfigured)?;
    if auditor.is_none() && !config.send.accept_unverified_confidential_amount {
        tracing::warn!(
            "confidential sends are refused: set send.confidential_auditor to enforce amounts"
        );
    }
    // The sweep Mpp needs any Token-2022 coin (the sweep is currency-agnostic).
    let Some(coin) = stablecoins
        .iter()
        .find(|c| c.token_program == TOKEN_2022_PROGRAM_ID)
    else {
        tracing::info!("confidential worker disabled: no Token-2022 stablecoin configured");
        return Ok(HashMap::new());
    };
    if let Some(auditor) = auditor {
        validate_auditor(config, coin, auditor)?;
    }
    if config.networks.is_empty() {
        tracing::info!("confidential worker disabled: no network configured");
        return Ok(HashMap::new());
    }
    let signer = match crate::signer::build_fee_payer_signer(
        &config.send.fee_payer,
        "send.fee_payer.key_name is missing",
        "send.fee_payer.pubkey is missing",
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "confidential worker disabled: no fee-payer signer");
            return Ok(HashMap::new());
        }
    };
    let Some(fee_payer_pubkey) = config.send.fee_payer.pubkey.clone() else {
        tracing::warn!("confidential worker disabled: no fee-payer pubkey");
        return Ok(HashMap::new());
    };

    Ok(spawn_confidential_workers(
        config,
        coin,
        signer,
        fee_payer_pubkey,
        store,
        auditor,
    ))
}

/// Reject an auditor that isn't a valid ElGamal keypair at boot instead of
/// letting every settlement fail.
fn validate_auditor(config: &Config, coin: &Stablecoin, auditor: [u8; 64]) -> Result<(), Error> {
    server::Mpp::new(server::Config {
        recipient: coin.mint.to_string(),
        currency: coin.mint.to_string(),
        decimals: coin.decimals,
        network: "mainnet".to_string(),
        challenge_binding_secret: config.send.mpp_challenge_binding_secret.clone(),
        realm: Some(config.send.realm.clone()),
        store: Some(std::sync::Arc::new(pay_kit::mpp::store::MemoryStore::new())),
        confidential_auditor: Some(auditor),
        html: false,
        ..Default::default()
    })
    .map(|_| ())
    .map_err(|e| Error::SendNotConfigured(format!("send.confidential_auditor: {e}")))
}

fn spawn_confidential_workers(
    config: &Config,
    coin: &Stablecoin,
    signer: std::sync::Arc<dyn pay_kit::mpp::solana_keychain::TransactionSigner>,
    fee_payer_pubkey: String,
    store: &StoreBackend,
    auditor: Option<[u8; 64]>,
) -> HashMap<Network, ConfidentialHandle> {
    let mut handles = HashMap::with_capacity(config.networks.len());
    for (network, net_cfg) in &config.networks {
        let handle = server::spawn_confidential_worker_with_tx_version(
            worker_config(
                config,
                *network,
                &net_cfg.rpc_url,
                coin,
                &fee_payer_pubkey,
                store,
                auditor,
            ),
            signer.clone(),
            pay_kit::core::tx::TxVersion::V1,
        );
        handles.insert(*network, handle);
    }
    handles
}

fn worker_config(
    config: &Config,
    network: Network,
    rpc_url: &str,
    coin: &Stablecoin,
    fee_payer_pubkey: &str,
    store: &StoreBackend,
    auditor: Option<[u8; 64]>,
) -> ConfidentialWorkerConfig {
    let cluster = match network {
        Network::Mainnet => "mainnet",
        Network::Sandbox => "localnet",
    };
    // pay-kit validates the canonical MPP wire slug, so workers use the same
    // mapping as the /v1/send issue path.
    ConfidentialWorkerConfig {
        network: cluster.to_string(),
        rpc_url: rpc_url.to_string(),
        challenge_binding_secret: config.send.mpp_challenge_binding_secret.clone(),
        realm: config.send.realm.clone(),
        sweep_currency: coin.mint.to_string(),
        sweep_decimals: coin.decimals,
        fee_payer_pubkey: fee_payer_pubkey.to_string(),
        // /v1/send relays to an arbitrary user-chosen recipient (the gateway
        // is NOT the payee), so it cannot decrypt the recipient balance.
        recipient_signer: None,
        // The mint auditor key enforces the challenged amount; without it
        // settlement fails closed unless unverified amounts are opted in.
        auditor,
        accept_unverified_amount: config.send.accept_unverified_confidential_amount,
        // Shared by every replica so a challenge settles once.
        store: store.namespace(&format!("confidential:{cluster}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pay_kit::mpp::solana_keychain::SolanaSigner;

    /// A minimal config with send disabled (its default).
    fn minimal_config(send_enabled: bool) -> Config {
        serde_json::from_value(serde_json::json!({
            "networks": {},
            "stablecoins": [],
            "send": { "enabled": send_enabled },
        }))
        .unwrap()
    }

    fn token_2022_coin() -> Stablecoin {
        Stablecoin {
            symbol: "USDC22".into(),
            mint: solana_pubkey::Pubkey::new_unique(),
            token_program: TOKEN_2022_PROGRAM_ID,
            decimals: 6,
        }
    }

    #[tokio::test]
    async fn confidential_worker_disabled_when_send_disabled() {
        assert!(
            build_confidential_workers(&minimal_config(false), &[], Some(&StoreBackend::Memory))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn confidential_worker_disabled_without_token_2022_coin_or_store() {
        // Send enabled but no fee-payer signer / Token-2022 coin ⇒ no worker.
        assert!(
            build_confidential_workers(&minimal_config(true), &[], Some(&StoreBackend::Memory))
                .await
                .unwrap()
                .is_empty()
        );
        let coin = token_2022_coin();
        assert!(
            build_confidential_workers(&minimal_config(true), &[coin], None)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn invalid_confidential_auditor_fails_boot() {
        use base64::Engine;
        let mut config = minimal_config(true);
        config.send.mpp_challenge_binding_secret = Some("s".repeat(32));
        config.send.confidential_auditor =
            Some(base64::engine::general_purpose::STANDARD.encode([7u8; 64]));
        let coin = token_2022_coin();
        assert!(
            build_confidential_workers(&config, &[coin], Some(&StoreBackend::Memory))
                .await
                .is_err()
        );
    }

    #[test]
    fn worker_config_carries_the_amount_policy_and_shared_store() {
        let mut config = minimal_config(true);
        let coin = token_2022_coin();
        let fee_payer = solana_pubkey::Pubkey::new_unique().to_string();
        let enforced = worker_config(
            &config,
            Network::Mainnet,
            "http://rpc",
            &coin,
            &fee_payer,
            &StoreBackend::Memory,
            Some([1u8; 64]),
        );
        assert_eq!(enforced.auditor, Some([1u8; 64]));
        assert!(!enforced.accept_unverified_amount);
        assert!(enforced.recipient_signer.is_none());
        assert_eq!(enforced.network, "mainnet");

        config.send.accept_unverified_confidential_amount = true;
        let unverified = worker_config(
            &config,
            Network::Sandbox,
            "http://rpc",
            &coin,
            &fee_payer,
            &StoreBackend::Memory,
            None,
        );
        assert_eq!(unverified.auditor, None);
        assert!(unverified.accept_unverified_amount);
        assert_eq!(unverified.network, "localnet");
    }

    #[tokio::test]
    async fn confidential_workers_are_created_per_configured_network() {
        let keypair = solana_keypair::Keypair::new();
        let keypair_bytes = serde_json::to_string(&keypair.to_bytes().to_vec()).unwrap();
        let signer = std::sync::Arc::new(
            pay_kit::mpp::solana_keychain::MemorySigner::from_private_key_string(&keypair_bytes)
                .unwrap(),
        );
        let coin = token_2022_coin();
        let config: Config = serde_json::from_value(serde_json::json!({
            "networks": {
                "mainnet": {"rpc_url": "http://mainnet.invalid"},
                "sandbox": {"rpc_url": "http://sandbox.invalid"}
            },
            "stablecoins": [],
            "send": {"enabled": true}
        }))
        .unwrap();

        let handles = spawn_confidential_workers(
            &config,
            &coin,
            signer.clone(),
            signer.pubkey().to_string(),
            &StoreBackend::Memory,
            None,
        );

        assert_eq!(handles.len(), 2);
        assert!(handles.contains_key(&Network::Mainnet));
        assert!(handles.contains_key(&Network::Sandbox));
    }
}
