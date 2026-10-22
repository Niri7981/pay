//! Whether a signed Solana transaction can still land.
//!
//! Replacing or releasing a recorded payout is only safe once its signed
//! bytes can never land. That needs two observations in a fixed order: the
//! finalized tip first, proving the blockhash expired, then the signature's
//! status from chain state at least as recent as that tip. Read the other way
//! round, a transaction can land between the two lookups and still read as
//! absent. [`confirm_not_landed`] is the only way to get a [`Replaceable`].

use std::future::Future;

/// The finalized tip a lookup is gated on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTip {
    pub slot: u64,
    pub block_height: u64,
}

/// One signature's status as the cluster reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Not known to the cluster, searching transaction history.
    Absent,
    /// Executed with an error, at the given commitment.
    Failed { finalized: bool },
    /// Executed without error, but not yet confirmed.
    Processed,
    /// Confirmed or finalized without error.
    Confirmed,
}

/// Statuses in request order, and the slot of the state they reflect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureStatuses {
    pub context_slot: u64,
    pub statuses: Vec<SignatureStatus>,
}

/// The chain reads [`confirm_not_landed`] needs.
pub trait ChainState {
    type Error;

    /// Slot and block height at `finalized` commitment.
    fn finalized_tip(&self) -> impl Future<Output = Result<ChainTip, Self::Error>> + Send;

    /// `getSignatureStatuses` with `searchTransactionHistory`.
    fn signature_statuses(
        &self,
        signatures: &[String],
    ) -> impl Future<Output = Result<SignatureStatuses, Self::Error>> + Send;
}

/// A recorded payout to check: its signature and, when known, the last block
/// height its blockhash is valid at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedPayout {
    pub signature: String,
    pub last_valid_block_height: Option<u64>,
}

/// Proof that a recorded payout can never land, so it may be replaced or its
/// claim released. Only [`confirm_not_landed`] constructs one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replaceable {
    reason: ReplaceReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceReason {
    /// It executed with an error, final at `finalized` or past expiry.
    Failed,
    /// Its blockhash expired at finalized commitment and it never landed.
    Expired,
}

impl Replaceable {
    pub fn reason(&self) -> ReplaceReason {
        self.reason
    }
}

/// Where a recorded payout stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Landing {
    Confirmed,
    /// Seen, or still inside its validity window: it may yet land.
    MayLand,
    /// The status could not be established against recent enough state.
    Unknown,
    Replaceable(Replaceable),
}

/// Classify `payouts`, reading the finalized tip before their statuses.
pub async fn confirm_not_landed<C: ChainState>(
    chain: &C,
    payouts: &[RecordedPayout],
) -> Result<Vec<Landing>, C::Error> {
    if payouts.is_empty() {
        return Ok(Vec::new());
    }
    let tip = chain.finalized_tip().await?;
    let signatures = payouts
        .iter()
        .map(|payout| payout.signature.clone())
        .collect::<Vec<_>>();
    let observed = chain.signature_statuses(&signatures).await?;
    if observed.context_slot < tip.slot || observed.statuses.len() != payouts.len() {
        return Ok(vec![Landing::Unknown; payouts.len()]);
    }
    Ok(payouts
        .iter()
        .zip(observed.statuses)
        .map(|(payout, status)| classify(tip, payout, status))
        .collect())
}

fn classify(tip: ChainTip, payout: &RecordedPayout, status: SignatureStatus) -> Landing {
    let expired = payout
        .last_valid_block_height
        .is_some_and(|last_valid| tip.block_height > last_valid);
    let replaceable = |reason| Landing::Replaceable(Replaceable { reason });
    match status {
        SignatureStatus::Confirmed => Landing::Confirmed,
        SignatureStatus::Failed { finalized } if finalized || expired => {
            replaceable(ReplaceReason::Failed)
        }
        SignatureStatus::Absent if expired => replaceable(ReplaceReason::Expired),
        SignatureStatus::Failed { .. } | SignatureStatus::Processed | SignatureStatus::Absent => {
            Landing::MayLand
        }
    }
}

/// Classify one `getSignatureStatuses` entry.
pub fn signature_status_from_rpc(entry: &serde_json::Value) -> SignatureStatus {
    if entry.is_null() {
        return SignatureStatus::Absent;
    }
    let commitment = entry
        .get("confirmationStatus")
        .and_then(serde_json::Value::as_str);
    if entry.get("err").is_some_and(|err| !err.is_null()) {
        return SignatureStatus::Failed {
            finalized: commitment == Some("finalized"),
        };
    }
    match commitment {
        Some("confirmed" | "finalized") => SignatureStatus::Confirmed,
        _ => SignatureStatus::Processed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A cluster on which a transaction lands between two reads.
    struct Chain {
        log: Mutex<Vec<&'static str>>,
        tip: ChainTip,
        context_slot: u64,
        statuses: Vec<SignatureStatus>,
    }

    impl Chain {
        fn new(block_height: u64, statuses: Vec<SignatureStatus>) -> Self {
            Self {
                log: Mutex::default(),
                tip: ChainTip {
                    slot: 1_000,
                    block_height,
                },
                context_slot: 1_010,
                statuses,
            }
        }
    }

    impl ChainState for Chain {
        type Error = ();

        async fn finalized_tip(&self) -> Result<ChainTip, ()> {
            self.log.lock().unwrap().push("tip");
            Ok(self.tip)
        }

        async fn signature_statuses(&self, _: &[String]) -> Result<SignatureStatuses, ()> {
            self.log.lock().unwrap().push("statuses");
            Ok(SignatureStatuses {
                context_slot: self.context_slot,
                statuses: self.statuses.clone(),
            })
        }
    }

    fn payout(last_valid: Option<u64>) -> RecordedPayout {
        RecordedPayout {
            signature: "sig".to_string(),
            last_valid_block_height: last_valid,
        }
    }

    fn check(chain: &Chain, payouts: &[RecordedPayout]) -> Vec<Landing> {
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        match std::pin::pin!(confirm_not_landed(chain, payouts)).poll(&mut context) {
            std::task::Poll::Ready(landings) => landings.unwrap(),
            std::task::Poll::Pending => unreachable!("fixture never pends"),
        }
    }

    fn expired() -> Landing {
        Landing::Replaceable(Replaceable {
            reason: ReplaceReason::Expired,
        })
    }

    #[test]
    fn the_tip_is_read_before_the_statuses() {
        let chain = Chain::new(101, vec![SignatureStatus::Absent]);
        assert_eq!(check(&chain, &[payout(Some(100))]), vec![expired()]);
        assert_eq!(*chain.log.lock().unwrap(), vec!["tip", "statuses"]);
    }

    #[test]
    fn statuses_older_than_the_tip_prove_nothing() {
        let mut chain = Chain::new(101, vec![SignatureStatus::Absent]);
        chain.context_slot = chain.tip.slot - 1;
        assert_eq!(check(&chain, &[payout(Some(100))]), vec![Landing::Unknown]);
        // A response for the wrong number of signatures proves nothing either.
        let chain = Chain::new(101, vec![]);
        assert_eq!(check(&chain, &[payout(Some(100))]), vec![Landing::Unknown]);
    }

    #[test]
    fn only_an_expired_absent_or_final_failure_is_replaceable() {
        let failed = |finalized| SignatureStatus::Failed { finalized };
        let cases = [
            (SignatureStatus::Absent, Some(100), expired()),
            (SignatureStatus::Absent, Some(101), Landing::MayLand),
            (SignatureStatus::Absent, None, Landing::MayLand),
            (SignatureStatus::Processed, Some(100), Landing::MayLand),
            (SignatureStatus::Confirmed, Some(100), Landing::Confirmed),
            (
                failed(true),
                Some(500),
                Landing::Replaceable(Replaceable {
                    reason: ReplaceReason::Failed,
                }),
            ),
            (failed(false), Some(500), Landing::MayLand),
            (
                failed(false),
                Some(100),
                Landing::Replaceable(Replaceable {
                    reason: ReplaceReason::Failed,
                }),
            ),
        ];
        for (status, last_valid, expected) in cases {
            let chain = Chain::new(101, vec![status]);
            assert_eq!(
                check(&chain, &[payout(last_valid)]),
                vec![expected],
                "{status:?} {last_valid:?}"
            );
        }
    }

    #[test]
    fn rpc_entries_classify() {
        use serde_json::json;
        assert_eq!(
            signature_status_from_rpc(&serde_json::Value::Null),
            SignatureStatus::Absent
        );
        assert_eq!(
            signature_status_from_rpc(&json!({"err": null, "confirmationStatus": "processed"})),
            SignatureStatus::Processed
        );
        assert_eq!(
            signature_status_from_rpc(&json!({"err": null, "confirmationStatus": "finalized"})),
            SignatureStatus::Confirmed
        );
        assert_eq!(
            signature_status_from_rpc(&json!({"err": {"x": 1}, "confirmationStatus": "confirmed"})),
            SignatureStatus::Failed { finalized: false }
        );
        assert_eq!(
            signature_status_from_rpc(&json!({"err": {"x": 1}, "confirmationStatus": "finalized"})),
            SignatureStatus::Failed { finalized: true }
        );
    }
}
