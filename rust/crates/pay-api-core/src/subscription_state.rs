//! Decode the on-chain `SubscriptionDelegation` (and its parent `Plan`)
//! published by the canonical subscriptions program or its legacy
//! multi-delegator deployment, which shares the account layout.
//!
//! The layouts are the codama-generated borsh structs from pay-kit
//! (`subscriptions-client`). Borsh leaves trailing bytes unread, so every
//! account is also checked for its exact length, account discriminator and
//! version before it is trusted, and the delegation must sit at the PDA
//! derived from its own plan and subscriber.

use std::str::FromStr;

use borsh::BorshDeserialize;
use pay_kit::generated::subscriptions::accounts::{Plan, SubscriptionDelegation};
use solana_pubkey::Pubkey;
use tracing::debug;

use crate::error::{Error, Result};
use crate::receipt::{MULTI_DELEGATOR_PROGRAM, SUBSCRIPTIONS_PROGRAM};
use crate::rpc::RpcClient;

/// `AccountDiscriminator::Plan`.
const PLAN_DISCRIMINATOR: u8 = 1;
/// `AccountDiscriminator::SubscriptionDelegation`.
const SUBSCRIPTION_DELEGATION_DISCRIMINATOR: u8 = 4;
const SUBSCRIPTION_DELEGATION_VERSION: u8 = 1;
const SUBSCRIPTION_DELEGATION_LEN: usize = 155;
const PLAN_LEN: usize = 491;
const SUBSCRIPTION_SEED: &[u8] = b"subscription";

#[derive(Debug, Clone)]
pub struct SubscriptionDelegationState {
    pub address: String,
    /// Header `delegator` — the subscriber wallet.
    pub subscriber: Pubkey,
    /// Header `delegatee` — the plan the subscription belongs to.
    pub plan: Pubkey,
    /// The plan's mint, when the plan account is still live.
    pub mint: Option<Pubkey>,
    pub amount_per_period: u64,
    pub period_hours: u64,
    pub current_period_start_ts: i64,
    pub expires_at_ts: i64,
}

/// Fetch and validate the subscription delegation an instruction of
/// `program_id` names at `subscription` for `plan`. The account must be owned
/// by that same program (canonical or legacy deployment) and sit at the PDA
/// derived under it. Returns `Ok(None)` when the account is missing or is not
/// a valid delegation for that plan.
pub async fn fetch_subscription_delegation(
    rpc: &RpcClient,
    rpc_url: &str,
    program_id: &str,
    subscription: &str,
    plan: &str,
) -> Result<Option<SubscriptionDelegationState>> {
    if program_id != SUBSCRIPTIONS_PROGRAM && program_id != MULTI_DELEGATOR_PROGRAM {
        return Ok(None);
    }
    let program = Pubkey::from_str(program_id).map_err(|_| Error::RpcMalformed)?;
    let (Ok(subscription_key), Ok(plan_key)) =
        (Pubkey::from_str(subscription), Pubkey::from_str(plan))
    else {
        return Ok(None);
    };
    let accounts = rpc
        .get_multiple_accounts_with_owner(rpc_url, &[subscription.to_string(), plan.to_string()])
        .await?;
    let mut accounts = accounts.into_iter();
    let Some(Some(delegation)) = accounts.next() else {
        return Ok(None);
    };
    if delegation.owner != program_id {
        return Ok(None);
    }
    let mut state = match decode_subscription_delegation(
        &program,
        &subscription_key,
        &plan_key,
        &delegation.data,
    ) {
        Ok(state) => state,
        Err(_) => {
            debug!(
                address = %subscription,
                bytes = delegation.data.len(),
                "account did not validate as a SubscriptionDelegation"
            );
            return Ok(None);
        }
    };
    if let Some(Some(plan_account)) = accounts.next()
        && plan_account.owner == program_id
    {
        state.mint = decode_plan_mint(&plan_account.data);
    }
    Ok(Some(state))
}

fn decode_subscription_delegation(
    program: &Pubkey,
    address: &Pubkey,
    plan: &Pubkey,
    data: &[u8],
) -> Result<SubscriptionDelegationState> {
    if data.len() != SUBSCRIPTION_DELEGATION_LEN
        || data[0] != SUBSCRIPTION_DELEGATION_DISCRIMINATOR
        || data[1] != SUBSCRIPTION_DELEGATION_VERSION
    {
        return Err(Error::RpcMalformed);
    }
    let decoded =
        SubscriptionDelegation::deserialize(&mut &data[..]).map_err(|_| Error::RpcMalformed)?;
    let subscriber = Pubkey::new_from_array(decoded.header.delegator.to_bytes());
    let delegatee = Pubkey::new_from_array(decoded.header.delegatee.to_bytes());
    if delegatee != *plan {
        return Err(Error::RpcMalformed);
    }
    let (expected, _) = Pubkey::find_program_address(
        &[SUBSCRIPTION_SEED, plan.as_ref(), subscriber.as_ref()],
        program,
    );
    if expected != *address {
        return Err(Error::RpcMalformed);
    }
    Ok(SubscriptionDelegationState {
        address: address.to_string(),
        subscriber,
        plan: delegatee,
        mint: None,
        amount_per_period: decoded.terms.amount,
        period_hours: decoded.terms.period_hours,
        current_period_start_ts: decoded.current_period_start_ts,
        expires_at_ts: decoded.expires_at_ts,
    })
}

fn decode_plan_mint(data: &[u8]) -> Option<Pubkey> {
    if data.len() != PLAN_LEN || data[0] != PLAN_DISCRIMINATOR {
        return None;
    }
    let plan = Plan::deserialize(&mut &data[..]).ok()?;
    Some(Pubkey::new_from_array(plan.data.mint.to_bytes()))
}

/// Format a `period_hours` value as a friendly label.
pub fn period_label(period_hours: u64) -> String {
    if period_hours.is_multiple_of(24 * 7) {
        let weeks = period_hours / (24 * 7);
        return match weeks {
            1 => "Every week".to_string(),
            n => format!("Every {n} weeks"),
        };
    }
    if period_hours.is_multiple_of(24) {
        let days = period_hours / 24;
        return match days {
            1 => "Every day".to_string(),
            n => format!("Every {n} days"),
        };
    }
    format!("Every {period_hours} h")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use borsh::BorshSerialize;
    use pay_kit::generated::subscriptions::accounts::RecurringDelegation;
    use pay_kit::generated::subscriptions::types::{Header, PlanData, PlanTerms};
    use solana_address::Address;

    pub(crate) fn subscriptions_program() -> Pubkey {
        Pubkey::from_str(SUBSCRIPTIONS_PROGRAM).unwrap()
    }

    pub(crate) fn subscription_pda(program: &Pubkey, plan: &Pubkey, subscriber: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(
            &[SUBSCRIPTION_SEED, plan.as_ref(), subscriber.as_ref()],
            program,
        )
        .0
    }

    pub(crate) fn subscription_delegation_bytes(
        subscriber: &Pubkey,
        plan: &Pubkey,
        amount: u64,
        period_hours: u64,
        start: i64,
        expires: i64,
    ) -> Vec<u8> {
        let account = SubscriptionDelegation {
            header: Header {
                discriminator: SUBSCRIPTION_DELEGATION_DISCRIMINATOR,
                version: SUBSCRIPTION_DELEGATION_VERSION,
                bump: 255,
                delegator: Address::new_from_array(subscriber.to_bytes()),
                delegatee: Address::new_from_array(plan.to_bytes()),
                payer: Address::new_from_array([9u8; 32]),
                init_id: 1,
            },
            terms: PlanTerms {
                amount,
                period_hours,
                created_at: 1_600_000_000,
            },
            amount_pulled_in_period: 0,
            current_period_start_ts: start,
            expires_at_ts: expires,
        };
        let mut bytes = Vec::new();
        account.serialize(&mut bytes).unwrap();
        bytes
    }

    pub(crate) fn plan_bytes(owner: &Pubkey, mint: &Pubkey) -> Vec<u8> {
        let plan = Plan {
            discriminator: PLAN_DISCRIMINATOR,
            owner: Address::new_from_array(owner.to_bytes()),
            bump: 254,
            status: 0,
            data: PlanData {
                plan_id: 1,
                mint: Address::new_from_array(mint.to_bytes()),
                terms: PlanTerms {
                    amount: 10_000_000,
                    period_hours: 720,
                    created_at: 1_600_000_000,
                },
                end_ts: 0,
                destinations: [Address::new_from_array([6u8; 32]); 4],
                pullers: [Address::new_from_array([6u8; 32]); 4],
                metadata_uri: [6u8; 128],
            },
        };
        let mut bytes = Vec::new();
        plan.serialize(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn decodes_a_valid_subscription_delegation() {
        let program = subscriptions_program();
        let subscriber = Pubkey::new_unique();
        let plan = Pubkey::new_unique();
        let address = subscription_pda(&program, &plan, &subscriber);
        let data = subscription_delegation_bytes(
            &subscriber,
            &plan,
            10_000_000,
            720,
            1_700_000_000,
            1_800_000_000,
        );
        assert_eq!(data.len(), SUBSCRIPTION_DELEGATION_LEN);
        let decoded = decode_subscription_delegation(&program, &address, &plan, &data).unwrap();
        assert_eq!(decoded.subscriber, subscriber);
        assert_eq!(decoded.plan, plan);
        assert_eq!(decoded.amount_per_period, 10_000_000);
        assert_eq!(decoded.period_hours, 720);
        assert_eq!(decoded.current_period_start_ts, 1_700_000_000);
        assert_eq!(decoded.expires_at_ts, 1_800_000_000);
    }

    #[test]
    fn rejects_a_plan_account_decoded_as_a_delegation() {
        let program = subscriptions_program();
        let plan = Pubkey::new_unique();
        let data = plan_bytes(&Pubkey::new_unique(), &Pubkey::new_unique());
        assert_eq!(data.len(), PLAN_LEN);
        // The old decoder accepted this prefix as a RecurringDelegation.
        assert!(RecurringDelegation::deserialize(&mut data.as_slice()).is_ok());
        assert!(decode_subscription_delegation(&program, &plan, &plan, &data).is_err());
        assert!(
            decode_subscription_delegation(
                &program,
                &plan,
                &plan,
                &data[..SUBSCRIPTION_DELEGATION_LEN]
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_wrong_length_discriminator_version_plan_or_address() {
        let program = subscriptions_program();
        let subscriber = Pubkey::new_unique();
        let plan = Pubkey::new_unique();
        let address = subscription_pda(&program, &plan, &subscriber);
        let data = subscription_delegation_bytes(&subscriber, &plan, 1, 24, 1, 2);

        let mut longer = data.clone();
        longer.push(0);
        assert!(decode_subscription_delegation(&program, &address, &plan, &longer).is_err());
        assert!(
            decode_subscription_delegation(&program, &address, &plan, &data[..data.len() - 1])
                .is_err()
        );
        for (index, value) in [(0, 3u8), (1, 0u8)] {
            let mut bad = data.clone();
            bad[index] = value;
            assert!(decode_subscription_delegation(&program, &address, &plan, &bad).is_err());
        }
        let other_plan = Pubkey::new_unique();
        assert!(decode_subscription_delegation(&program, &address, &other_plan, &data).is_err());
        assert!(
            decode_subscription_delegation(&program, &Pubkey::new_unique(), &plan, &data).is_err()
        );
    }

    #[test]
    fn decodes_plan_mint_only_from_a_plan_account() {
        let mint = Pubkey::new_unique();
        assert_eq!(
            decode_plan_mint(&plan_bytes(&Pubkey::new_unique(), &mint)),
            Some(mint)
        );
        let delegation =
            subscription_delegation_bytes(&Pubkey::new_unique(), &Pubkey::new_unique(), 1, 1, 1, 1);
        assert_eq!(decode_plan_mint(&delegation), None);
    }

    #[test]
    fn period_label_handles_days_weeks_and_hours() {
        assert_eq!(period_label(24), "Every day");
        assert_eq!(period_label(24 * 30), "Every 30 days");
        assert_eq!(period_label(168), "Every week");
        assert_eq!(period_label(168 * 4), "Every 4 weeks");
        assert_eq!(period_label(6), "Every 6 h");
    }
}
