//! `pay plans publish` — derive on-chain `Plan` PDAs for every
//! subscription endpoint declared in a pay-demo.yaml.
//!
//! v0 surface: derives the deterministic Plan PDA per endpoint from the
//! operator's wallet + a stable seed and writes the address back into the
//! YAML in place. The on-chain `create_plan` broadcast is a TODO — pay-kit
//! exposes `INSTRUCTION_CREATE_PLAN = 7` but the SDK does not yet ship a
//! typed account-meta builder for it. Running with `--dry-run` is the
//! safe default until that lands; users with a manual publish script can
//! still benefit from the PDA derivation + write-back today.

use std::path::PathBuf;
use std::str::FromStr;

use owo_colors::OwoColorize;
use pay_core::server::subscription::PlanRoute;
use pay_kit::mpp::program::subscriptions::{default_program_id, find_plan_pda, plan_id_seed};
use solana_pubkey::Pubkey;

use super::atomic_write;

#[derive(clap::Args)]
pub struct PublishCommand {
    /// Path to the YAML spec containing `subscription:` endpoints.
    /// Defaults to `./pay-demo.yaml`.
    #[arg(long, default_value = "pay-demo.yaml")]
    pub spec: PathBuf,

    /// Explicit Plan owner pubkey (base58). When omitted, falls back to
    /// `operator.recipient` in the spec.
    #[arg(long)]
    pub owner: Option<String>,

    /// Print the derived Plan PDAs without modifying the YAML. The default
    /// for v0 because the on-chain broadcast path is not yet implemented.
    #[arg(long, default_value_t = true)]
    pub dry_run: bool,

    /// Write the derived Plan PDAs back into the YAML. Use this once the
    /// Plan accounts have been published on-chain through another tool —
    /// pay does not broadcast them in v0.
    #[arg(long)]
    pub write: bool,
}

impl PublishCommand {
    pub fn run(self) -> pay_core::Result<()> {
        let raw = std::fs::read_to_string(&self.spec).map_err(|e| {
            pay_core::Error::Config(format!("Failed to read {}: {e}", self.spec.display()))
        })?;
        let api: pay_types::metering::ApiSpec = serde_yml::from_str(&raw).map_err(|e| {
            pay_core::Error::Config(format!("Invalid YAML at {}: {e}", self.spec.display()))
        })?;

        let owner_str = if let Some(o) = self.owner.clone() {
            o
        } else {
            let mut operator = api.operator.clone().ok_or_else(|| {
                pay_core::Error::Config(
                    "spec has no `operator:` block; pass --owner <pubkey> instead".to_string(),
                )
            })?;
            operator
                .resolve_env_templates("operator")
                .map_err(pay_core::Error::Config)?;
            operator.recipient.clone().ok_or_else(|| {
                pay_core::Error::Config(
                    "spec has no `operator.recipient`; pass --owner <pubkey> to specify the Plan owner".to_string(),
                )
            })?
        };
        let owner = Pubkey::from_str(&owner_str).map_err(|e| {
            pay_core::Error::Config(format!("Plan owner is not a valid pubkey: {e}"))
        })?;
        let program_id = default_program_id();

        let mut rows: Vec<PlanRow> = Vec::new();
        for endpoint in &api.endpoints {
            let Some(sub) = endpoint.subscription.as_ref() else {
                continue;
            };
            // Stable plan-id derivation: must match `pay gate api`
            // (see `pay_core::server::subscription::compute_plan_id_numeric`
            // + `pay_kit::mpp::program::subscriptions::plan_id_seed`) so the
            // PDA this command writes back to the YAML is the same one
            // the running server expects to find on-chain.
            //
            // Reuse a YAML-pinned `plan_id_numeric` when present so an
            // operator who hand-edited the value keeps a stable PDA.
            let route = PlanRoute::of(endpoint);
            let plan_id_numeric = sub
                .plan_id_numeric
                .unwrap_or_else(|| route.plan_id_numeric(&owner_str, &api.subdomain));
            let seed = plan_id_seed(plan_id_numeric);
            let (plan_pda, _) = find_plan_pda(&owner, &seed, &program_id);
            rows.push(PlanRow {
                route,
                period: sub.period.clone(),
                currency: sub.currency.clone(),
                derived_plan: plan_pda.to_string(),
                existing_plan: sub.plan_id.clone(),
            });
        }

        if rows.is_empty() {
            eprintln!(
                "{}",
                "No subscription endpoints found in spec — nothing to publish.".dimmed()
            );
            return Ok(());
        }

        eprintln!();
        eprintln!("Subscription endpoints:");
        for row in &rows {
            let status = match row.existing_plan.as_deref() {
                Some(existing) if existing == row.derived_plan => {
                    "already pinned".green().to_string()
                }
                Some(_) => "differs from spec".yellow().to_string(),
                None => "pending publish".dimmed().to_string(),
            };
            let label = row.route.to_string();
            eprintln!("  {} [{status}]", label.bold());
            eprintln!("    period   {}", row.period);
            eprintln!("    currency {}", row.currency);
            eprintln!("    plan     {}", row.derived_plan);
            if let Some(existing) = row.existing_plan.as_deref()
                && existing != row.derived_plan
            {
                eprintln!("    {} {}", "existing in YAML:".yellow(), existing);
            }
        }
        eprintln!();

        if self.write {
            let updated = write_back_plan_ids(&raw, &rows)?;
            atomic_write(&self.spec, &updated)?;
            eprintln!(
                "{} {}",
                "Wrote plan_id values into".green(),
                self.spec.display().to_string().green()
            );
        } else if self.dry_run {
            eprintln!(
                "{}",
                "Dry run: no YAML changes. Pass --write to update plan_id in place once the \n\
                 Plan accounts have been published on-chain. The actual on-chain broadcast \n\
                 will land in a follow-up slice (pay-kit's INSTRUCTION_CREATE_PLAN=7 still \n\
                 needs an account-meta builder)."
                    .dimmed()
            );
        }

        Ok(())
    }
}

struct PlanRow {
    route: PlanRoute,
    period: String,
    currency: String,
    derived_plan: String,
    existing_plan: Option<String>,
}

/// In-place rewrite of `plan_id:` under each route's `subscription:` block.
fn write_back_plan_ids(yaml: &str, rows: &[PlanRow]) -> pay_core::Result<String> {
    let updates = rows
        .iter()
        .map(|r| (r.route.clone(), vec![("plan_id", r.derived_plan.clone())]))
        .collect();
    let (out, missing) = super::plan_yaml::rewrite_subscription_fields(yaml, &updates);
    if !missing.is_empty() {
        let missing: Vec<String> = missing.iter().map(ToString::to_string).collect();
        return Err(pay_core::Error::Config(format!(
            "Failed to write plan_id for endpoint(s): {}",
            missing.join(", ")
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pay_types::metering::HttpMethod;

    #[test]
    fn write_back_inserts_plan_id_when_absent() {
        let yaml = "endpoints:\n  - method: GET\n    path: api/v1/pro\n    subscription:\n      period: 30d\n      currency: USDC\n";
        let rows = vec![PlanRow {
            route: PlanRoute::new(&HttpMethod::Get, "api/v1/pro"),
            period: "30d".into(),
            currency: "USDC".into(),
            derived_plan: "PlanXYZ".into(),
            existing_plan: None,
        }];
        let out = write_back_plan_ids(yaml, &rows).unwrap();
        assert!(out.contains("plan_id: PlanXYZ"), "{out}");
    }

    #[test]
    fn write_back_replaces_existing_plan_id() {
        let yaml = "endpoints:\n  - method: GET\n    path: api/v1/pro\n    subscription:\n      period: 30d\n      currency: USDC\n      plan_id: OLD\n";
        let rows = vec![PlanRow {
            route: PlanRoute::new(&HttpMethod::Get, "api/v1/pro"),
            period: "30d".into(),
            currency: "USDC".into(),
            derived_plan: "NEW".into(),
            existing_plan: Some("OLD".into()),
        }];
        let out = write_back_plan_ids(yaml, &rows).unwrap();
        assert!(out.contains("plan_id: NEW"), "{out}");
        assert!(!out.contains("plan_id: OLD"), "{out}");
    }

    #[test]
    fn write_back_preserves_comments_and_other_endpoints() {
        let yaml = "endpoints:\n  # comment-1\n  - method: GET\n    path: api/v1/pro\n    # subscription block\n    subscription:\n      period: 30d\n      currency: USDC\n  - method: POST\n    path: api/v1/charge\n    metering:\n      dimensions:\n        - direction: usage\n          unit: requests\n          scale: 1\n          tiers:\n            - price_usd: 0.01\n";
        let rows = vec![PlanRow {
            route: PlanRoute::new(&HttpMethod::Get, "api/v1/pro"),
            period: "30d".into(),
            currency: "USDC".into(),
            derived_plan: "PlanXYZ".into(),
            existing_plan: None,
        }];
        let out = write_back_plan_ids(yaml, &rows).unwrap();
        assert!(out.contains("# comment-1"), "comment preserved");
        assert!(out.contains("# subscription block"));
        assert!(out.contains("plan_id: PlanXYZ"));
        // Other endpoints stay intact.
        assert!(out.contains("metering:"));
    }

    #[test]
    fn write_back_supports_inline_list_item_paths() {
        let yaml = "endpoints:\n  - path: api/v1/pro\n    method: GET\n    subscription:\n      period: 30d\n      currency: USDC\n";
        let rows = vec![PlanRow {
            route: PlanRoute::new(&HttpMethod::Get, "api/v1/pro"),
            period: "30d".into(),
            currency: "USDC".into(),
            derived_plan: "PlanXYZ".into(),
            existing_plan: None,
        }];

        let out = write_back_plan_ids(yaml, &rows).unwrap();

        assert!(out.contains("plan_id: PlanXYZ"), "{out}");
    }

    #[test]
    fn write_back_keeps_get_and_post_plans_on_the_same_path_apart() {
        let yaml = "endpoints:\n  - method: GET\n    path: api/v1/pro\n    subscription:\n      period: 30d\n      currency: USDC\n  - method: POST\n    path: api/v1/pro\n    subscription:\n      period: 30d\n      currency: USDC\n";
        let row = |method, plan: &str| PlanRow {
            route: PlanRoute::new(&method, "api/v1/pro"),
            period: "30d".into(),
            currency: "USDC".into(),
            derived_plan: plan.into(),
            existing_plan: None,
        };
        let rows = vec![
            row(HttpMethod::Get, "GET_PLAN"),
            row(HttpMethod::Post, "POST_PLAN"),
        ];

        let out = write_back_plan_ids(yaml, &rows).unwrap();

        let api: pay_types::metering::ApiSpec = serde_yml::from_str(&format!(
            "name: t\nsubdomain: t\ntitle: t\ndescription: t\ncategory: ai_ml\nversion: v1\nrouting:\n  type: proxy\n  url: https://example.com\n{out}"
        ))
        .unwrap();
        let plans: Vec<_> = api
            .endpoints
            .iter()
            .map(|ep| ep.subscription.as_ref().unwrap().plan_id.clone().unwrap())
            .collect();
        assert_eq!(plans, ["GET_PLAN", "POST_PLAN"]);
    }

    #[test]
    fn write_back_errors_when_an_endpoint_cannot_be_matched() {
        let rows = vec![PlanRow {
            route: PlanRoute::new(&HttpMethod::Get, "api/v1/missing"),
            period: "30d".into(),
            currency: "USDC".into(),
            derived_plan: "PlanXYZ".into(),
            existing_plan: None,
        }];

        let error = write_back_plan_ids("endpoints: []\n", &rows).unwrap_err();

        assert!(error.to_string().contains("api/v1/missing"));
    }
}
