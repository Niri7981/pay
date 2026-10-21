//! Provider-neutral cleanup for resources leased to an MPP channel.

use std::sync::Arc;

use mcp_compute::google::{GoogleCloudFunctionsDriver, GoogleConfig};
use mcp_compute::trigger_google::{GoogleTriggerConfig, GoogleTriggerDriver};
use mcp_compute::{ComputeDriver, TriggerDriver};
use mcp_data::DataDriver;
use mcp_data::firestore::{FirestoreConfig, FirestoreDriver};

use crate::error::JobError;

const COMPUTE_DRIVER: &str = "google-cloud-functions";
const DATA_DRIVER: &str = "gcp-firestore";
const TRIGGER_DRIVER: &str = "google-cloud-scheduler";

#[derive(Default)]
pub struct ResourceCleaner {
    compute: Vec<Arc<dyn ComputeDriver>>,
    data: Vec<Arc<dyn DataDriver>>,
    triggers: Vec<Arc<dyn TriggerDriver>>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CleanupSummary {
    pub compute_resources: usize,
    pub data_resources: usize,
    pub trigger_resources: usize,
}

impl ResourceCleaner {
    /// The isolated orphan job deliberately supports only compute drivers and
    /// loads no financial, wallet, data, or trigger runtime.
    pub fn for_reconciliation() -> Result<Self, JobError> {
        let configured = std::env::var("PAY_RESOURCE_CLEANUP_DRIVERS")
            .map_err(|_| JobError::Config("PAY_RESOURCE_CLEANUP_DRIVERS is required".into()))?;
        let mut cleaner = Self::default();
        for driver in configured
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if driver != COMPUTE_DRIVER {
                return Err(JobError::Config(format!(
                    "unsupported orphan reconciliation driver: {driver}"
                )));
            }
            let config =
                GoogleConfig::from_env().map_err(|error| JobError::Config(error.to_string()))?;
            cleaner.compute.push(Arc::new(
                GoogleCloudFunctionsDriver::new(config)
                    .map_err(|error| JobError::Config(error.to_string()))?,
            ));
        }
        if cleaner.compute.is_empty() {
            return Err(JobError::Config(
                "at least one reconciliation driver is required".into(),
            ));
        }
        Ok(cleaner)
    }

    /// Failures are isolated from settlement by the separate scheduled job.
    pub async fn reconcile_orphans(&self, dry_run: bool) -> Result<usize, JobError> {
        let mut candidates = 0;
        let mut first_error = None;
        for driver in &self.compute {
            match driver.reconcile_orphans(dry_run).await {
                Ok(count) => candidates += count,
                Err(error) => {
                    tracing::error!(driver = driver.id(), %error, dry_run, "resource reconciliation failed");
                    first_error.get_or_insert_with(|| {
                        JobError::Config(format!("compute reconciliation: {error}"))
                    });
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(candidates),
        }
    }

    /// Build exactly the configured provider drivers. An unset, empty, unknown
    /// or misconfigured list aborts startup so production cannot silently leak
    /// resources after a channel becomes unusable: a deployment without
    /// resource-backed services must say so with `none`.
    pub async fn from_env() -> Result<Self, JobError> {
        let configured = std::env::var("PAY_RESOURCE_CLEANUP_DRIVERS").ok();
        let mut cleaner = Self::default();
        for driver in parse_driver_list(configured.as_deref())? {
            match driver {
                COMPUTE_DRIVER => cleaner.compute.push(Arc::new(
                    GoogleCloudFunctionsDriver::new(
                        GoogleConfig::from_env()
                            .map_err(|error| JobError::Config(error.to_string()))?,
                    )
                    .map_err(|error| JobError::Config(error.to_string()))?,
                )),
                DATA_DRIVER => cleaner.data.push(Arc::new(
                    FirestoreDriver::new(
                        FirestoreConfig::from_env()
                            .map_err(|error| JobError::Config(error.to_string()))?,
                    )
                    .map_err(|error| JobError::Config(error.to_string()))?,
                )),
                TRIGGER_DRIVER => cleaner.triggers.push(Arc::new(
                    GoogleTriggerDriver::new(
                        GoogleTriggerConfig::from_env()
                            .map_err(|error| JobError::Config(error.to_string()))?,
                    )
                    .await
                    .map_err(|error| JobError::Config(error.to_string()))?,
                )),
                other => {
                    return Err(JobError::Config(format!(
                        "unknown PAY_RESOURCE_CLEANUP_DRIVERS entry: {other}"
                    )));
                }
            }
        }
        Ok(cleaner)
    }

    pub fn is_enabled(&self) -> bool {
        !self.compute.is_empty() || !self.data.is_empty() || !self.triggers.is_empty()
    }

    /// Triggers are revoked first so a failure below cannot leave a schedule
    /// able to invoke a reused target. Every driver runs; the first error is
    /// returned so the lifecycle worker retries.
    pub async fn cleanup_channel(&self, channel_id: &str) -> Result<CleanupSummary, JobError> {
        let mut summary = CleanupSummary::default();
        let mut failure = None;
        for driver in &self.triggers {
            match driver.cleanup_channel(channel_id).await {
                Ok(count) => summary.trigger_resources += count,
                Err(error) => {
                    failure.get_or_insert(JobError::Config(format!("trigger cleanup: {error}")));
                }
            }
        }
        for driver in &self.compute {
            match driver.cleanup_channel(channel_id).await {
                Ok(count) => summary.compute_resources += count,
                Err(error) => {
                    failure.get_or_insert(JobError::Config(format!("compute cleanup: {error}")));
                }
            }
        }
        for driver in &self.data {
            match driver.cleanup_channel(channel_id).await {
                Ok(count) => summary.data_resources += count,
                Err(error) => {
                    failure.get_or_insert(JobError::Config(format!("data cleanup: {error}")));
                }
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(summary),
        }
    }
}

/// Explicit declaration that no resource-backed service uses this worker.
const NO_DRIVERS: &str = "none";

/// The configured cleanup drivers. Cleanup cannot be disabled by omission,
/// since an empty set lets the worker drop a channel's retry anchor while its
/// resources live on.
fn parse_driver_list(configured: Option<&str>) -> Result<Vec<&str>, JobError> {
    let required = || {
        JobError::Config(format!(
            "PAY_RESOURCE_CLEANUP_DRIVERS is required: list the cleanup driver of every \
             resource-backed service ({COMPUTE_DRIVER}, {DATA_DRIVER}, {TRIGGER_DRIVER}) \
             or `{NO_DRIVERS}`"
        ))
    };
    let drivers = configured
        .ok_or_else(required)?
        .split(',')
        .map(str::trim)
        .filter(|driver| !driver.is_empty())
        .collect::<Vec<_>>();
    if drivers.is_empty() {
        return Err(required());
    }
    if drivers.contains(&NO_DRIVERS) {
        if drivers.len() != 1 {
            return Err(JobError::Config(format!(
                "PAY_RESOURCE_CLEANUP_DRIVERS `{NO_DRIVERS}` cannot be combined with drivers"
            )));
        }
        return Ok(Vec::new());
    }
    for (index, driver) in drivers.iter().enumerate() {
        if drivers[..index].contains(driver) {
            return Err(JobError::Config(format!(
                "duplicate PAY_RESOURCE_CLEANUP_DRIVERS entry: {driver}"
            )));
        }
    }
    Ok(drivers)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FailingCompute;

    #[async_trait::async_trait]
    impl ComputeDriver for FailingCompute {
        fn id(&self) -> &'static str {
            "failing"
        }
        fn gateway_prefix(&self) -> &'static str {
            "failing-"
        }
        fn capabilities(&self) -> mcp_compute::types::DriverCapabilities {
            unreachable!()
        }
        async fn deploy(
            &self,
            _: &mcp_compute::types::Tenant,
            _: mcp_compute::types::DeployRequest,
        ) -> mcp_compute::driver::Result<mcp_compute::types::ComputeOperation> {
            unreachable!()
        }
        async fn get(
            &self,
            _: &mcp_compute::types::Tenant,
            _: mcp_compute::types::ResourceRequest,
        ) -> mcp_compute::driver::Result<mcp_compute::types::Deployment> {
            unreachable!()
        }
        async fn list(
            &self,
            _: &mcp_compute::types::Tenant,
            _: mcp_compute::types::ListRequest,
        ) -> mcp_compute::driver::Result<mcp_compute::types::DeploymentList> {
            unreachable!()
        }
        async fn delete(
            &self,
            _: &mcp_compute::types::Tenant,
            _: mcp_compute::types::ResourceRequest,
        ) -> mcp_compute::driver::Result<mcp_compute::types::ComputeOperation> {
            unreachable!()
        }
        async fn operation(
            &self,
            _: &mcp_compute::types::Tenant,
            _: &str,
        ) -> mcp_compute::driver::Result<mcp_compute::types::ComputeOperation> {
            unreachable!()
        }
        async fn invoke(
            &self,
            _: &mcp_compute::types::Tenant,
            _: mcp_compute::types::InvokeRequest,
        ) -> mcp_compute::driver::Result<mcp_compute::types::InvocationResult> {
            unreachable!()
        }
        async fn invoke_gateway(
            &self,
            _: mcp_compute::types::GatewayInvokeRequest,
        ) -> mcp_compute::driver::Result<mcp_compute::types::GatewayInvocation> {
            unreachable!()
        }
        async fn cleanup_channel(&self, _: &str) -> mcp_compute::driver::Result<usize> {
            Err(mcp_compute::driver::ComputeError::Provider(
                "unavailable".into(),
            ))
        }
    }

    #[derive(Default)]
    struct CountingTriggers(AtomicUsize);

    #[async_trait::async_trait]
    impl TriggerDriver for CountingTriggers {
        fn id(&self) -> &'static str {
            "counting"
        }
        fn capabilities(&self) -> mcp_compute::trigger_types::TriggerDriverCapabilities {
            unreachable!()
        }
        async fn create(
            &self,
            _: &mcp_compute::types::Tenant,
            _: mcp_compute::trigger_types::CreateTriggerRequest,
        ) -> mcp_compute::trigger_driver::Result<mcp_compute::trigger_types::Trigger> {
            unreachable!()
        }
        async fn get(
            &self,
            _: &mcp_compute::types::Tenant,
            _: mcp_compute::trigger_types::TriggerRequest,
        ) -> mcp_compute::trigger_driver::Result<mcp_compute::trigger_types::Trigger> {
            unreachable!()
        }
        async fn list(
            &self,
            _: &mcp_compute::types::Tenant,
            _: mcp_compute::trigger_types::ListTriggersRequest,
        ) -> mcp_compute::trigger_driver::Result<mcp_compute::trigger_types::TriggerList> {
            unreachable!()
        }
        async fn pause(
            &self,
            _: &mcp_compute::types::Tenant,
            _: mcp_compute::trigger_types::TriggerRequest,
        ) -> mcp_compute::trigger_driver::Result<mcp_compute::trigger_types::Trigger> {
            unreachable!()
        }
        async fn resume(
            &self,
            _: &mcp_compute::types::Tenant,
            _: mcp_compute::trigger_types::TriggerRequest,
        ) -> mcp_compute::trigger_driver::Result<mcp_compute::trigger_types::Trigger> {
            unreachable!()
        }
        async fn run_now(
            &self,
            _: &mcp_compute::types::Tenant,
            _: mcp_compute::trigger_types::TriggerRequest,
        ) -> mcp_compute::trigger_driver::Result<mcp_compute::trigger_types::Trigger> {
            unreachable!()
        }
        async fn delete(
            &self,
            _: &mcp_compute::types::Tenant,
            _: mcp_compute::trigger_types::TriggerRequest,
        ) -> mcp_compute::trigger_driver::Result<()> {
            unreachable!()
        }
        async fn cleanup_target(
            &self,
            _: &mcp_compute::types::Tenant,
            _: &str,
            _: &str,
            _: Option<&str>,
        ) -> mcp_compute::trigger_driver::Result<usize> {
            unreachable!()
        }
        async fn cleanup_channel(&self, _: &str) -> mcp_compute::trigger_driver::Result<usize> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(2)
        }
        async fn execute(
            &self,
            _: mcp_compute::trigger_types::ExecuteTriggerRequest,
        ) -> mcp_compute::trigger_driver::Result<
            mcp_compute::trigger_driver::TriggerExecutionResponse,
        > {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn compute_failures_do_not_skip_trigger_revocation() {
        let triggers = Arc::new(CountingTriggers::default());
        let cleaner = ResourceCleaner {
            compute: vec![Arc::new(FailingCompute)],
            data: Vec::new(),
            triggers: vec![triggers.clone()],
        };
        assert!(cleaner.cleanup_channel("channel").await.is_err());
        assert_eq!(triggers.0.load(Ordering::SeqCst), 1);

        let cleaner = ResourceCleaner {
            compute: Vec::new(),
            data: Vec::new(),
            triggers: vec![triggers.clone()],
        };
        assert_eq!(
            cleaner.cleanup_channel("channel").await.unwrap(),
            CleanupSummary {
                trigger_resources: 2,
                ..Default::default()
            }
        );
    }

    #[test]
    fn cleanup_drivers_must_be_declared_explicitly() {
        for missing in [None, Some(""), Some(" , ")] {
            assert!(
                parse_driver_list(missing)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("is required"),
                "{missing:?}"
            );
        }
        assert!(parse_driver_list(Some("none")).unwrap().is_empty());
        assert!(parse_driver_list(Some(" none ")).unwrap().is_empty());
        assert!(parse_driver_list(Some("none,gcp-firestore")).is_err());
        assert!(parse_driver_list(Some("gcp-firestore,gcp-firestore")).is_err());
        assert_eq!(
            parse_driver_list(Some("google-cloud-functions, google-cloud-scheduler")).unwrap(),
            vec![COMPUTE_DRIVER, TRIGGER_DRIVER]
        );
    }

    #[test]
    fn empty_driver_list_disables_cleanup() {
        let cleaner = ResourceCleaner::default();
        assert!(!cleaner.is_enabled());
    }
}
