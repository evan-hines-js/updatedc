//! The one place the controller's environment contract is spelled.
//!
//! `updatec` takes every process-startup setting from the environment — there is deliberately no
//! second (argv) configuration surface — and the Helm chart is what sets those variables in a real
//! deployment. That makes each name a contract between two languages, and it was written twice:
//! `main.rs` read bare string literals and `deploy/charts/updatec/templates/*.yaml` wrote bare YAML
//! literals, with nothing tying them together.
//!
//! Half of these settings are optional and fail SILENTLY when the two halves disagree. Rename
//! `UPDATED_ALERT_URL` on either side and the controller does not fail to start; it comes up with
//! alerting quietly switched off, which is indistinguishable from a fleet that simply has no
//! condition transitions to report. `UPDATED_METRICS_ADDRESS` is the same shape: the scrape target
//! just stops existing.
//!
//! So the names live here once, and [`ALL`] is asserted against the rendered chart by the
//! `chart_env_contract` test: a variable the chart sets that the controller does not read fails the
//! build, in either direction. Adding a setting means adding it here, which is what puts it in
//! `ALL` and therefore under the check.

/// Declare the controller's environment variables and the list of them from one source.
///
/// The list is not a second place to maintain — it is generated from the declarations — because a
/// name missing from [`ALL`] is a name the chart check silently stops covering, which is precisely
/// the failure this module exists to end.
macro_rules! controller_env {
    ( $( $(#[$meta:meta])* $konst:ident = $value:expr; )* ) => {
        $( $(#[$meta])* pub const $konst: &str = $value; )*

        /// Every environment variable the controller reads, complete by construction.
        pub const ALL: &[&str] = &[ $($konst),* ];
    };
}

controller_env! {
    /// Serve `GET /metrics` on this address. Absent means the metrics listener is off.
    METRICS_ADDRESS = "UPDATED_METRICS_ADDRESS";
    /// POST condition transitions to this webhook. Absent means alerting is off.
    ALERT_URL = "UPDATED_ALERT_URL";
    /// Bearer-token file for the alert webhook, re-read per delivery.
    ALERT_TOKEN_FILE = "UPDATED_ALERT_TOKEN_FILE";
    /// The namespace the controller and gateway operate in.
    NAMESPACE = "UPDATED_NAMESPACE";
    /// The `UpdateRepository` this process serves.
    REPOSITORY = "UPDATED_REPOSITORY";
    /// The origin signed into every node's durable enrollment bundle. Required.
    PUBLIC_URL = "UPDATED_PUBLIC_URL";
    /// Gateway data-plane listen address.
    LISTEN = "UPDATED_LISTEN";
    /// Gateway health listen address.
    HEALTH_LISTEN = "UPDATED_HEALTH_LISTEN";
    /// Lease name serializing in-place enrollment claims. Required in gateway mode.
    ENROLLMENT_LOCK_NAME = "UPDATED_ENROLLMENT_LOCK_NAME";
    /// Directory of the gateway's cert-manager-issued mTLS material.
    GATEWAY_TLS_DIR = "UPDATED_GATEWAY_TLS_DIR";
    /// The client CN the fleet bootstrap certificate must present.
    ENROLLMENT_CLIENT_CN = "UPDATED_ENROLLMENT_CLIENT_CN";
    /// Directory of the fleet issuing CA the join endpoint signs node CSRs with.
    ISSUING_CA_DIR = "UPDATED_ISSUING_CA_DIR";
    /// Controller state directory.
    STATE_DIR = "UPDATED_STATE_DIR";
    /// Image the controller runs healthproxy from. Required in controller mode.
    HEALTHPROXY_IMAGE = "UPDATED_HEALTHPROXY_IMAGE";
    /// Pull policy for that image.
    HEALTHPROXY_PULL_POLICY = "UPDATED_HEALTHPROXY_PULL_POLICY";
    /// How many shards a fleet report projection may span. Owned by the contracts crate, which is
    /// what reads it; aliased rather than re-spelled so the chart check covers it too.
    FLEET_REPORT_MAX_SHARDS = updated_contracts::telemetry::FLEET_REPORT_MAX_SHARDS_ENV;
}

/// The pod identity, supplied by Kubernetes rather than by our chart, so it is deliberately not in
/// [`ALL`]: the chart neither sets it nor should be asserted to.
pub const HOSTNAME: &str = "HOSTNAME";

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Every name is distinct and carries the project prefix the chart check filters on.
    ///
    /// A duplicate would mean two settings silently sharing one variable, and a name outside the
    /// `UPDATED_` prefix would be skipped by that filter — present in `ALL`, but never actually
    /// checked against the chart.
    #[test]
    fn the_contract_is_a_set_of_distinct_prefixed_names() {
        let mut seen = std::collections::BTreeSet::new();
        for name in ALL {
            assert!(
                name.starts_with("UPDATED_"),
                "{name} is outside the prefix the chart check filters on"
            );
            assert!(seen.insert(*name), "{name} is declared twice");
        }
        assert_eq!(seen.len(), ALL.len());
    }
}
