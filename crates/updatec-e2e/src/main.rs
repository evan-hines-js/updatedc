//! The fleet end-to-end test for the `updatec` operator.
//!
//! It builds the kind environment (`scripts/kind-updatec-e2e.sh`), scales it to a real fleet with
//! per-set load-balancer Services, a Jenkins tier, an out-of-cluster slice fronted by the real
//! `updated-healthproxy`, and an `updated`-managed HAProxy tier — then asserts, against the live
//! control plane, that the ordered red→green lifecycle transaction ran, that per-set isolation and
//! reconciler-programmed endpoints hold, that the HAProxy tier upgrades with zero downtime, and
//! that a seeded chaos generation rolls half the fleet back to its exact predecessors while the
//! other half advances, before converging every cohort onto one version.

use std::env;

mod alertsink;
mod chaos;
mod cluster;
mod controls;
mod fleet;
mod haproxy;
mod labeler;
mod layout;
mod probe;
pub(crate) use chaos::*;
pub(crate) use cluster::*;
pub(crate) use controls::*;
pub(crate) use fleet::*;
pub(crate) use haproxy::*;
pub(crate) use labeler::*;
pub(crate) use layout::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    updated::tls::install_crypto_provider();
    match env::args().nth(1).as_deref() {
        // The one place anything — Rust or shell — learns the enrollment name a host asserts.
        // `resource_name` is the single definition; this prints it so nothing outside this binary
        // re-implements the derivation.
        Some("agent-name") => {
            let hostname = env::args()
                .nth(2)
                .ok_or("agent-name needs a hostname: `updatec-e2e agent-name <hostname>`")?;
            println!("{}", resource_name(&hostname));
            Ok(())
        }
        // The in-cluster webhook receiver the alerting assertion reads (see `alertsink`). It runs
        // from this same binary — already in the node image — so the receiver is not a bespoke
        // image or a shell one-liner nobody tests.
        Some("alert-sink") => alertsink::run().await,
        // The in-cluster load probe behind the zero-lost-requests assertion (see `probe`): same
        // binary, same rationale, and placed inside the cluster so its measurements carry no
        // port-forward noise the assertion would have to tolerate.
        Some("load-probe") => {
            let url = env::args()
                .nth(2)
                .ok_or("load-probe needs a URL: `updatec-e2e load-probe <url> <interval_ms>`")?;
            let interval: u64 = env::args()
                .nth(3)
                .ok_or("load-probe needs an interval: `updatec-e2e load-probe <url> <interval_ms>`")?
                .parse()?;
            probe::run(&url, interval).await
        }
        None => run_e2e().await,
        Some(command) => {
            Err(format!("unknown command {command:?}; use `agent-name <hostname>`, `alert-sink`, `load-probe <url> <interval_ms>`, or no argument to run the e2e").into())
        }
    }
}

async fn run_e2e() -> Result<(), Box<dyn std::error::Error>> {
    bring_up_cluster().await?;
    // The pod set labeler starts here and runs for the rest of the test, keeping every pod in
    // its set's Service.
    let fleet = Fleet::connect().await?;
    let layout = prepare_fleet().await?;
    fleet
        .wait_for_convergence(BASELINE_VERSION, FLEET_ROLLOUT_TIMEOUT_SECS)
        .await?;
    assert_set_isolation().await?;
    assert_external_endpoints_reconciled().await?;
    assert_lifecycle_transaction().await?;
    assert_haproxy_zero_downtime_upgrade().await?;
    let chaos = Chaos {
        fleet: fleet.clone(),
        layout: layout.clone(),
    };
    chaos.run().await?;
    // Composed into the same run, on the same cluster, above the version the chaos generation
    // converged the fleet onto: each scenario publishes the next major to the one group it
    // exercises, so they cost a single group's rollout apiece rather than a fleet's.
    let baseline = version_major(BASELINE_VERSION).ok_or("unparseable baseline version")?;
    assert_node_controls(&layout, &fleet, &format!("{}.0.0", baseline + 4)).await?;
    assert_staleness_fails_closed(&layout, &fleet, &format!("{}.0.0", baseline + 5)).await?;
    assert_regression_rollback(
        &layout,
        &fleet,
        &format!("{}.0.0", baseline + 6),
        &format!("{}.0.0", baseline + 7),
    )
    .await?;
    assert_dataflow_inputs(&layout, &fleet, &format!("{}.0.0", baseline + 8)).await?;
    assert_schedule_freeze_and_emergency(&layout, &fleet, &format!("{}.0.0", baseline + 9)).await?;
    assert_quarantine_fails_closed(&fleet).await?;
    assert_metrics_exposed().await?;
    println!(
        "E2E PASS: {COHORT_COUNT} cohorts exercised the ordered lifecycle transaction, per-set \
         isolation, reconciler-programmed endpoints, a zero-downtime HAProxy upgrade, a seeded \
         rollback whose rejecting cohorts released their sets' slots to their siblings, the \
         fleet-wide regression halt and its delivered alert, the onRegression=rollback response \
         (rebased, durably vetoed across a controller restart, released by corrected bytes), the \
         producer->consumer dataflow with a no-rename re-stage, a schedule freeze waived only by a \
         stated emergency, a quarantined group that moved nobody, live metrics expositions, the \
         per-node hold/cordon controls, staleness failing closed, and exact fleet convergence"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{agent_resource_name, resource_name};

    /// Golden vectors for the derivation every consumer reads out of this binary
    /// (`updatec-e2e agent-name`). Changing it renames every node in the fleet and the kind
    /// e2e at once, so it must be a deliberate edit, not a refactoring accident.
    #[test]
    fn agent_names_match_dynamic_enrollment_names() {
        assert_eq!(agent_resource_name(0), "agent-53fa7c16911537893c54970e");
        assert_eq!(agent_resource_name(4), "agent-9f815b3ffd9a32a533b577d9");
    }

    /// The ordinal is the fleet-wide node index, and the layout constants that bound it are
    /// tunable. A node past the 256th must get its OWN name: a narrowed ordinal would wrap it onto
    /// an existing node's CR, and a scenario would then bench, signal, or assert against the wrong
    /// machine — a silent wrong answer rather than a failure.
    #[test]
    fn an_ordinal_past_a_byte_gets_its_own_name() {
        assert_eq!(agent_resource_name(256), resource_name("agent-256"));
        assert_ne!(agent_resource_name(256), agent_resource_name(0));
    }
}
