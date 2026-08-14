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
        None => run_e2e().await,
        Some(command) => {
            Err(format!("unknown command {command:?}; use `agent-name <hostname>`, `alert-sink`, or no argument to run the e2e").into())
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
    println!(
        "E2E PASS: {COHORT_COUNT} cohorts exercised the ordered lifecycle transaction, per-set \
         isolation, reconciler-programmed endpoints, a zero-downtime HAProxy upgrade, a seeded \
         rollback whose rejecting cohorts released their sets' slots to their siblings, the \
         fleet-wide regression halt and its delivered alert, the per-node hold/cordon controls, \
         staleness failing closed, and exact fleet convergence"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::agent_resource_name;

    /// Golden vectors for the derivation every consumer reads out of this binary
    /// (`updatec-e2e agent-name`). Changing it renames every node in the fleet and the kind
    /// e2e at once, so it must be a deliberate edit, not a refactoring accident.
    #[test]
    fn agent_names_match_dynamic_enrollment_names() {
        assert_eq!(agent_resource_name(0), "agent-53fa7c16911537893c54970e");
        assert_eq!(agent_resource_name(4), "agent-9f815b3ffd9a32a533b577d9");
    }
}
