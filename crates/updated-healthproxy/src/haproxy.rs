//! The HAProxy [`LoadBalancer`] backend: program one or more HAProxy instances' server states from
//! health via the Runtime API (each instance's admin stats socket).
//!
//! This backend is **agnostic to how HAProxy is deployed**. It does not assume `updated` manages the
//! HAProxy processes — it only needs each instance's admin stats socket reachable and the fronted
//! servers pre-declared in that instance's `backend` (so `set server` can flip their state). The
//! HAProxy could be a plain Deployment, an appliance, or anything else; this only speaks the Runtime
//! API to it. (Our *demo* separately installs and holds HAProxy under `updated` from a signed
//! bundle — which additionally shows `updated` managing infra outside a cluster — but that is a
//! property of the demo topology, not a requirement of this backend.)
//!
//! Membership is driven from the fleet's own signed health: a ready node routes (`state ready`), a
//! not-ready node **drains** (`state drain`) — existing connections finish while no new ones arrive,
//! which is what makes a rollout zero-downtime. We never add or remove servers, only flip the admin
//! state of the ones the config already declares. The full desired set is programmed to *every*
//! instance each cycle, so the call is idempotent and the cluster converges.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{LoadBalancer, Member};

/// One HAProxy runtime-API exchange is bounded by this — the health fetches and the reconcile loop
/// are already bounded elsewhere, and a single hung instance must not stall the others.
const RUNTIME_API_TIMEOUT: Duration = Duration::from_secs(3);

/// The HAProxy backend for a cluster of instances fronting one fleet. Every instance is programmed
/// with the same member set; each is one `host:port` admin stats socket (`stats socket ipv4@*:PORT
/// level admin` in the HAProxy config `updated` writes).
pub struct HAProxyLb {
    endpoints: Vec<String>,
    backend: String,
}

impl HAProxyLb {
    /// `endpoints`: one admin stats socket (`host:port`) per HAProxy instance. `backend`: the name
    /// of the HAProxy `backend` section whose servers are the fleet.
    pub fn new(endpoints: Vec<String>, backend: String) -> Self {
        Self { endpoints, backend }
    }
}

/// The Runtime API state word for a member. A not-ready node **drains** rather than going hard
/// `maint`: draining lets in-flight requests finish while refusing new ones, so a health-driven
/// removal is graceful — the difference between a clean rollout and dropped connections.
fn desired_state(ready: bool) -> &'static str {
    if ready {
        "ready"
    } else {
        "drain"
    }
}

/// Build the `;`-joined Runtime API command batch that converges every server to its member's
/// state. A server is named by its node identity (the same name `updated` writes into the HAProxy
/// config under `backend`), so we only ever flip an existing server's admin state. Pure, so the
/// health→command mapping is tested without a socket.
fn state_commands(backend: &str, members: &[Member]) -> String {
    members
        .iter()
        .map(|member| {
            format!(
                "set server {backend}/{} state {}",
                member.node,
                desired_state(member.ready)
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// A HAProxy Runtime API response reports each command's failure inline (e.g. `No such server.`); a
/// successful `set server ... state` prints nothing. So any non-empty, non-whitespace output is a
/// problem worth surfacing rather than swallowing.
fn response_error(response: &str) -> Option<String> {
    let trouble: Vec<&str> = response
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    (!trouble.is_empty()).then(|| trouble.join("; "))
}

/// Send a command batch to one HAProxy admin socket and return its response text. One connection per
/// instance per reconcile, bounded by [`RUNTIME_API_TIMEOUT`]; the socket closes the connection
/// after a one-shot batch, so the response is read to EOF.
async fn run_commands(endpoint: &str, batch: &str) -> Result<String, String> {
    let exchange = async {
        let mut stream = TcpStream::connect(endpoint)
            .await
            .map_err(|error| format!("connecting: {error}"))?;
        stream
            .write_all(format!("{batch}\n").as_bytes())
            .await
            .map_err(|error| format!("writing: {error}"))?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .map_err(|error| format!("reading: {error}"))?;
        Ok::<_, String>(response)
    };
    match tokio::time::timeout(RUNTIME_API_TIMEOUT, exchange).await {
        Ok(result) => result.map_err(|error| format!("HAProxy runtime API {endpoint}: {error}")),
        Err(_) => Err(format!(
            "HAProxy runtime API {endpoint} timed out after {}s",
            RUNTIME_API_TIMEOUT.as_secs()
        )),
    }
}

#[async_trait::async_trait]
impl LoadBalancer for HAProxyLb {
    async fn reconcile(&self, members: &[Member]) -> Result<(), String> {
        let batch = state_commands(&self.backend, members);
        if batch.is_empty() {
            return Ok(());
        }
        // Program every instance so the whole cluster converges. One unreachable or erroring instance
        // must not block the others — the reachable ones are still driven correctly — so failures are
        // collected and summarized rather than short-circuiting, and a persistently broken instance
        // stays visible and is retried next cycle.
        let mut failures = Vec::new();
        for endpoint in &self.endpoints {
            match run_commands(endpoint, &batch).await {
                Ok(response) => {
                    if let Some(error) = response_error(&response) {
                        failures.push(format!("{endpoint}: {error}"));
                    }
                }
                Err(error) => failures.push(error),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join(" | "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(node: &str, ready: bool) -> Member {
        Member {
            node: node.to_string(),
            address: "10.0.0.1".to_string(),
            ready,
        }
    }

    #[test]
    fn commands_route_ready_nodes_and_drain_not_ready_ones() {
        let members = vec![member("agent-0", true), member("agent-1", false)];
        assert_eq!(
            state_commands("fleet", &members),
            "set server fleet/agent-0 state ready; set server fleet/agent-1 state drain"
        );
        // A not-ready node drains (graceful), never hard maint — that is the zero-downtime property.
        assert_eq!(desired_state(true), "ready");
        assert_eq!(desired_state(false), "drain");
        assert_eq!(state_commands("fleet", &[]), "");
    }

    #[test]
    fn only_non_empty_runtime_output_is_treated_as_an_error() {
        // A successful `set server` prints nothing.
        assert_eq!(response_error(""), None);
        assert_eq!(response_error("\n  \n"), None);
        // An inline failure line is surfaced.
        assert_eq!(
            response_error("No such server.\n"),
            Some("No such server.".to_string())
        );
    }
}
