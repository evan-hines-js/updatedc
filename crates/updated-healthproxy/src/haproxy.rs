//! The HAProxy [`LoadBalancer`] backend: program one or more HAProxy instances' server states from
//! health via the Runtime API (each instance's admin stats socket).
//!
//! This backend is **agnostic to how HAProxy is deployed**. It does not assume `updated` manages the
//! HAProxy processes — it only needs each instance's admin stats socket reachable and the fronted
//! servers pre-declared in that instance's `backend` (so `set server` can flip their state). The
//! HAProxy could be a plain Deployment, an appliance, or anything else; this only speaks the Runtime
//! API to it. (The fleet e2e separately installs and holds HAProxy under `updated` from a signed
//! bundle — which additionally shows `updated` managing infra outside a cluster — but that is a
//! property of that topology, not a requirement of this backend.)
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

/// The longest one HAProxy runtime-API exchange may take, whatever the cluster size. A single hung
/// instance must not stall the others for longer than this even when there is budget to spare.
const RUNTIME_API_TIMEOUT: Duration = Duration::from_secs(3);

/// The budget for one runtime-API exchange when `instances` are programmed this reconcile.
///
/// Derived, not written down. The fan-out runs [`crate::FANOUT_CONCURRENCY`] wide, so `instances`
/// take `ceil(instances / width)` waves, and the whole reconcile is bounded by
/// [`crate::RECONCILE_TIMEOUT`] at the call site. A per-exchange timeout picked independently of
/// those two holds only for as many instances as it happens to cover: one cluster larger than that
/// and the waves past the outer deadline are never programmed at all — and it is the *same* leading
/// instances that consume the budget every cycle, so the tail stays frozen on stale membership
/// behind a single "timed out" line. Dividing the outer deadline by the wave count makes the fan-out
/// fit by construction at any size.
fn exchange_timeout(instances: usize) -> Duration {
    let waves = instances.div_ceil(crate::FANOUT_CONCURRENCY).max(1) as u32;
    RUNTIME_API_TIMEOUT.min(crate::RECONCILE_TIMEOUT / waves)
}

/// The HAProxy backend for a cluster of instances fronting one fleet. Every instance is programmed
/// with the same member set; each is one `host:port` admin stats socket (`stats socket ipv4@*:PORT
/// level admin` in the HAProxy config `updated` writes).
pub struct HAProxyLb {
    endpoints: Vec<String>,
    backend: String,
    /// The servers this process currently owns: the node set of the last non-empty reconcile, kept
    /// because the shutdown drain runs after there is any membership left to read it from (see
    /// [`HAProxyLb::desired_members`]).
    managed_servers: std::sync::Mutex<std::collections::BTreeSet<String>>,
}

impl HAProxyLb {
    /// `endpoints`: one admin stats socket (`host:port`) per HAProxy instance. `backend`: the name
    /// of the HAProxy `backend` section whose servers are the fleet.
    pub fn new(endpoints: Vec<String>, backend: String) -> Self {
        Self {
            endpoints,
            backend,
            managed_servers: std::sync::Mutex::default(),
        }
    }

    /// What to program this cycle, and the record of what this process currently owns.
    ///
    /// An empty `observed` is the shutdown drain (see [`crate::run`]): there is no membership to
    /// program, so the answer is "drain everything this process owned". That record tracks *current*
    /// membership, not history — a node that left the inventory is no longer declared in the
    /// HAProxy `backend` section, and `set server <backend>/<gone> state drain` makes the instance
    /// answer `No such server.`, which [`response_error`] turns into a failed reconcile. Accumulating
    /// departed nodes would therefore fail the drain — the one log line that is supposed to mean the
    /// handover was unsafe — on every deployment that followed an inventory shrink, and grow the set
    /// for the process lifetime besides.
    fn desired_members(&self, observed: &[Member]) -> Vec<Member> {
        let mut managed = self.managed_servers.lock().expect("managed server lock");
        if observed.is_empty() {
            return managed
                .iter()
                .map(|node| Member {
                    node: node.clone(),
                    address: String::new(),
                    ready: false,
                })
                .collect();
        }
        *managed = observed.iter().map(|member| member.node.clone()).collect();
        observed.to_vec()
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

/// HAProxy's default `tune.bufsize`. The Runtime API reads one command line into the request
/// buffer, so a line longer than this cannot be processed at all — the instance errors or severs
/// mid-command, identically on every cycle, and no server is ever programmed.
const HAPROXY_BUFSIZE: usize = 16384;

/// The longest command line we will send. Half the default buffer, because HAProxy reserves part of
/// the buffer for its own use and an operator may have tuned `tune.bufsize` *down*; the cost of a
/// smaller batch is one more short-lived connection, and the cost of an over-long one is a backend
/// that is never programmed.
const MAX_BATCH_BYTES: usize = HAPROXY_BUFSIZE / 2;

/// The bytes a batch occupies on the wire: the commands plus the newline that terminates the
/// command line. What HAProxy buffers is the line, so the line is what the limit is applied to.
fn line_bytes(batch: usize) -> usize {
    batch + "\n".len()
}

/// Build the `;`-joined Runtime API command batches that converge every server to its member's
/// state. A server is named by its node identity (the same name `updated` writes into the HAProxy
/// config under `backend`), so we only ever flip an existing server's admin state.
///
/// Split across batches so no single line exceeds [`MAX_BATCH_BYTES`]: one line per member is fine
/// for a handful of nodes and roughly 400 nodes past the default `tune.bufsize`, at which point a
/// single joined line stops being a command HAProxy can read at all — and because the config
/// declares the servers without `check`, every one of them stays in its default *routable* state, so
/// an unhealthy node keeps taking traffic. Chunking makes the batch size independent of the fleet
/// size. Pure, so the health→command mapping is tested without a socket.
///
/// BOTH operator-supplied names on this line — `backend` and the member's node identity — are
/// interpolated into a `;`-joined batch on a `level admin` socket, so either one carrying `;` or
/// whitespace would be a second command rather than a name. That is the configuration's business,
/// not this function's: [`updated_contracts::backend::is_balancer_safe`] refuses such a name at startup — for the
/// identity in `parse_member`, for the backend in `Config::build` — where an operator typo is a
/// configuration error instead of a fleet that is never programmed again.
fn state_batches(backend: &str, members: &[Member]) -> Vec<String> {
    const SEPARATOR: &str = "; ";
    let mut batches: Vec<String> = Vec::new();
    for member in members {
        let command = format!(
            "set server {backend}/{} state {}",
            member.node,
            desired_state(member.ready)
        );
        match batches.last_mut() {
            // What has to fit is the *line* HAProxy reads, so the trailing newline `run_commands`
            // writes counts too, not the batch alone.
            Some(batch)
                if line_bytes(batch.len() + SEPARATOR.len() + command.len()) <= MAX_BATCH_BYTES =>
            {
                batch.push_str(SEPARATOR);
                batch.push_str(&command);
            }
            // A lone command past the limit still gets its own batch rather than being dropped:
            // a node name that long is a configuration problem, and HAProxy refusing it loudly is
            // the fail-closed answer.
            _ => batches.push(command),
        }
    }
    batches
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

/// Upper bound on one admin-socket response. A successful `set server ... state` prints nothing and
/// a failure is a handful of short lines, so this only bounds a hostile or misdirected peer: the
/// endpoints are operator-written `host:port` strings resolved over cluster DNS, and a typo'd port
/// or a reused pod IP puts an arbitrary TCP peer at the other end. Reading to EOF there absorbs
/// whatever it streams for the whole exchange budget, [`crate::FANOUT_CONCURRENCY`] connections at a
/// time, until this component — the only writer of load-balancer membership — is OOM-killed and the
/// fleet freezes at the last programmed set. Same rule as every other network read in the tree (see
/// [`updated_contracts::telemetry::MAX_FLEET_REPORT_SHARD_BYTES`]): the running total is what caps
/// the read.
const RUNTIME_API_RESPONSE_LIMIT: usize = 8 * 1024;

/// Read one admin-socket response to EOF, failing rather than growing past
/// [`RUNTIME_API_RESPONSE_LIMIT`]. Mirrors the shared HTTP bounded read; the transport differs (a
/// raw socket has no declared length at all), the rule does not.
async fn read_bounded_response(stream: &mut TcpStream) -> Result<String, String> {
    let mut response = String::new();
    // One byte past the limit, so an over-long response is detected rather than silently truncated
    // into what looks like a valid (possibly empty ⇒ "success") reply.
    let read = stream
        .take(RUNTIME_API_RESPONSE_LIMIT as u64 + 1)
        .read_to_string(&mut response)
        .await
        .map_err(|error| format!("reading: {error}"))?;
    if read > RUNTIME_API_RESPONSE_LIMIT {
        return Err(format!(
            "reading: response exceeded {RUNTIME_API_RESPONSE_LIMIT} bytes"
        ));
    }
    Ok(response)
}

/// Send every command batch to one HAProxy admin socket and return the concatenated response text.
/// The socket is one-shot — it closes the connection after processing a batch line — so each batch
/// is its own short-lived connection, sent in order. `budget` (see [`exchange_timeout`]) bounds the
/// whole instance's exchange, batches included, so the fan-out still fits inside the reconcile
/// deadline however many batches the fleet size produces. Each response is read to EOF, bounded by
/// [`RUNTIME_API_RESPONSE_LIMIT`].
async fn run_commands(
    endpoint: &str,
    batches: &[String],
    budget: Duration,
) -> Result<String, String> {
    let exchange = async {
        let mut responses = String::new();
        for batch in batches {
            let mut stream = TcpStream::connect(endpoint)
                .await
                .map_err(|error| format!("connecting: {error}"))?;
            stream
                .write_all(format!("{batch}\n").as_bytes())
                .await
                .map_err(|error| format!("writing: {error}"))?;
            responses.push_str(&read_bounded_response(&mut stream).await?);
        }
        Ok::<_, String>(responses)
    };
    match tokio::time::timeout(budget, exchange).await {
        Ok(result) => result.map_err(|error| format!("HAProxy runtime API {endpoint}: {error}")),
        Err(_) => Err(format!(
            "HAProxy runtime API {endpoint} timed out after {}ms",
            budget.as_millis()
        )),
    }
}

#[async_trait::async_trait]
impl LoadBalancer for HAProxyLb {
    async fn reconcile(&self, members: &[Member]) -> Result<(), String> {
        let desired = self.desired_members(members);
        let batches = state_batches(&self.backend, &desired);
        if batches.is_empty() {
            return Ok(());
        }
        // Program every instance so the whole cluster converges. One unreachable or erroring instance
        // must not block the others — the reachable ones are still driven correctly — so failures are
        // collected and summarized rather than short-circuiting, and a persistently broken instance
        // stays visible and is retried next cycle.
        //
        // Concurrently, because "must not block the others" is otherwise false: the whole reconcile
        // is bounded by a deadline at the call site, so serialized exchanges let a few dead leading
        // instances burn the outer budget and silently skip every instance after them — on every
        // cycle, since the walk always restarts at the same dead instances. Each exchange's own
        // budget is derived from that outer deadline and this fan-out's width, so the same
        // truncation cannot return by way of a cluster larger than a fixed timeout happened to
        // cover. Results are tagged with their index so the summary reads in configured order
        // regardless of completion order.
        use futures::stream::StreamExt;
        let batches = batches.as_slice();
        let budget = exchange_timeout(self.endpoints.len());
        let mut exchanges = Vec::with_capacity(self.endpoints.len());
        for (index, endpoint) in self.endpoints.iter().enumerate() {
            exchanges.push(async move {
                let failure = match run_commands(endpoint, batches, budget).await {
                    Ok(response) => {
                        response_error(&response).map(|error| format!("{endpoint}: {error}"))
                    }
                    Err(error) => Some(error),
                };
                (index, failure)
            });
        }
        let mut outcomes: Vec<(usize, Option<String>)> = futures::stream::iter(exchanges)
            .buffer_unordered(crate::FANOUT_CONCURRENCY)
            .collect()
            .await;
        outcomes.sort_by_key(|(index, _)| *index);
        let failures: Vec<String> = outcomes
            .into_iter()
            .filter_map(|(_, failure)| failure)
            .collect();
        if failures.is_empty() {
            if members.is_empty() {
                self.managed_servers
                    .lock()
                    .expect("managed server lock")
                    .clear();
            }
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
            state_batches("fleet", &members),
            vec!["set server fleet/agent-0 state ready; set server fleet/agent-1 state drain"]
        );
        // A not-ready node drains (graceful), never hard maint — that is the zero-downtime property.
        assert_eq!(desired_state(true), "ready");
        assert_eq!(desired_state(false), "drain");
        assert!(state_batches("fleet", &[]).is_empty());
    }

    #[test]
    fn an_empty_shutdown_reconcile_drains_every_server_this_process_managed() {
        let load_balancer = HAProxyLb::new(Vec::new(), "fleet".into());
        load_balancer.desired_members(&[member("agent-1", true), member("agent-0", false)]);
        let draining = load_balancer.desired_members(&[]);
        assert_eq!(
            state_batches("fleet", &draining),
            vec!["set server fleet/agent-0 state drain; set server fleet/agent-1 state drain"]
        );
    }

    /// The drain must name what this process owns *now*. A node removed from the inventory is
    /// usually removed from the HAProxy `backend` section too, and HAProxy answers `No such server.`
    /// for it — which fails the whole reconcile. Remembering departed nodes would therefore break
    /// the shutdown handover on every deployment that followed an inventory shrink, behind the one
    /// log line that is supposed to mean the handover was unsafe, and grow the set forever besides.
    #[test]
    fn a_departed_node_is_forgotten_rather_than_drained_after_it_left_the_inventory() {
        let load_balancer = HAProxyLb::new(Vec::new(), "fleet".into());
        load_balancer.desired_members(&[member("agent-0", true), member("agent-1", true)]);
        // agent-1 leaves the inventory; the next cycle is the one that redefines ownership.
        load_balancer.desired_members(&[member("agent-0", true)]);
        let draining = load_balancer.desired_members(&[]);
        assert_eq!(
            state_batches("fleet", &draining),
            vec!["set server fleet/agent-0 state drain"]
        );
    }

    /// Every name that reaches this batch builder came through the inventory gate, so a name that
    /// could end the command it is written into never exists at this layer — the batch for a member
    /// is exactly one command, whatever the member set. (The gate itself is asserted in
    /// [`crate::tests`].)
    #[test]
    fn one_member_is_always_exactly_one_command() {
        let batches = state_batches(
            "fleet",
            &[member("agent-0", true), member("vm_db-17", false)],
        );
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].matches("set server").count(), 2);
        for injected in ["agent-0; shutdown frontend public", "agent-0 state maint"] {
            assert!(
                !updated_contracts::backend::is_balancer_safe(injected),
                "{injected:?} must be refused before it can be programmed"
            );
        }
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

    /// The whole fan-out must fit inside the deadline the reconcile is bounded by at EVERY cluster
    /// size, not only at the sizes a fixed per-exchange timeout happened to cover. Past that point
    /// the trailing waves are simply never programmed, identically every cycle.
    #[test]
    fn the_fan_out_fits_inside_the_reconcile_deadline_at_every_cluster_size() {
        for instances in [0, 1, crate::FANOUT_CONCURRENCY, 96, 1000, 100_000] {
            let waves = instances.div_ceil(crate::FANOUT_CONCURRENCY).max(1) as u32;
            assert!(
                exchange_timeout(instances) * waves <= crate::RECONCILE_TIMEOUT,
                "{instances} instances take {waves} wave(s) of {:?}, past the {:?} deadline",
                exchange_timeout(instances),
                crate::RECONCILE_TIMEOUT
            );
        }
        // A cluster that fits in one wave still gets no more than one exchange is ever worth: a
        // hung instance must not hold its wave open for the entire reconcile.
        assert_eq!(exchange_timeout(1), RUNTIME_API_TIMEOUT);
    }

    /// Every command line sent must fit in HAProxy's request buffer at EVERY fleet size, not only
    /// at the two-member sizes the integration tests exercise. A single joined line crosses the
    /// default `tune.bufsize` at roughly 400 members, and past that point HAProxy can read no
    /// command at all: the whole backend stays in its declared (routable) state forever, so an
    /// unhealthy node keeps taking traffic — deterministically, every cycle.
    #[test]
    fn every_command_batch_fits_haproxys_buffer_at_every_fleet_size() {
        for members in [1usize, 2, 399, 400, 401, 5_000, 100_000] {
            let fleet: Vec<Member> = (0..members)
                .map(|index| member(&format!("agent-{index}"), index % 3 != 0))
                .collect();
            let batches = state_batches("fleet", &fleet);
            for batch in &batches {
                assert!(
                    line_bytes(batch.len()) <= MAX_BATCH_BYTES,
                    "{members} members produced a {}-byte line, past the {MAX_BATCH_BYTES}-byte limit",
                    line_bytes(batch.len())
                );
                assert!(line_bytes(batch.len()) <= HAPROXY_BUFSIZE);
            }
            // Chunking must not drop, duplicate, or reorder a single member: the batches rejoined
            // are exactly the commands the whole fleet implies, in configured order.
            let sent: Vec<&str> = batches.iter().flat_map(|batch| batch.split("; ")).collect();
            let expected: Vec<String> = fleet
                .iter()
                .map(|member| {
                    format!(
                        "set server fleet/{} state {}",
                        member.node,
                        desired_state(member.ready)
                    )
                })
                .collect();
            assert_eq!(sent, expected, "{members} members");
        }
        // A single command longer than the limit is still sent (loudly refused by HAProxy) rather
        // than silently dropped.
        let huge = state_batches("fleet", &[member(&"n".repeat(MAX_BATCH_BYTES), true)]);
        assert_eq!(huge.len(), 1);
    }

    /// A misdirected or hostile peer on an admin socket must cost one logged failure, not the
    /// healthproxy's memory: it is the only writer of load-balancer membership, so OOM-killing it
    /// freezes the fleet at the last programmed set while unhealthy nodes keep taking traffic.
    #[tokio::test]
    async fn a_peer_that_streams_forever_is_cut_off_at_the_response_limit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    // Never closes, never stops: exactly the read-to-EOF trap.
                    let flood = vec![b'x'; 64 * 1024];
                    while socket.write_all(&flood).await.is_ok() {}
                });
            }
        });

        let error = run_commands(
            &endpoint,
            &[state_batches("fleet", &[member("agent-0", true)])[0].clone()],
            Duration::from_secs(5),
        )
        .await
        .expect_err("an unbounded response must fail, not be absorbed");
        assert!(
            error.contains("exceeded"),
            "expected a bounded-read failure, got: {error}"
        );
    }
}
