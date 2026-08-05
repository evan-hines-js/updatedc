//! Integration test over the HAProxy Runtime API path: drive a cluster of (fake) HAProxy admin
//! stats sockets from a member set and assert exactly which `set server ... state` commands each
//! instance receives — without a real HAProxy. The fake socket mimics the one-shot admin protocol:
//! read the batch line, write a response, close.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use updated_healthproxy::haproxy::HAProxyLb;
use updated_healthproxy::{LoadBalancer, Member};

/// A stand-in HAProxy admin socket: it records the command batch each connection sends and, after
/// `delay` (an instance that answers slowly), replies with `response` (empty = the success case,
/// where `set server` prints nothing), then closes so the client's read-to-EOF returns.
async fn spawn_haproxy(
    response: &'static str,
    delay: Duration,
    recorded: Arc<Mutex<Vec<String>>>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let recorded = recorded.clone();
            tokio::spawn(async move {
                // Read one batch line (the client writes `batch\n` then waits for our response, so we
                // must not read to EOF or we would deadlock waiting for a half-close that never comes).
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    match sock.read(&mut byte).await {
                        Ok(0) => break,
                        Ok(_) if byte[0] == b'\n' => break,
                        Ok(_) => buf.push(byte[0]),
                        Err(_) => break,
                    }
                }
                recorded
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).into_owned());
                tokio::time::sleep(delay).await;
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

fn members() -> Vec<Member> {
    vec![
        Member {
            node: "agent-0".into(),
            address: "10.0.0.1".into(),
            ready: true,
        },
        Member {
            node: "agent-1".into(),
            address: "10.0.0.2".into(),
            ready: false,
        },
    ]
}

const EXPECTED_BATCH: &str =
    "set server fleet/agent-0 state ready; set server fleet/agent-1 state drain";

#[tokio::test]
async fn every_instance_in_the_cluster_is_programmed_with_the_same_member_set() {
    let a = Arc::new(Mutex::new(Vec::new()));
    let b = Arc::new(Mutex::new(Vec::new()));
    let addr_a = spawn_haproxy("", Duration::ZERO, a.clone()).await;
    let addr_b = spawn_haproxy("", Duration::ZERO, b.clone()).await;

    let lb = HAProxyLb::new(vec![addr_a.to_string(), addr_b.to_string()], "fleet".into());
    lb.reconcile(&members()).await.unwrap();

    // Both HAProxy instances received the identical converge batch: ready node up, not-ready node
    // draining. Programming the whole cluster is what keeps the two load balancers in agreement.
    assert_eq!(a.lock().unwrap().as_slice(), [EXPECTED_BATCH.to_string()]);
    assert_eq!(b.lock().unwrap().as_slice(), [EXPECTED_BATCH.to_string()]);
}

#[tokio::test]
async fn an_inline_runtime_error_is_surfaced() {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let addr = spawn_haproxy("No such server.\n", Duration::ZERO, recorded.clone()).await;

    let lb = HAProxyLb::new(vec![addr.to_string()], "fleet".into());
    let error = lb.reconcile(&members()).await.unwrap_err();

    assert!(
        error.contains("No such server."),
        "runtime error not surfaced: {error}"
    );
}

/// A cluster whose instances all answer slowly, each a little faster than the one configured before
/// it. Two properties at once.
///
/// Timing: each exchange carries its own timeout, but the reconcile as a whole is bounded by a
/// *shorter* deadline at the call site, so programming the instances one at a time drops every
/// instance past the point the outer budget ran out — and it does so on every cycle, because the
/// walk always restarts at the same slow leading instances. A node whose report went unhealthy would
/// keep taking traffic from the skipped instances forever.
///
/// Ordering: answering fastest-last means the concurrent fan-out completes in exactly the reverse of
/// configured order, so the operator-facing summary is in configured order only because the results
/// are put back in it.
#[tokio::test(flavor = "multi_thread")]
async fn a_cluster_of_slow_instances_is_programmed_within_one_reconcile_deadline() {
    const INSTANCES: usize = 8;
    const RESPONSE_DELAY: Duration = Duration::from_millis(400);
    // Spread between neighbouring instances, small beside RESPONSE_DELAY so every instance is still
    // "slow" and the serialized cost stays dominated by the base delay.
    const STAGGER: Duration = Duration::from_millis(20);

    let mut endpoints = Vec::new();
    for index in 0..INSTANCES {
        let recorded = Arc::new(Mutex::new(Vec::new()));
        // Reversed: the LAST-configured instance answers first and the first answers last, so the
        // concurrent fan-out completes in the exact opposite of configured order. With one delay for
        // all of them `buffer_unordered` hands results back in roughly submission order and the
        // ordering assertion below passes whether the summary is sorted or not.
        let delay = RESPONSE_DELAY + STAGGER * (INSTANCES - 1 - index) as u32;
        endpoints.push(
            spawn_haproxy("No such server.\n", delay, recorded)
                .await
                .to_string(),
        );
    }

    let lb = HAProxyLb::new(endpoints.clone(), "fleet".into());
    // Deliberately far tighter than INSTANCES * RESPONSE_DELAY, which is what a serialized walk
    // costs; the real reconcile deadline is only a few multiples of this.
    let budget = RESPONSE_DELAY * 4;
    let error = tokio::time::timeout(budget, lb.reconcile(&members()))
        .await
        .expect("every instance must be programmed inside one reconcile deadline")
        .expect_err("each instance answered with an inline failure");

    // Every instance was reached, and the summary reads in configured order — the exact reverse of
    // the order these results completed in.
    assert_eq!(
        error,
        endpoints
            .iter()
            .map(|endpoint| format!("{endpoint}: No such server."))
            .collect::<Vec<_>>()
            .join(" | ")
    );
}

#[tokio::test]
async fn an_unreachable_instance_does_not_block_a_healthy_one() {
    let live = Arc::new(Mutex::new(Vec::new()));
    let live_addr = spawn_haproxy("", Duration::ZERO, live.clone()).await;
    // Nothing listens here, so this instance fails to connect.
    let dead_addr = "127.0.0.1:1";

    let lb = HAProxyLb::new(
        vec![live_addr.to_string(), dead_addr.to_string()],
        "fleet".into(),
    );
    let error = lb.reconcile(&members()).await.unwrap_err();

    // The dead instance is reported...
    assert!(
        error.contains(dead_addr),
        "dead instance not reported: {error}"
    );
    // ...but the reachable one was still programmed correctly (best-effort per instance).
    assert_eq!(
        live.lock().unwrap().as_slice(),
        [EXPECTED_BATCH.to_string()]
    );
}

/// A fleet far past the point where one joined command line stops fitting HAProxy's request buffer
/// (default `tune.bufsize` 16384, i.e. roughly 400 members). Every member must still be programmed:
/// the servers are declared without `check`, so a batch HAProxy cannot read leaves the whole backend
/// in its default *routable* state and an unhealthy node keeps taking traffic — deterministically,
/// every cycle, since the same oversized line is rebuilt each time.
#[tokio::test]
async fn a_fleet_too_large_for_one_command_line_is_still_fully_programmed() {
    const FLEET: usize = 900;
    /// HAProxy's default request-buffer size: no line we send may reach it.
    const BUFSIZE: usize = 16384;

    let fleet: Vec<Member> = (0..FLEET)
        .map(|index| Member {
            node: format!("agent-{index}"),
            address: format!("10.0.{}.{}", index / 256, index % 256),
            ready: index % 2 == 0,
        })
        .collect();

    let recorded = Arc::new(Mutex::new(Vec::new()));
    let addr = spawn_haproxy("", Duration::ZERO, recorded.clone()).await;
    let lb = HAProxyLb::new(vec![addr.to_string()], "fleet".into());
    lb.reconcile(&fleet).await.unwrap();

    let lines = recorded.lock().unwrap().clone();
    assert!(lines.len() > 1, "a fleet this size must be split up");
    for line in &lines {
        assert!(
            line.len() + 1 < BUFSIZE,
            "a {}-byte command line cannot be read by HAProxy",
            line.len() + 1
        );
    }
    // Split, but not lossy: every member is programmed, in configured order, exactly once.
    let sent: Vec<String> = lines
        .iter()
        .flat_map(|line| line.split("; "))
        .map(str::to_owned)
        .collect();
    let expected: Vec<String> = fleet
        .iter()
        .map(|member| {
            format!(
                "set server fleet/{} state {}",
                member.node,
                if member.ready { "ready" } else { "drain" }
            )
        })
        .collect();
    assert_eq!(sent, expected);
}
