//! Integration test over the HAProxy Runtime API path: drive a cluster of (fake) HAProxy admin
//! stats sockets from a member set and assert exactly which `set server ... state` commands each
//! instance receives — without a real HAProxy. The fake socket mimics the one-shot admin protocol:
//! read the batch line, write a response, close.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use updated_healthproxy::haproxy::HAProxyLb;
use updated_healthproxy::{LoadBalancer, Member};

/// A stand-in HAProxy admin socket: it records the command batch each connection sends and replies
/// with `response` (empty = the success case, where `set server` prints nothing), then closes so the
/// client's read-to-EOF returns.
async fn spawn_haproxy(response: &'static str, recorded: Arc<Mutex<Vec<String>>>) -> SocketAddr {
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
    let addr_a = spawn_haproxy("", a.clone()).await;
    let addr_b = spawn_haproxy("", b.clone()).await;

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
    let addr = spawn_haproxy("No such server.\n", recorded.clone()).await;

    let lb = HAProxyLb::new(vec![addr.to_string()], "fleet".into());
    let error = lb.reconcile(&members()).await.unwrap_err();

    assert!(
        error.contains("No such server."),
        "runtime error not surfaced: {error}"
    );
}

#[tokio::test]
async fn an_unreachable_instance_does_not_block_a_healthy_one() {
    let live = Arc::new(Mutex::new(Vec::new()));
    let live_addr = spawn_haproxy("", live.clone()).await;
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
