//! Integration test over the real HTTP health path: resolve fleet membership from CDN reports
//! and drive a load balancer with it. The `LoadBalancer` seam lets us assert what membership
//! the reconciler *would program* without needing a Kubernetes cluster.

use std::net::SocketAddr;
use std::sync::Mutex;

use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use updated_contracts::telemetry::{report_object_key, NodeReport};
use updated_healthproxy::{resolve_members, FleetNode, LoadBalancer, Member};

static TEST_KEY: std::sync::LazyLock<(Vec<u8>, Vec<u8>)> = std::sync::LazyLock::new(|| {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
    (pkcs8.as_ref().to_vec(), key.public_key().as_ref().to_vec())
});

/// A well-formed running digest. Membership follows health, never the digest, but a report
/// needs one to pass the shared trust gate.
const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// A CDN standing in for the object store: serves each node's report at
/// `/telemetry/<node>.json`, 404 for anything it was not given.
async fn spawn_cdn(reports: Vec<(String, bool)>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let bodies: Vec<(String, String)> = reports
        .into_iter()
        .map(|(node, healthy)| {
            let report = NodeReport::new(&node, "deploy-3", DIGEST, "3.0.0", DIGEST, healthy);
            let envelope = updated_contracts::telemetry::sign_report(&report, &TEST_KEY.0).unwrap();
            let body = serde_json::to_string(&envelope).unwrap();
            (format!("/{}", report_object_key(&node)), body)
        })
        .collect();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let bodies = bodies.clone();
            tokio::spawn(async move {
                let mut scratch = [0u8; 1024];
                let read = sock.read(&mut scratch).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&scratch[..read]);
                let path = request.split_whitespace().nth(1).unwrap_or("");
                let response = match bodies.iter().find(|(p, _)| p == path) {
                    Some((_, body)) => format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    ),
                    None => {
                        "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                            .to_string()
                    }
                };
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

/// A load balancer that just records the membership it was told to program.
#[derive(Default)]
struct RecordingLb {
    last: Mutex<Option<Vec<Member>>>,
}

#[async_trait::async_trait]
impl LoadBalancer for RecordingLb {
    async fn reconcile(&self, members: &[Member]) -> Result<(), String> {
        *self.last.lock().unwrap() = Some(members.to_vec());
        Ok(())
    }
}

fn inventory(pairs: &[(&str, &str)]) -> Vec<FleetNode> {
    pairs
        .iter()
        .map(|(node, address)| FleetNode {
            node: node.to_string(),
            address: address.to_string(),
            public_key: TEST_KEY.1.clone(),
        })
        .collect()
}

#[tokio::test]
async fn membership_reflects_each_node_health_and_drives_the_balancer() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cdn = spawn_cdn(vec![
        ("agent-0".into(), true),
        ("agent-1".into(), false),
        // agent-2 has no report at all — must fail closed to not-ready.
    ])
    .await;
    let base = format!("http://{cdn}");
    let inventory = inventory(&[
        ("agent-0", "10.0.0.1"),
        ("agent-1", "10.0.0.2"),
        ("agent-2", "10.0.0.3"),
    ]);
    let client = reqwest::Client::new();

    let mut cache = std::collections::HashMap::new();
    let members = resolve_members(&client, &base, &inventory, &mut cache).await;
    assert_eq!(
        members,
        vec![
            Member {
                node: "agent-0".into(),
                address: "10.0.0.1".into(),
                ready: true
            },
            Member {
                node: "agent-1".into(),
                address: "10.0.0.2".into(),
                ready: false
            },
            Member {
                node: "agent-2".into(),
                address: "10.0.0.3".into(),
                ready: false
            },
        ]
    );

    // The reconciler hands exactly this set to the load balancer.
    let lb = RecordingLb::default();
    lb.reconcile(&members).await.unwrap();
    let programmed = lb.last.lock().unwrap().clone().unwrap();
    assert_eq!(programmed, members);
    // Only the healthy, settled node is in rotation; the rest are present but not-ready, so
    // the balancer keeps routing to agent-0 alone.
    assert_eq!(
        programmed
            .iter()
            .filter(|m| m.ready)
            .map(|m| m.node.as_str())
            .collect::<Vec<_>>(),
        vec!["agent-0"]
    );
}

/// A transient CDN outage must not drain an otherwise-healthy fleet: a node fetched ready one cycle
/// stays ready the next when the CDN is unreachable, because the last good report is reused (still
/// within `REPORT_FRESHNESS`). This is the difference between failing closed on a genuine not-ready
/// report and blindly mass-evicting when the checker's own dependency blinks.
#[tokio::test]
async fn a_transient_cdn_outage_does_not_drain_a_freshly_healthy_node() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cdn = spawn_cdn(vec![("agent-0".into(), true)]).await;
    let live = format!("http://{cdn}");
    let inventory = inventory(&[("agent-0", "10.0.0.1")]);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let mut cache = std::collections::HashMap::new();

    // Cycle 1: the live CDN reports the node healthy; the cache is populated.
    let live_members = resolve_members(&client, &live, &inventory, &mut cache).await;
    assert!(
        live_members[0].ready,
        "node should be ready from the live CDN"
    );

    // Cycle 2: the CDN is unreachable (a dead endpoint stands in for the outage). The fresh fetch
    // fails, but the cached healthy report is still within the freshness window, so the node stays
    // in rotation instead of being drained by a transport error alone.
    let dead = "http://127.0.0.1:1";
    let outage_members = resolve_members(&client, dead, &inventory, &mut cache).await;
    assert!(
        outage_members[0].ready,
        "a healthy node must survive a transient CDN outage via its last good report"
    );
}
