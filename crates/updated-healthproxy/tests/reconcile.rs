//! Integration test over the real HTTP health path: resolve fleet membership from CDN reports
//! and drive a load balancer with it. The `LoadBalancer` seam lets us assert what membership
//! the reconciler *would program* without needing a Kubernetes cluster.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use updated_contracts::backend::BackendInventoryMember;
use updated_contracts::key::P256PublicKey;
use updated_contracts::telemetry::{
    FleetReports, NodeReport, DEFAULT_FLEET_REPORT_MAX_SHARDS, FLEET_INDEX_OBJECT_KEY,
};
use updated_healthproxy::{resolve_members, LoadBalancer, Member};

static TEST_KEY: std::sync::LazyLock<(Vec<u8>, P256PublicKey)> = std::sync::LazyLock::new(|| {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
    (
        pkcs8.as_ref().to_vec(),
        P256PublicKey::parse_hex(&hex::encode(key.public_key().as_ref())).unwrap(),
    )
});

/// A well-formed running digest. Membership follows health, never the digest, but a report
/// needs one to pass the shared trust gate.
const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// How the store fails one object it does hold — the two shapes a reader must tell apart from an
/// object that is simply empty.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// Answered 404: a swept or negative-cached per-generation prefix, an ACL on it.
    Missing,
    /// Accepted and never answered: a blackholed or hung CDN, which is what a per-fetch budget
    /// exists to bound.
    Hang,
}

/// A CDN standing in for the object store: serves the stable fleet index and every immutable shard
/// it names, 404 for anything else. Individual objects can be failed mid-run ([`TestCdn::fail`]),
/// which is how the partial- and total-loss reads below are staged.
struct TestCdn {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    /// Every shard object of the published generation, as (request path, body).
    shards: Vec<(String, String)>,
    faults: Arc<Mutex<std::collections::HashMap<String, Fault>>>,
}

impl TestCdn {
    /// Fail one object from now on, leaving everything else served.
    fn fail(&self, path: &str, how: Fault) {
        self.faults.lock().unwrap().insert(path.to_string(), how);
    }

    /// The request path of the shard object holding `node`. Placement is the writer's, so a test
    /// that wants to fail "the shard this node lives in" must read it off the published generation
    /// rather than recompute the hash.
    fn shard_path_of(&self, node: &str) -> String {
        self.shards
            .iter()
            .find(|(_, body)| {
                serde_json::from_str::<serde_json::Value>(body)
                    .ok()
                    .and_then(|document| Some(document.get("reports")?.get(node).is_some()))
                    .unwrap_or(false)
            })
            .map(|(path, _)| path.clone())
            .expect("every reported node is placed in some shard of the generation")
    }
}

async fn spawn_cdn(reports: Vec<(String, bool)>) -> TestCdn {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut fleet = FleetReports::default();
    for (node, healthy) in reports {
        let mut report =
            NodeReport::new(&node, "deploy-3", DIGEST, "3.0.0", DIGEST, DIGEST, healthy);
        bind_reconciliation(&mut report);
        let body =
            updated_contracts::telemetry::encode_signed_report(&report, &TEST_KEY.0).unwrap();
        // A test fixture minting the acceptance a real scanner would have produced from these
        // bytes and the object's durable metadata.
        let accepted = updated_contracts::telemetry::accept_stored_report(
            &body,
            &node,
            updated_contracts::telemetry::ReportStoredAt::from_unix_millis(1).unwrap(),
        )
        .unwrap();
        fleet.record(accepted);
    }
    let (_, index_body, shards, _) = fleet
        .rebalance(DEFAULT_FLEET_REPORT_MAX_SHARDS)
        .unwrap()
        .into_parts();
    let shard_bodies: Vec<(String, String)> = shards
        .into_iter()
        .map(|(location, body)| {
            (
                format!("/{}", location.object_key()),
                String::from_utf8(body).unwrap(),
            )
        })
        .collect();
    let mut bodies = shard_bodies.clone();
    bodies.push((
        format!("/{FLEET_INDEX_OBJECT_KEY}"),
        String::from_utf8(index_body).unwrap(),
    ));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let faults: Arc<Mutex<std::collections::HashMap<String, Fault>>> = Arc::default();
    let observed = requests.clone();
    let failing = faults.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let bodies = bodies.clone();
            let observed = observed.clone();
            let failing = failing.clone();
            tokio::spawn(async move {
                let mut scratch = [0u8; 1024];
                let read = sock.read(&mut scratch).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&scratch[..read]);
                let path = request.split_whitespace().nth(1).unwrap_or("").to_string();
                observed.lock().unwrap().push(path.clone());
                let fault = failing.lock().unwrap().get(&path).copied();
                if fault == Some(Fault::Hang) {
                    // Hold the connection open and never answer, keeping `sock` alive.
                    std::future::pending::<()>().await;
                }
                let response = match bodies.iter().find(|(p, _)| *p == path) {
                    Some((_, body)) if fault.is_none() => format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    ),
                    _ => "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        .to_string(),
                };
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    TestCdn {
        address: addr,
        requests,
        shards: shard_bodies,
        faults,
    }
}

fn bind_reconciliation(report: &mut NodeReport) {
    use updated_contracts::reconciler::{
        HostAction, LastReconciliation, MutationOperation, Reason, ReconciledRelease,
        ReconcilerIdentity, ReconciliationTransition, SuccessfulMutation,
    };
    let running = ReconciledRelease::new(
        report.version.clone(),
        DIGEST.into(),
        report.archive_sha256.clone(),
    )
    .unwrap();
    let transition = ReconciliationTransition::new(running.clone(), running);
    let reconciler_release =
        ReconciledRelease::new("1.0.0".into(), DIGEST.into(), DIGEST.into()).unwrap();
    report.reconciliation = Some(
        LastReconciliation::new(
            MutationOperation::Apply,
            Reason::Restart,
            updated_contracts::reconciler::attempt::CONVERGE.into(),
            transition,
            ReconcilerIdentity::new(
                report.provider_set_sha256.clone(),
                "system".into(),
                reconciler_release,
            )
            .unwrap(),
            SuccessfulMutation::new(false, HostAction::None, None).unwrap(),
            1,
        )
        .unwrap(),
    );
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

fn inventory(pairs: &[(&str, &str)]) -> Vec<BackendInventoryMember> {
    pairs
        .iter()
        .map(|(node, address)| BackendInventoryMember::Active {
            node: node.to_string(),
            address: address.to_string(),
            public_key: TEST_KEY.1.clone(),
        })
        .collect()
}

#[tokio::test]
async fn membership_reflects_each_node_health_and_drives_the_balancer() {
    updated::tls::install_crypto_provider();
    let cdn = spawn_cdn(vec![
        ("agent-0".into(), true),
        ("agent-1".into(), false),
        // agent-2 has no report at all — must fail closed to not-ready.
    ])
    .await;
    let base = format!("http://{}", cdn.address);
    let inventory = inventory(&[
        ("agent-0", "10.0.0.1"),
        ("agent-1", "10.0.0.2"),
        ("agent-2", "10.0.0.3"),
    ]);
    let client = reqwest::Client::new();

    let mut cache = updated_healthproxy::LastKnownGood::new();
    let (members, observed) = resolve_members(
        &client,
        &base,
        &inventory,
        std::time::Duration::from_secs(2),
        &mut cache,
    )
    .await;
    assert!(observed, "a usable fleet index is an observation");
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

#[tokio::test]
async fn a_cordon_is_drained_without_consulting_or_trusting_its_s3_report() {
    updated::tls::install_crypto_provider();
    let cdn = spawn_cdn(vec![("agent-0".into(), true)]).await;
    let base = format!("http://{}", cdn.address);
    let inventory = vec![BackendInventoryMember::Cordoned {
        node: "agent-0".into(),
    }];
    let mut cache = updated_healthproxy::LastKnownGood::new();
    let (members, observed) = resolve_members(
        &reqwest::Client::new(),
        &base,
        &inventory,
        std::time::Duration::from_secs(2),
        &mut cache,
    )
    .await;

    assert!(observed, "an all-cordoned inventory needs no report shard");
    assert_eq!(
        members,
        vec![Member {
            node: "agent-0".into(),
            address: String::new(),
            ready: false,
        }]
    );
    let requests = cdn.requests.lock().unwrap();
    assert_eq!(
        requests.as_slice(),
        &[] as &[String],
        "a cordoned identity is decided by trusted inventory, not by any report shard"
    );
}

/// A transient CDN outage must not drain an otherwise-healthy fleet: a node fetched ready one cycle
/// stays ready the next when the CDN is unreachable, because the last good report is reused (still
/// within `REPORT_FRESHNESS`). This is the difference between failing closed on a genuine not-ready
/// report and blindly mass-evicting when the checker's own dependency blinks.
#[tokio::test]
async fn a_transient_cdn_outage_does_not_drain_a_freshly_healthy_node() {
    updated::tls::install_crypto_provider();
    let cdn = spawn_cdn(vec![("agent-0".into(), true)]).await;
    let live = format!("http://{}", cdn.address);
    let inventory = inventory(&[("agent-0", "10.0.0.1")]);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let mut cache = updated_healthproxy::LastKnownGood::new();

    // Cycle 1: the live CDN reports the node healthy; the cache is populated.
    let (live_members, live_observed) = resolve_members(
        &client,
        &live,
        &inventory,
        std::time::Duration::from_secs(2),
        &mut cache,
    )
    .await;
    assert!(
        live_members[0].ready,
        "node should be ready from the live CDN"
    );
    assert!(live_observed, "a usable fleet index is an observation");

    // Cycle 2: the CDN is unreachable (a dead endpoint stands in for the outage). The fresh fetch
    // fails, but the cached healthy report is still within the freshness window, so the node stays
    // in rotation instead of being drained by a transport error alone.
    let dead = "http://127.0.0.1:1";
    let (outage_members, outage_observed) = resolve_members(
        &client,
        dead,
        &inventory,
        std::time::Duration::from_secs(2),
        &mut cache,
    )
    .await;
    assert!(
        outage_members[0].ready,
        "a healthy node must survive a transient CDN outage via its last good report"
    );
    // The bridged readiness above is exactly why the failure must be reported: it is invisible in
    // the membership this cycle, and by the cycle it becomes visible the whole fleet has drained.
    assert!(
        !outage_observed,
        "an unreadable index must read as a failed observation, so the edge is logged and \
         `healthproxy_reports_timestamp_seconds` stops advancing while the reports are bridged"
    );
}

/// An index that answers but cannot be USED is the same failed observation as one that never
/// answers. It is the more dangerous shape of the two: a 200 error page from a CDN, a truncated
/// object, or a writer one release ahead parses to nothing, every node falls back to its cached
/// report, and once those age out the ENTIRE inventory is programmed out of the backend set. If
/// that flattened to "nobody has a report", the only trace would be one `reports_stale_total`
/// increment per node — indistinguishable from a fleet that genuinely stopped heartbeating.
#[tokio::test]
async fn an_unusable_fleet_index_reads_as_a_failed_observation_not_an_empty_fleet() {
    updated::tls::install_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut scratch = [0u8; 1024];
                let _ = sock.read(&mut scratch).await;
                let body = "<html>504 Gateway Timeout</html>";
                let _ = sock
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
                let _ = sock.shutdown().await;
            });
        }
    });
    let mut cache = updated_healthproxy::LastKnownGood::new();
    let (members, observed) = resolve_members(
        &reqwest::Client::new(),
        &format!("http://{addr}"),
        &inventory(&[("agent-0", "10.0.0.1")]),
        std::time::Duration::from_secs(2),
        &mut cache,
    )
    .await;
    assert!(
        !observed,
        "an index body that does not parse is not an observation of the fleet"
    );
    assert!(
        !members[0].ready,
        "…and with no cached report the node still fails closed"
    );
}

/// A reader configured for one node must not download all active shards. That would preserve the
/// monolith's full-fleet read amplification under a different object layout and make the shard
/// knob a latency multiplier for small consumers.
#[tokio::test]
async fn a_subset_reader_fetches_only_its_nodes_shard() {
    updated::tls::install_crypto_provider();
    let cdn = spawn_cdn(
        (0..64)
            .map(|index| (format!("agent-{index}"), true))
            .collect(),
    )
    .await;
    let base = format!("http://{}", cdn.address);
    let mut cache = updated_healthproxy::LastKnownGood::new();
    let (members, _) = resolve_members(
        &reqwest::Client::new(),
        &base,
        &inventory(&[("agent-0", "10.0.0.1")]),
        std::time::Duration::from_secs(2),
        &mut cache,
    )
    .await;
    assert!(members[0].ready);

    let requests = cdn.requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        2,
        "a one-node inventory reads exactly the stable index and one canonical shard: {requests:?}"
    );
    assert!(requests.contains(&format!("/{FLEET_INDEX_OBJECT_KEY}")));
}

/// A readable index over unreadable SHARDS is not an observation of the fleet. Readiness is read
/// from the shards, and the writer commits every shard of a generation before the index that names
/// it, so a readable index whose shards all fail — a swept or negative-cached per-generation
/// prefix, an ACL on it, a half-published generation — is a broken read, not a fleet that stopped
/// heartbeating. Counted as an observation it did the damage the flag exists to prevent, one object
/// lower down: every node resolves through its cached report, the whole inventory drains one
/// freshness window later, and meanwhile no edge is logged and
/// `healthproxy_reports_timestamp_seconds` keeps advancing as if the reports were being read.
#[tokio::test]
async fn a_generation_whose_every_shard_fails_is_not_an_observation() {
    updated::tls::install_crypto_provider();
    let cdn = spawn_cdn(vec![("agent-0".into(), true)]).await;
    let base = format!("http://{}", cdn.address);
    let inventory = inventory(&[("agent-0", "10.0.0.1")]);
    let client = reqwest::Client::new();
    let timeout = std::time::Duration::from_secs(2);
    let mut cache = updated_healthproxy::LastKnownGood::new();

    let (members, observed) =
        resolve_members(&client, &base, &inventory, timeout, &mut cache).await;
    assert!(observed && members[0].ready);

    // The index still serves; every shard it names is gone.
    for (path, _) in &cdn.shards {
        cdn.fail(path, Fault::Missing);
    }
    let (members, observed) =
        resolve_members(&client, &base, &inventory, timeout, &mut cache).await;
    assert!(
        !observed,
        "an index whose every selected shard failed is a failed observation, so the edge is logged \
         and `healthproxy_reports_timestamp_seconds` stops advancing while the reports are bridged"
    );
    assert!(
        members[0].ready,
        "…and readiness is bridged from the last observed report meanwhile, exactly as an \
         unreadable index is"
    );
}

/// `health_timeout` is the operator's PER-FETCH budget — what its CRD field and env var have always
/// said — not one budget for the whole fan-out. Spanning the pass, it threw away partial progress:
/// a single hung shard voided the cycle's observation and dropped EVERY node to last-known-good,
/// contradicting the partial-observation rule the reader is built on (missing shards resolve
/// through last-known-good for THEIR nodes only) and turning one slow object into a fleet-wide
/// drain once those cached reports aged out.
#[tokio::test]
async fn one_hung_shard_costs_its_own_budget_and_leaves_the_other_shards_observed() {
    updated::tls::install_crypto_provider();
    let cdn = spawn_cdn(
        (0..8)
            .map(|index| (format!("agent-{index}"), true))
            .collect(),
    )
    .await;
    // A node the writer placed in a different shard than agent-0, so the reader selects two shards
    // and one of them can be hung without touching the other.
    let elsewhere = (1..8)
        .map(|index| format!("agent-{index}"))
        .find(|node| cdn.shard_path_of(node) != cdn.shard_path_of("agent-0"))
        .expect("eight nodes over the default shard count are not all in one shard");
    cdn.fail(&cdn.shard_path_of(&elsewhere), Fault::Hang);

    let mut cache = updated_healthproxy::LastKnownGood::new();
    let (members, observed) = resolve_members(
        &reqwest::Client::new(),
        &format!("http://{}", cdn.address),
        &inventory(&[("agent-0", "10.0.0.1"), (&elsewhere, "10.0.0.2")]),
        std::time::Duration::from_secs(1),
        &mut cache,
    )
    .await;
    assert!(
        observed,
        "the index and one shard were read: the cycle observed the fleet, partially"
    );
    assert!(
        members[0].ready,
        "the node whose shard was read is judged from this cycle's report, not dropped because \
         another shard hung"
    );
    assert!(
        !members[1].ready,
        "the node whose shard hung has no observation and no cached report, so it fails closed"
    );
}
