use super::*;

use axum::http::Request;
use object_store::memory::InMemory;
use tower::ServiceExt;

#[derive(Debug)]
struct TestSigner {
    result: Result<reqwest::Url, &'static str>,
    calls: std::sync::Mutex<Vec<(Method, ObjectPath, Duration)>>,
}

#[async_trait::async_trait]
impl Signer for TestSigner {
    async fn signed_url(
        &self,
        method: Method,
        path: &ObjectPath,
        expires_in: Duration,
    ) -> object_store::Result<reqwest::Url> {
        self.calls
            .lock()
            .unwrap()
            .push((method, path.clone(), expires_in));
        self.result
            .clone()
            .map_err(|message| object_store::Error::Generic {
                store: "test signer",
                source: std::io::Error::other(message).into(),
            })
    }
}

fn test_signer() -> Arc<dyn Signer> {
    Arc::new(TestSigner {
        result: Ok(reqwest::Url::parse(
            "https://objects.example/test-object?test-signature=secret",
        )
        .unwrap()),
        calls: std::sync::Mutex::new(Vec::new()),
    })
}

#[derive(Debug, Default)]
struct TestUploadSigner {
    calls: std::sync::Mutex<Vec<(ObjectPath, usize, Duration)>>,
}

#[async_trait::async_trait]
impl crate::runtime::UploadSigner for TestUploadSigner {
    async fn signed_upload(
        &self,
        key: &ObjectPath,
        max_bytes: usize,
        expires_in: Duration,
    ) -> Result<updated_contracts::dataflow::UploadCapability, crate::runtime::StorageError> {
        self.calls
            .lock()
            .unwrap()
            .push((key.clone(), max_bytes, expires_in));
        Ok(updated_contracts::dataflow::UploadCapability {
            schema: updated_contracts::dataflow::UploadCapability::SCHEMA,
            url: "https://objects.example/fleet/".into(),
            fields: updated_contracts::dataflow::testing::presigned_post_fields(key.as_ref()),
        })
    }
}

fn test_upload_signer() -> Arc<dyn crate::runtime::UploadSigner> {
    Arc::new(TestUploadSigner::default())
}

fn renewal_agent(
    kind: crate::AgentIdentityKind,
    repository: &str,
    public_key: Option<&str>,
) -> crate::UpdateAgent {
    crate::UpdateAgent::new(
        "node-a",
        crate::UpdateAgentSpec {
            repository_ref: crate::LocalObjectReference {
                name: repository.into(),
            },
            identity: crate::AgentIdentity {
                kind,
                registration_sha256: (kind == crate::AgentIdentityKind::Enrolled)
                    .then(|| updated_contracts::digest::sha256_bytes(b"node-a")),
                public_key: public_key.map(str::to_owned),
            },
            labels: Default::default(),
            backend_address: None,
            hold: false,
            cordon: false,
        },
    )
}

/// The key a test node's leaf certifies, hex as `peer_identity` encodes it. Real on-curve
/// points (the P-256 generator and its double): a pinned identity is admitted through the same
/// gate production uses, so a fabricated `04`-prefixed string would be refused here exactly as
/// it is in the field.
const TEST_LEAF_KEY: &str =
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
const TEST_OTHER_LEAF_KEY: &str =
    "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";
const TEST_REPOSITORY: &str = "prod";

fn node_leaf(repository: &str, node: &str) -> ClientIdentity {
    node_leaf_keyed(repository, node, TEST_LEAF_KEY)
}

fn node_identity(node: &str) -> ClientIdentity {
    node_leaf(TEST_REPOSITORY, node)
}

/// A minted node leaf certifying `public_key` — the previous holder of a re-enrolled name holds
/// a leaf identical to the replacement's but for this.
fn node_leaf_keyed(repository: &str, node: &str, public_key: &str) -> ClientIdentity {
    ClientIdentity {
        common_name: Some(node.into()),
        node: Some(crate::join::NodeSpiffeId {
            repository: repository.into(),
            node: node.into(),
        }),
        public_key: Some(public_key.into()),
    }
}

#[test]
fn a_node_leaf_authorizes_only_within_the_repository_it_was_minted_for() {
    // The fleet CA is shared across the repositories in a namespace, so `staging`'s leaf is a
    // perfectly valid, CA-verified certificate on `prod`'s listener. Only the SAN's scope
    // distinguishes them; dropping it let staging's `web-01` read production `web-01`'s secrets
    // and overwrite its telemetry.
    let staging = node_leaf("staging", "web-01");
    assert_eq!(staging.node_in("staging"), Some("web-01"));
    assert_eq!(staging.node_in("prod"), None);
}

#[test]
fn capability_authorization_memo_is_keyed_by_leaf_and_strictly_bounded() {
    let memo = AuthorizationMemo::default();
    let now = tokio::time::Instant::now();
    let current = node_leaf_keyed(TEST_REPOSITORY, "node-a", "key-a");
    let replacement = node_leaf_keyed(TEST_REPOSITORY, "node-a", "key-b");
    let assignment = AuthorizedAssignment {
        assignment_sha256: "a".repeat(64),
        input_object_sha256: Some("b".repeat(64)),
    };
    memo.insert("node-a", &current, assignment.clone(), now);
    assert_eq!(
        memo.get("node-a", &current, Some(&"a".repeat(64)), now),
        Some(assignment)
    );
    assert_eq!(
        memo.get("node-a", &current, Some(&"c".repeat(64)), now),
        None,
        "a request for a newly verified assignment bypasses a predecessor memo"
    );
    assert_eq!(memo.get("node-a", &replacement, None, now), None);
    assert_eq!(
        memo.get("node-a", &current, None, now + AUTHORIZATION_MEMO_TTL),
        None,
        "the boundary itself is expired"
    );
}

#[test]
fn the_bootstrap_certificate_is_a_node_in_no_repository() {
    let bootstrap = ClientIdentity {
        common_name: Some("updated-enrollment".into()),
        node: None,
        public_key: Some(TEST_LEAF_KEY.into()),
    };
    assert_eq!(bootstrap.node_in("prod"), None);
    assert!(is_enrollment_identity(&bootstrap, "updated-enrollment"));
    // A minted node leaf never regains enrollment authority by taking the bootstrap CN.
    assert!(!is_enrollment_identity(
        &node_leaf("prod", "updated-enrollment"),
        "updated-enrollment"
    ));
}

#[test]
fn a_spiffe_uri_round_trips_and_rejects_a_prefix_only_uri() {
    let identity = crate::join::NodeSpiffeId {
        repository: "prod".into(),
        node: "web-01".into(),
    };
    assert_eq!(
        crate::join::NodeSpiffeId::parse(&identity.uri()),
        Some(identity)
    );
    // The old gate accepted any URI carrying the trust-domain prefix, which names neither a
    // repository nor a node.
    for uri in [
        "spiffe://updated.fleet/scope/",
        "spiffe://updated.fleet/scope/prod",
        "spiffe://updated.fleet/scope//node/web-01",
        "spiffe://updated.fleet/scope/prod/node/",
        "spiffe://elsewhere/scope/prod/node/web-01",
    ] {
        assert_eq!(
            crate::join::NodeSpiffeId::parse(uri),
            None,
            "{uri} must not parse as a node identity"
        );
    }
}

#[test]
fn renewal_requires_a_provisioned_agent_repository_and_pinned_key() {
    let enrolled = renewal_agent(
        crate::AgentIdentityKind::Enrolled,
        "repo",
        Some(TEST_LEAF_KEY),
    );
    assert!(is_pinned_identity(&enrolled, "repo", TEST_LEAF_KEY));
    assert!(!is_pinned_identity(&enrolled, "other", TEST_LEAF_KEY));
    assert!(!is_pinned_identity(&enrolled, "repo", TEST_OTHER_LEAF_KEY));
    assert!(is_pinned_identity(
        &renewal_agent(
            crate::AgentIdentityKind::Manual,
            "repo",
            Some(TEST_LEAF_KEY)
        ),
        "repo",
        TEST_LEAF_KEY
    ));
    assert!(!is_pinned_identity(
        &renewal_agent(crate::AgentIdentityKind::Enrolled, "repo", None),
        "repo",
        TEST_LEAF_KEY
    ));
}

#[test]
fn identity_lookup_distinguishes_revocation_from_control_plane_failure() {
    let api_error = |code| {
        kube::Error::Api(kube::core::ErrorResponse {
            status: "Failure".into(),
            message: "synthetic".into(),
            reason: "synthetic".into(),
            code,
        })
    };
    assert_eq!(
        identity_object::<()>(Err(api_error(404))).unwrap_err(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        identity_object::<()>(Err(api_error(500))).unwrap_err(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(identity_object::<_>(Ok("live")).is_ok());
}

#[tokio::test]
async fn a_deleting_repository_grants_no_fresh_authority() {
    let mut repository = crate::UpdateRepository::new(TEST_REPOSITORY, crate::tests::repository());
    repository.metadata.deletion_timestamp = Some(
        k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(chrono::Utc::now()),
    );
    let client = crate::tests::apiserver(move |method, path, _| {
        assert_eq!(method, Method::GET);
        assert_eq!(
            path,
            "/apis/updated.dev/v1alpha1/namespaces/default/updaterepositories/prod"
        );
        (StatusCode::OK, serde_json::to_value(&repository).unwrap())
    });
    let authority = IdentityAuthority {
        client,
        namespace: Arc::from("default"),
        repository: Arc::from(TEST_REPOSITORY),
    };
    assert_eq!(
        live_repository(&authority).await.unwrap_err(),
        StatusCode::FORBIDDEN
    );
}

/// The certificate-authenticated routes present no key in their body, so the gate reads it off
/// the connection's leaf: it must refuse exactly what renewal refuses, and never merely trust
/// that the connection authenticated.
#[test]
fn a_certificate_authenticated_route_requires_the_leaf_s_own_pinned_identity() {
    let enrolled = renewal_agent(
        crate::AgentIdentityKind::Enrolled,
        "repo",
        Some(TEST_LEAF_KEY),
    );
    assert!(is_pinned_leaf(
        &node_leaf_keyed("repo", "n", TEST_LEAF_KEY),
        &enrolled,
        "repo"
    ));
    // Re-provisioning a machine under its existing hostname deletes the `UpdateAgent` and lets
    // the replacement enroll fresh, pinning a NEW key to the SAME name. The previous holder's
    // leaf still authenticates for the rest of its 90-day life and there is no revocation path,
    // so the pin is the only thing that stops it reading the replacement's secrets, bundle and
    // telemetry slot.
    assert!(!is_pinned_leaf(
        &node_leaf_keyed("repo", "n", TEST_OTHER_LEAF_KEY),
        &enrolled,
        "repo"
    ));
    // The fleet CA is shared across repositories, so a leaf minted by another repository's
    // `/enroll` authenticates here and must still be refused this repository's material.
    assert!(!is_pinned_leaf(
        &node_leaf_keyed("repo", "n", TEST_LEAF_KEY),
        &renewal_agent(
            crate::AgentIdentityKind::Enrolled,
            "other",
            Some(TEST_LEAF_KEY)
        ),
        "repo"
    ));
    // An operator-provisioned node pins its leaf key without using online enrollment.
    assert!(is_pinned_leaf(
        &node_leaf_keyed("repo", "n", TEST_LEAF_KEY),
        &renewal_agent(
            crate::AgentIdentityKind::Manual,
            "repo",
            Some(TEST_LEAF_KEY)
        ),
        "repo"
    ));
    assert!(!is_pinned_leaf(
        &node_leaf_keyed("repo", "n", TEST_LEAF_KEY),
        &renewal_agent(crate::AgentIdentityKind::Reserved, "repo", None),
        "repo"
    ));
    // A connection with no client certificate carries no key and authorizes nothing.
    assert!(!is_pinned_leaf(
        &ClientIdentity {
            common_name: None,
            node: None,
            public_key: None,
        },
        &enrolled,
        "repo"
    ));
}

#[test]
fn manual_identity_uses_the_same_pinned_leaf_authorization_as_enrolled() {
    let leaf = node_leaf("repo", "node-a");
    let manual = renewal_agent(
        crate::AgentIdentityKind::Manual,
        "repo",
        Some(TEST_LEAF_KEY),
    );
    assert!(authorized_identity(&leaf, &manual, "repo"));
    assert!(
        !authorized_identity(&node_leaf("repo", "node-b"), &manual, "repo"),
        "a leaf cannot borrow another manual node's declaration"
    );
    assert!(
        !authorized_identity(&node_leaf("other", "node-a"), &manual, "repo"),
        "the fleet CA does not erase a leaf's repository scope"
    );

    let reserved = renewal_agent(crate::AgentIdentityKind::Reserved, "repo", None);
    assert!(
        !authorized_identity(&leaf, &reserved, "repo"),
        "a reserved name is not a provisioned machine"
    );
    let malformed_manual = renewal_agent(crate::AgentIdentityKind::Manual, "repo", None);
    assert!(
        !authorized_identity(&leaf, &malformed_manual, "repo"),
        "identity-kind field invariants fail closed"
    );
}

#[test]
fn enrolled_identity_can_read_and_write_only_while_its_key_is_pinned() {
    let leaf = node_leaf("repo", "node-a");
    let enrolled = renewal_agent(
        crate::AgentIdentityKind::Enrolled,
        "repo",
        Some(TEST_LEAF_KEY),
    );
    assert!(authorized_identity(&leaf, &enrolled, "repo"));
    assert!(!authorized_identity(
        &node_leaf_keyed("repo", "node-a", TEST_OTHER_LEAF_KEY),
        &enrolled,
        "repo"
    ));
    let mut forged_registration = enrolled;
    forged_registration.spec.identity.registration_sha256 = Some("a".repeat(64));
    assert!(
        !authorized_identity(&leaf, &forged_registration, "repo"),
        "the enrollment digest has one meaning: SHA-256(node name)"
    );
}

#[test]
fn only_an_explicitly_reserved_name_may_be_completed_by_enrollment() {
    // `/enroll` authenticates with the fleet-wide bootstrap certificate, so any agent this
    // predicate accepts is claimable by whichever fleet member asks first — along with its
    // labels, and hence its group and deployment. Only an explicit reservation qualifies.
    let desired = renewal_agent(
        crate::AgentIdentityKind::Enrolled,
        "repo",
        Some(TEST_LEAF_KEY),
    );
    let deferred = |kind| {
        let mut agent = renewal_agent(kind, "repo", None);
        agent.spec.identity.registration_sha256 = None;
        agent
    };
    assert!(adopts_preapproval(
        &deferred(crate::AgentIdentityKind::Reserved),
        &desired
    ));
    assert!(
        !adopts_preapproval(&deferred(crate::AgentIdentityKind::Manual), &desired),
        "a declared manual agent is the offline path, not a hijackable reservation: adopting \
         it would let any holder of the shared fleet certificate claim an operator-declared \
         name before that machine is ever built, and read its secrets"
    );
    let mut already_identified = deferred(crate::AgentIdentityKind::Reserved);
    already_identified.spec.identity.public_key = Some("key".into());
    assert!(
        !adopts_preapproval(&already_identified, &desired),
        "an agent that already has a pinned key is never re-adopted"
    );
    let mut other_repository = deferred(crate::AgentIdentityKind::Reserved);
    other_repository.spec.repository_ref.name = "other".into();
    assert!(!adopts_preapproval(&other_repository, &desired));
    let mut established = deferred(crate::AgentIdentityKind::Reserved);
    established.spec.identity.registration_sha256 = Some("registration".into());
    assert!(!adopts_preapproval(&established, &desired));
}

#[test]
fn enrollment_stops_at_the_repositorys_agent_ceiling() {
    // `/enroll` is authorized by the fleet-wide bootstrap certificate and the node names
    // itself, so unbounded creation let one caller grow the durable rollout state past the
    // apiserver's object limit — after which NO generation publishes again, for any node.
    let ceiling = updated_contracts::backend::MAX_BACKEND_INVENTORY_MEMBERS;
    assert!(!at_enrollment_capacity(ceiling - 1));
    assert!(at_enrollment_capacity(ceiling));
    assert!(at_enrollment_capacity(ceiling + 1));
}

#[test]
fn enrollment_lock_is_available_only_when_unheld_or_expired() {
    let now = chrono::Utc::now();
    let empty = LeaseSpec::default();
    assert!(enrollment_lock_available(&empty, now));

    let live = enrollment_lock_spec("gateway-a", now, 1);
    assert!(!enrollment_lock_available(&live, now));
    assert!(enrollment_lock_available(
        &live,
        now + chrono::Duration::seconds(i64::from(ENROLLMENT_LOCK_SECONDS))
    ));

    let mut released = live;
    assert!(release_enrollment_lock_spec(
        &mut released,
        "gateway-a",
        now
    ));
    assert_eq!(released.holder_identity, None);
    assert_eq!(
        released.lease_duration_seconds,
        Some(ENROLLMENT_LOCK_SECONDS)
    );
    assert!(enrollment_lock_available(&released, now));

    let before = released.clone();
    assert!(!release_enrollment_lock_spec(
        &mut released,
        "gateway-b",
        now
    ));
    assert_eq!(released, before);
}

fn direct_content_state(store: Arc<InMemory>, signer: Arc<dyn Signer>) -> ContentState {
    ContentState {
        destination: Arc::new(Reloadable::new(Destination {
            store,
            signer,
            upload_signer: test_upload_signer(),
            prefix: Arc::from("routing"),
        })),
    }
}

#[tokio::test]
async fn a_rebuilt_object_store_takes_effect_without_a_restart() {
    // Credentials are baked into an `ObjectStore` at construction, so a handler that captured
    // one at start-up serves a rotated key — or a one-hour STS session token — until it
    // expires and then answers 502 for the life of the process. The live router must read
    // through the reloadable, prefix included.
    let first_signer = Arc::new(TestSigner {
        result: Ok(
            reqwest::Url::parse("https://objects.example/first?test-signature=secret").unwrap(),
        ),
        calls: std::sync::Mutex::new(Vec::new()),
    });
    let destination = Arc::new(Reloadable::new(Destination {
        store: seeded().await,
        signer: first_signer.clone(),
        upload_signer: test_upload_signer(),
        prefix: Arc::from("routing"),
    }));
    let uri = "/targets/nested/app".parse().unwrap();
    assert_eq!(
        repository_redirect(&destination.get(), Method::GET, &uri)
            .await
            .status(),
        StatusCode::TEMPORARY_REDIRECT
    );
    assert_eq!(
        first_signer.calls.lock().unwrap()[0].1.as_ref(),
        "routing/targets/nested/app"
    );

    let rotated = Arc::new(InMemory::new());
    rotated
        .put(
            &ObjectPath::from("rotated/targets/nested/app"),
            PutPayload::from_static(b"rotated"),
        )
        .await
        .unwrap();
    let rotated_signer = Arc::new(TestSigner {
        result: Ok(reqwest::Url::parse(
            "https://objects.example/rotated?test-signature=rotated-secret",
        )
        .unwrap()),
        calls: std::sync::Mutex::new(Vec::new()),
    });
    destination.set(Destination {
        store: rotated,
        signer: rotated_signer.clone(),
        upload_signer: test_upload_signer(),
        prefix: Arc::from("rotated"),
    });
    assert_eq!(
        repository_redirect(&destination.get(), Method::GET, &uri)
            .await
            .status(),
        StatusCode::TEMPORARY_REDIRECT
    );
    assert_eq!(
        rotated_signer.calls.lock().unwrap()[0].1.as_ref(),
        "rotated/targets/nested/app"
    );
}

#[tokio::test]
async fn a_failed_store_rebuild_keeps_the_working_store_serving() {
    let destination = Reloadable::new(Destination {
        store: seeded().await,
        signer: test_signer(),
        upload_signer: test_upload_signer(),
        prefix: Arc::from("routing"),
    });

    // The apiserver cannot answer: a rebuild is best-effort, so the store built from the last
    // good answer keeps serving. Swapping in nothing (or a store built from a partial read)
    // would turn a transient blip into a data-plane outage — the very failure this timer is
    // here to prevent.
    let unavailable = crate::tests::apiserver(|_, _, _| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"kind": "Status", "code": 500}),
        )
    });
    rebuild_destination(&unavailable, "fleet-system", TEST_REPOSITORY, &destination).await;
    let live = destination.get();
    assert_eq!(&*live.prefix, "routing");
    assert_eq!(
        live.store
            .get(&ObjectPath::from("routing/targets/nested/app"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .to_vec(),
        b"hello".to_vec(),
    );

    // And a rebuild that succeeds replaces the destination with the managed repository's one
    // canonical namespace/name key space. There is no operator-selected prefix to drift.
    let mut repository = crate::UpdateRepository::new(TEST_REPOSITORY, crate::tests::repository());
    repository.metadata.namespace = Some("fleet-system".into());
    let available = crate::tests::apiserver(move |_, _, _| {
        (StatusCode::OK, serde_json::to_value(&repository).unwrap())
    });
    rebuild_destination(&available, "fleet-system", TEST_REPOSITORY, &destination).await;
    assert_eq!(
        &*destination.get().prefix,
        crate::runtime::managed_repository_prefix("fleet-system", TEST_REPOSITORY)
    );
}

/// A peer that stops reading any large control response cannot retain a data-listener permit
/// forever. Repository payloads redirect to S3, while exact private objects use bounded JSON
/// capabilities carrying the control-plane-authenticated byte digest.
#[tokio::test(start_paused = true)]
async fn a_client_that_stops_reading_cannot_hold_a_connection_past_the_deadline() {
    use tokio::io::AsyncWriteExt as _;

    let app = Router::new().route(
        "/big",
        axum::routing::get(|| async { Body::from(vec![7u8; 1 << 20]) }),
    );
    let (mut client, server) = tokio::io::duplex(4 * 1024);
    let served = tokio::spawn(serve_http(TokioIo::new(server), app, CONNECTION_TIMEOUT));
    client
        .write_all(b"GET /big HTTP/1.1\r\nHost: gateway\r\n\r\n")
        .await
        .unwrap();

    // Never read the response, and never close: the peer is simply gone.
    tokio::time::timeout(CONNECTION_TIMEOUT + Duration::from_secs(60), served)
        .await
        .expect("the connection must be dropped at its deadline")
        .unwrap();
    drop(client);
}

/// The plaintext listener's permits are exactly as exhaustible as the data listener's, and it
/// is the one nobody has to authenticate to. A peer that sends a complete probe request and
/// then stops reading leaves hyper blocked mid-write with no header-read timer armed, so only
/// the overall deadline releases the permit. At the data plane's 30 minutes,
/// [`HEALTH_CONNECTIONS`] sockets and no credentials stop `serve_plain` from accepting — and
/// the chart points both the readiness and the liveness probe at this port, so the kubelet
/// then kills the gateway and the enrollment control plane goes with it.
#[tokio::test(start_paused = true)]
async fn a_wedged_health_connection_is_released_on_the_health_listeners_own_deadline() {
    use tokio::io::AsyncWriteExt as _;

    // Smaller than one probe response, so hyper is left blocked mid-write with the request
    // head already parsed.
    let (mut client, server) = tokio::io::duplex(64);
    let served = tokio::spawn(serve_http(
        TokioIo::new(server),
        health_router(),
        HEALTH_CONNECTION_TIMEOUT,
    ));
    client
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: gateway\r\n\r\n")
        .await
        .unwrap();

    let started = tokio::time::Instant::now();
    tokio::time::timeout(HEALTH_CONNECTION_TIMEOUT + Duration::from_secs(5), served)
        .await
        .expect("a wedged probe connection must end on the health listener's own deadline")
        .unwrap();
    assert!(
        started.elapsed() < CONNECTION_TIMEOUT,
        "the health listener must not inherit the release-download deadline"
    );
    drop(client);
}

async fn seeded() -> Arc<InMemory> {
    let store = Arc::new(InMemory::new());
    store
        .put(
            &ObjectPath::from("routing/targets/nested/app"),
            PutPayload::from_static(b"hello"),
        )
        .await
        .unwrap();
    // A zero-length object: a published target may legitimately be empty, and it is the one
    // length at which a suffix range has nothing to place.
    store
        .put(
            &ObjectPath::from("routing/targets/nested/empty"),
            PutPayload::from_static(b""),
        )
        .await
        .unwrap();
    store
}

fn get_as(path: &str, range: Option<&str>, identity: ClientIdentity) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(range) = range {
        builder = builder.header("range", range);
    }
    let mut request = builder.body(Body::empty()).unwrap();
    request.extensions_mut().insert(identity);
    request
}

#[tokio::test]
async fn immutable_targets_redirect_through_the_configured_signer() {
    let store = seeded().await;
    store
        .put(
            &ObjectPath::from("routing/targets/assignments/configs/config-sha.json"),
            PutPayload::from_static(b"shared config"),
        )
        .await
        .unwrap();
    let signer = Arc::new(TestSigner {
        result: Ok(reqwest::Url::parse(
            "https://objects.example/updates/routing/targets/nested/app?X-Amz-Signature=redacted",
        )
        .unwrap()),
        calls: std::sync::Mutex::new(Vec::new()),
    });
    let state = direct_content_state(store, signer.clone());
    let response = repository_redirect(
        &state.destination(),
        Method::GET,
        &"/targets/nested/app".parse().unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        response.headers()[header::LOCATION],
        "https://objects.example/updates/routing/targets/nested/app?X-Amz-Signature=redacted"
    );
    assert_eq!(
        response.headers()[header::CACHE_CONTROL],
        "private, no-store"
    );
    {
        let calls = signer.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, Method::GET);
        assert_eq!(calls[0].1.as_ref(), "routing/targets/nested/app");
        assert_eq!(calls[0].2, OBJECT_CAPABILITY_TTL);
    }

    let response = repository_redirect(
        &state.destination(),
        Method::GET,
        &"/targets/assignments/configs/config-sha.json"
            .parse()
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let calls = signer.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[1].1.as_ref(),
        "routing/targets/assignments/configs/config-sha.json"
    );
}

#[tokio::test]
async fn bootstrap_and_cross_repository_leaves_cannot_mint_repository_capabilities() {
    let signer = Arc::new(TestSigner {
        result: Ok(
            reqwest::Url::parse("https://objects.example/object?X-Amz-Signature=redacted").unwrap(),
        ),
        calls: std::sync::Mutex::new(Vec::new()),
    });
    let app = Router::new()
        .route("/targets/{*rest}", axum::routing::get(repo_get))
        .with_state(AuthorizationState {
            content: direct_content_state(seeded().await, signer.clone()),
            memo: Arc::new(AuthorizationMemo::default()),
            identity: IdentityAuthority {
                client: crate::tests::apiserver(|_, _, _| {
                    panic!("a certificate outside this repository reached the apiserver")
                }),
                namespace: Arc::from("default"),
                repository: Arc::from(TEST_REPOSITORY),
            },
        });
    let bootstrap = ClientIdentity {
        common_name: Some("updated-enrollment".into()),
        node: None,
        public_key: Some(TEST_LEAF_KEY.into()),
    };
    for identity in [bootstrap, node_leaf("another-repository", "node-a")] {
        let response = app
            .clone()
            .oneshot(get_as("/targets/nested/app", None, identity))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    assert!(
        signer.calls.lock().unwrap().is_empty(),
        "an unauthorized certificate reached the S3 signer"
    );
}

#[tokio::test]
async fn a_superseded_leaf_cannot_mint_repository_capabilities() {
    let signer = Arc::new(TestSigner {
        result: Ok(
            reqwest::Url::parse("https://objects.example/object?X-Amz-Signature=redacted").unwrap(),
        ),
        calls: std::sync::Mutex::new(Vec::new()),
    });
    let replacement = renewal_agent(
        crate::AgentIdentityKind::Enrolled,
        TEST_REPOSITORY,
        Some(TEST_OTHER_LEAF_KEY),
    );
    let client = crate::tests::apiserver(move |method, path, _| {
        assert_eq!(method, Method::GET);
        assert_eq!(
            path,
            "/apis/updated.dev/v1alpha1/namespaces/default/updateagents/node-a"
        );
        (StatusCode::OK, serde_json::to_value(&replacement).unwrap())
    });
    let app = Router::new()
        .route("/targets/{*rest}", axum::routing::get(repo_get))
        .with_state(AuthorizationState {
            content: direct_content_state(seeded().await, signer.clone()),
            memo: Arc::new(AuthorizationMemo::default()),
            identity: IdentityAuthority {
                client,
                namespace: Arc::from("default"),
                repository: Arc::from(TEST_REPOSITORY),
            },
        });

    let response = app
        .oneshot(get_as(
            "/targets/nested/app",
            None,
            node_leaf(TEST_REPOSITORY, "node-a"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        signer.calls.lock().unwrap().is_empty(),
        "a superseded certificate reached the S3 signer"
    );
}

#[tokio::test]
async fn every_repository_read_requires_a_signed_s3_capability() {
    let store = seeded().await;
    store
        .put(
            &ObjectPath::from("routing/targets/assignments/agents/node.json"),
            PutPayload::from_static(b"assignment"),
        )
        .await
        .unwrap();
    let signer = Arc::new(TestSigner {
        result: Err("signing unavailable"),
        calls: std::sync::Mutex::new(Vec::new()),
    });
    let state = direct_content_state(store, signer.clone());
    let response = repository_redirect(
        &state.destination(),
        Method::GET,
        &"/targets/assignments/agents/node.json".parse().unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        signer.calls.lock().unwrap()[0].1.as_ref(),
        "routing/targets/assignments/agents/node.json"
    );

    let response = repository_redirect(
        &state.destination(),
        Method::HEAD,
        &"/targets/nested/app".parse().unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        signer.calls.lock().unwrap()[1].1.as_ref(),
        "routing/targets/nested/app"
    );
}

#[tokio::test]
async fn signer_output_must_satisfy_the_shared_capability_url_grammar() {
    for invalid in [
        "http://objects.example/object?signature=secret",
        "https://user@objects.example/object?signature=secret",
        "https://objects.example/object?signature=secret#fragment",
    ] {
        let signer = Arc::new(TestSigner {
            result: Ok(reqwest::Url::parse(invalid).unwrap()),
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let state = direct_content_state(Arc::new(InMemory::new()), signer);
        let result = signed_object_url(
            &state.destination(),
            Method::GET,
            &ObjectPath::from("routing/metadata/root.json"),
        )
        .await;
        assert_eq!(result.unwrap_err(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[tokio::test]
async fn enrollment_authorizes_only_the_controller_published_exact_object() {
    let signer = Arc::new(TestSigner {
        result: Ok(reqwest::Url::parse(
            "https://objects.example/enrollment?X-Amz-Signature=redacted",
        )
        .unwrap()),
        calls: std::sync::Mutex::new(Vec::new()),
    });
    let state = direct_content_state(Arc::new(InMemory::new()), signer.clone());
    let mut agent = renewal_agent(
        crate::AgentIdentityKind::Enrolled,
        TEST_REPOSITORY,
        Some(TEST_LEAF_KEY),
    );
    let relative = format!(
        "enrollments/{}/{}/{}.json",
        updated_contracts::digest::sha256_bytes(b"node-a"),
        "a".repeat(64),
        "b".repeat(64)
    );
    agent.status = Some(crate::UpdateAgentStatus {
        enrollment_object_key: Some(relative.clone()),
        ..Default::default()
    });

    let capability = enrollment_download_capability(&state, &agent)
        .await
        .unwrap();
    capability.validate().unwrap();
    assert_eq!(capability.sha256, "b".repeat(64));
    {
        let calls = signer.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, Method::GET);
        assert_eq!(calls[0].1, crate::object_key("routing", &relative));
        assert_eq!(calls[0].2, OBJECT_CAPABILITY_TTL);
    }

    agent.status.as_mut().unwrap().enrollment_object_key = Some(format!(
        "enrollments/{}/{}/{}.json",
        updated_contracts::digest::sha256_bytes(b"another-node"),
        "a".repeat(64),
        "b".repeat(64)
    ));
    assert_eq!(
        enrollment_download_capability(&state, &agent)
            .await
            .unwrap_err(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        signer.calls.lock().unwrap().len(),
        1,
        "a malformed or foreign status pointer must never reach the signer"
    );
}

/// A resolved chain for one agent of the generation `timestamp` names. Each call builds its own
/// `SignedMetadata`, exactly as a per-request resolve does.
fn enrollment(timestamp: &str, agent: &str) -> SignedEnrollment {
    SignedEnrollment {
        metadata: std::sync::Arc::new(SignedMetadata {
            root: "root".into(),
            timestamp: timestamp.into(),
            snapshot: "snapshot".into(),
            // Stands in for the real thing, which carries one signed entry per published agent.
            targets: "targets".into(),
        }),
        agent_document: agent.into(),
        managed_configuration: "config".into(),
    }
}

/// The generation's role documents are held ONCE, however many agents are cached against it.
/// `targets.json` has an entry per published agent, so a per-agent copy made the cache
/// O(fleet²) bytes — ~15 GB at `MAX_BACKEND_INVENTORY_MEMBERS`, and the gateway was OOM-killed at the
/// fleet size it documents, in exactly the steady state (no publishes, so no eviction) the cache
/// is for.
#[test]
fn one_generations_metadata_is_stored_once_however_many_agents_are_cached() {
    let cache = VerifiedEnrollments {
        inner: std::sync::Mutex::new(Generation::default()),
    };
    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::hours(1);
    let generation = generation_key("routing", "anchor", "timestamp-1");
    for index in 0..64 {
        let path = format!("assignments/agents/node-{index}.json");
        // Each agent resolves its own copy of the chain, as a real request does.
        cache.insert(
            &generation,
            &path,
            &enrollment("timestamp-1", "agent"),
            expires,
        );
    }
    let guard = cache.lock();
    assert_eq!(guard.entries.len(), 64);
    assert_eq!(
        std::sync::Arc::strong_count(guard.metadata.as_ref().unwrap()),
        1,
        "the cache holds exactly one copy of the generation's role documents"
    );
}

/// A full TUF verification is per-request asymmetric-crypto work at a rate the fleet's polling
/// interval multiplies, so it is memoized — but only for exactly as long as the generation it
/// verified is the published one AND that generation's chain is unexpired. A publish re-signs
/// `timestamp`, which is part of the key, so a new generation can neither hit an old entry nor
/// leave one behind; and once the chain expires the memo stops answering, so the serving path
/// goes back through the verifier that refuses it.
#[test]
fn a_verified_enrollment_is_memoized_only_within_one_unexpired_generation() {
    let cache = VerifiedEnrollments {
        inner: std::sync::Mutex::new(Generation::default()),
    };
    let chain = enrollment("timestamp-1", "agent");
    let path = "assignments/agents/node.json";
    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::hours(1);
    let first = generation_key("routing", "anchor", "timestamp-1");
    assert!(cache.get(&first, path, now).is_none());
    cache.insert(&first, path, &chain, expires);
    assert_eq!(
        cache.get(&first, path, now).unwrap().agent_document,
        "agent"
    );
    assert!(
        cache.get(&first, path, expires).is_none(),
        "a publisher that stops re-signing must not keep an expired chain servable: at the \
         expiry the memo stops answering and the full verifier refuses it again"
    );

    let republished = generation_key("routing", "anchor", "timestamp-2");
    assert!(
        cache.get(&republished, path, now).is_none(),
        "a new generation must never be served an older verification"
    );
    cache.insert(
        &republished,
        "assignments/agents/other.json",
        &chain,
        expires,
    );
    assert!(
        cache.get(&republished, path, now).is_none(),
        "and the previous generation's entries are dropped, not left to accumulate"
    );
    // The trust anchor and the repository prefix are part of the identity of a generation: a
    // chain verified for one must never satisfy a lookup for another.
    assert_ne!(generation_key("other", "anchor", "timestamp-1"), first);
    assert_ne!(generation_key("routing", "other", "timestamp-1"), first);
}

/// The cached generation expires at the EARLIEST of its four role expiries — the instant the
/// verifier itself would start rejecting the chain — and a chain whose expiries cannot be read
/// is not cacheable at all.
#[test]
fn a_generations_cache_lifetime_is_its_earliest_role_expiry() {
    let role = |expires: &str| {
        serde_json::json!({"signed": {"expires": expires}, "signatures": []}).to_string()
    };
    let chain = SignedMetadata {
        root: role("2030-01-01T00:00:00Z"),
        timestamp: role("2027-03-04T05:06:07Z"),
        snapshot: role("2029-01-01T00:00:00Z"),
        targets: role("2028-01-01T00:00:00Z"),
    };
    assert_eq!(
        chain_expiry(&chain).unwrap().to_rfc3339(),
        "2027-03-04T05:06:07+00:00"
    );
    let unreadable = SignedMetadata {
        snapshot: "not json".into(),
        ..chain
    };
    assert!(
        chain_expiry(&unreadable).is_none(),
        "an unreadable expiry makes the chain uncacheable, never cacheable forever"
    );
}

#[test]
fn enrollment_resolves_consistent_snapshot_target_objects() {
    let digest = "a".repeat(64);
    let metadata = serde_json::json!({
        "signed": {"targets": {
            "assignments/agents/node.json": {"hashes": {"sha256": digest}}
        }}
    });
    assert_eq!(
        consistent_target_object(&metadata, "assignments/agents/node.json"),
        Some(format!(
            "targets/{}.assignments/agents/node.json",
            "a".repeat(64)
        ))
    );
    assert_eq!(consistent_target_object(&metadata, "missing"), None);
}

#[test]
fn only_the_configured_bootstrap_identity_can_enroll() {
    let bootstrap = |cn: &str| ClientIdentity {
        common_name: Some(cn.to_owned()),
        node: None,
        public_key: Some(TEST_LEAF_KEY.into()),
    };
    assert!(is_enrollment_identity(
        &bootstrap("updated-agent"),
        "updated-agent"
    ));
    assert!(!is_enrollment_identity(
        &bootstrap("ordinary-node"),
        "updated-agent"
    ));
    assert!(!is_enrollment_identity(
        &ClientIdentity {
            common_name: None,
            node: None,
            public_key: None,
        },
        "updated-agent"
    ));
    assert!(!is_enrollment_identity(&bootstrap(""), ""));
    // A minted per-node leaf can never regain enrollment authority by taking the bootstrap CN.
    assert!(!is_enrollment_identity(
        &node_identity("updated-agent"),
        "updated-agent"
    ));
    assert!(is_distinct_from_bootstrap_identity(
        "agent-7",
        "updated-agent"
    ));
    assert!(!is_distinct_from_bootstrap_identity(
        "updated-agent",
        "updated-agent"
    ));
}

/// The mirror image of the enrollment gate: only a minted per-node leaf resolves to a node.
#[test]
fn only_a_minted_node_leaf_carries_steady_state_authority() {
    assert_eq!(
        node_identity("agent-7").node_in(TEST_REPOSITORY),
        Some("agent-7")
    );
    assert_eq!(
        ClientIdentity {
            common_name: Some("updated-agent".into()),
            node: None,
            public_key: Some(TEST_LEAF_KEY.into()),
        }
        .node_in(TEST_REPOSITORY),
        None
    );
}
