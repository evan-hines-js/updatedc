//! The single-writer lease. Exactly one `updatec controller` publishes for a repository at a time;
//! everything else in this runtime assumes the holder is this process.

use super::*;

/// Different repositories have independent publishers even when they share a namespace.
/// A fixed-length digest also handles maximum-length Kubernetes repository names.
pub fn publisher_lease_name(repository: &str) -> String {
    let digest = updated_contracts::digest::sha256_bytes(repository.as_bytes());
    format!("updatec-publisher-{}", &digest[..32])
}

pub async fn acquire_or_renew_publisher_lease(
    client: Client,
    namespace: &str,
    repository: &str,
    identity: &str,
) -> Result<bool, kube::Error> {
    acquire_or_renew_lease(
        client,
        namespace,
        &publisher_lease_name(repository),
        identity,
    )
    .await
}

pub(crate) async fn holds_publisher_lease(
    client: &Client,
    namespace: &str,
    repository: &str,
    identity: &str,
) -> Result<bool, kube::Error> {
    holds_lease(
        client,
        namespace,
        &publisher_lease_name(repository),
        identity,
    )
    .await
}

/// The elected publisher additionally owns the shared state volume. Keep this lock for the
/// entire leadership epoch, and terminate the process on lease loss BEFORE dropping it:
/// cancelling an async reconcile does not stop its already-running blocking filesystem work.
pub fn acquire_publisher_state(state_dir: &Path) -> std::io::Result<updated::lock::InstanceLock> {
    updated::lock::InstanceLock::acquire(&state_dir.join("publisher.lock"))
}

/// End the writer epoch without unwinding and releasing its filesystem lock ahead of outstanding
/// writes. The kernel stops all threads and releases the lock; Kubernetes restarts the replica.
pub fn exit_publisher_epoch() -> ! {
    std::process::exit(1)
}

/// Acquire or renew the Kubernetes single-writer lease. Conflicts are ordinary follower
/// outcomes, not reconciliation failures.
pub async fn acquire_or_renew_lease(
    client: Client,
    namespace: &str,
    name: &str,
    identity: &str,
) -> Result<bool, kube::Error> {
    let leases: Api<Lease> = Api::namespaced(client, namespace);
    let now = chrono::Utc::now();
    let Some(mut lease) = leases.get_opt(name).await? else {
        let lease = Lease {
            metadata: kube::api::ObjectMeta {
                name: Some(name.into()),
                namespace: Some(namespace.into()),
                ..Default::default()
            },
            spec: Some(new_lease_spec(identity, now, 0)),
        };
        return match leases.create(&PostParams::default(), &lease).await {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(error)) if error.code == 409 => Ok(false),
            Err(error) => Err(error),
        };
    };

    let spec = lease.spec.get_or_insert_with(Default::default);
    let held_by_us = spec.holder_identity.as_deref() == Some(identity);
    if !held_by_us && !lease_expired(spec, now) {
        return Ok(false);
    }
    let transitions = spec
        .lease_transitions
        .unwrap_or_default()
        .saturating_add(i32::from(!held_by_us));
    // A renewal preserves the original `acquireTime` — per the coordination.k8s.io lease
    // contract it marks when the current holder *first* acquired, not each heartbeat. Only a
    // takeover (a different identity) stamps a fresh acquisition; `new_lease_spec` sets `now`.
    let prior_acquire = spec.acquire_time.clone();
    let mut next = new_lease_spec(identity, now, transitions);
    if held_by_us {
        if let Some(acquire) = prior_acquire {
            next.acquire_time = Some(acquire);
        }
    }
    *spec = next;
    // `lease` still carries the `resourceVersion` we read, so this PUT is a compare-and-swap: if any
    // other candidate acquired or renewed in the meantime, the apiserver rejects it with a 409 and we
    // become a follower. This serializes changes to the lease record, but cannot stop a paused
    // former holder from resuming work. The publisher's shared-state lock and process-ending
    // epoch boundary additionally fence those outstanding writes across a leader change.
    match leases.replace(name, &PostParams::default(), &lease).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(error)) if error.code == 409 => Ok(false),
        Err(error) => Err(error),
    }
}

pub(crate) fn new_lease_spec(
    identity: &str,
    now: chrono::DateTime<chrono::Utc>,
    transitions: i32,
) -> LeaseSpec {
    LeaseSpec {
        holder_identity: Some(identity.into()),
        lease_duration_seconds: Some(LEASE_SECONDS),
        acquire_time: Some(MicroTime(now)),
        renew_time: Some(MicroTime(now)),
        lease_transitions: Some(transitions),
        preferred_holder: None,
        strategy: None,
    }
}

/// Whether a Kubernetes `Lease` has lapsed: its holder stopped renewing long enough ago that the
/// lease it took no longer means anything.
///
/// The one expiry rule for every `Lease` this control plane takes — the controller's single-writer
/// publication lease and the gateway's enrollment lock. Both are the same mechanism protecting the
/// same kind of thing (only one actor may proceed), and they had byte-identical implementations in
/// two files. A change to either — clock-skew tolerance, a different reading of an absent
/// `renewTime` — would have moved one and left the other, and the two failures do not look alike:
/// the publication lease going wrong means two controllers signing generations, while the
/// enrollment lock going wrong means two machines claiming one node identity.
///
/// A missing `renewTime` reads as expired: a lease nobody has renewed is not held.
pub(crate) fn lease_expired(spec: &LeaseSpec, now: chrono::DateTime<chrono::Utc>) -> bool {
    let Some(renewed) = spec.renew_time.as_ref().map(|time| time.0) else {
        return true;
    };
    let seconds = spec.lease_duration_seconds.unwrap_or_default().max(0) as i64;
    renewed + chrono::Duration::seconds(seconds) <= now
}

/// Read-only check that `identity` still holds the lease `name` and it has not expired. Used to
/// re-verify leadership right before the irreversible S3 publish: the main loop only renews on a 5s
/// tick, and CPU-bound TUF signing can starve that past the lease deadline, so a former leader whose
/// lease was already taken over could otherwise keep uploading.
pub(crate) async fn holds_lease(
    client: &Client,
    namespace: &str,
    name: &str,
    identity: &str,
) -> Result<bool, kube::Error> {
    let leases: Api<Lease> = Api::namespaced(client.clone(), namespace);
    let Some(lease) = leases.get_opt(name).await? else {
        return Ok(false);
    };
    let Some(spec) = lease.spec else {
        return Ok(false);
    };
    Ok(spec.holder_identity.as_deref() == Some(identity)
        && !lease_expired(&spec, chrono::Utc::now()))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod lease_tests {
    use super::*;

    #[test]
    fn publisher_leases_are_repository_scoped_and_bounded() {
        assert_eq!(publisher_lease_name("first"), publisher_lease_name("first"));
        assert_ne!(
            publisher_lease_name("first"),
            publisher_lease_name("second")
        );
        let longest = publisher_lease_name(&"a".repeat(253));
        assert!(longest.len() <= 63);
        assert!(longest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
    }

    #[tokio::test]
    async fn separate_repositories_can_hold_publisher_leases_together() {
        use axum::http::{Method, StatusCode};
        let leases = Arc::new(std::sync::Mutex::new(
            BTreeMap::<String, serde_json::Value>::new(),
        ));
        let served = leases.clone();
        let client = crate::tests::apiserver(move |method, path, body| {
            let mut leases = served.lock().unwrap();
            if *method == Method::POST || *method == Method::PUT {
                let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let name = value["metadata"]["name"].as_str().unwrap().to_owned();
                leases.insert(name, value.clone());
                return (StatusCode::OK, value);
            }
            let name = path.rsplit('/').next().unwrap();
            match leases.get(name) {
                Some(value) => (StatusCode::OK, value.clone()),
                None => (
                    StatusCode::NOT_FOUND,
                    serde_json::json!({
                        "apiVersion":"v1", "kind":"Status", "status":"Failure",
                        "reason":"NotFound", "message":"lease absent", "code":404
                    }),
                ),
            }
        });
        assert!(
            acquire_or_renew_publisher_lease(client.clone(), "default", "first", "pod-a")
                .await
                .unwrap()
        );
        assert!(
            acquire_or_renew_publisher_lease(client.clone(), "default", "second", "pod-b")
                .await
                .unwrap()
        );
        assert!(holds_publisher_lease(&client, "default", "first", "pod-a")
            .await
            .unwrap());
        assert!(holds_publisher_lease(&client, "default", "second", "pod-b")
            .await
            .unwrap());
        assert!(
            !acquire_or_renew_publisher_lease(client.clone(), "default", "first", "pod-c")
                .await
                .unwrap()
        );
        assert!(
            acquire_or_renew_publisher_lease(client, "default", "first", "pod-a")
                .await
                .unwrap()
        );
    }

    #[test]
    fn publisher_epoch_exit_worker() {
        let Some(dir) = std::env::var_os("UPDATED_TEST_PUBLISHER_EPOCH") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let _lock = acquire_publisher_state(&dir).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let writes = dir.clone();
            let writer = tokio::task::spawn_blocking(move || {
                for i in 0..1000 {
                    std::fs::write(writes.join("writes"), i.to_string()).unwrap();
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            while !dir.join("writes").exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            // Model the old failure: cancelling the waiter leaves the write task alive.
            drop(writer);
            std::fs::write(dir.join("ready"), b"ready").unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while !dir.join("lose-lease").exists() && std::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            exit_publisher_epoch();
        });
    }

    #[test]
    fn a_lost_epoch_cannot_write_after_its_successor_acquires_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "runtime::lease::lease_tests::publisher_epoch_exit_worker",
                "--nocapture",
            ])
            .env("UPDATED_TEST_PUBLISHER_EPOCH", dir.path());
        let mut child = foundation::process::ContainedChild::spawn(command).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !dir.path().join("ready").exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(dir.path().join("ready").exists());
        assert_eq!(
            acquire_publisher_state(dir.path()).err().unwrap().kind(),
            std::io::ErrorKind::WouldBlock
        );
        std::fs::write(dir.path().join("lose-lease"), b"lost").unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(1));
        let _successor = acquire_publisher_state(dir.path()).unwrap();
        let before = std::fs::read(dir.path().join("writes")).unwrap();
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(before, std::fs::read(dir.path().join("writes")).unwrap());
    }

    #[tokio::test]
    async fn signing_key_materialization_requires_one_complete_rotatable_set() {
        let guard = tempfile::tempdir().unwrap();
        let directory = guard.path().join("keys");
        let source = guard.path().join("source");
        updated_tuf::repo::generate_keys(&source).await.unwrap();
        let mut data = BTreeMap::new();
        for name in updated_tuf::repo::KEY_FILE_NAMES {
            data.insert(
                name.to_string(),
                ByteString(updated_tuf::repo::read_signing_key_bytes(&source.join(name)).unwrap()),
            );
        }
        let original_targets = data["targets.pk8"].0.clone();
        let complete = Secret {
            data: Some(data.clone()),
            ..Default::default()
        };
        let mut incomplete = complete.clone();
        incomplete.data.as_mut().unwrap().remove("root.next.pk8");

        let error = materialize_signing_keys(&incomplete, &directory)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("root.next.pk8"), "{error}");
        assert!(
            !directory.try_exists().unwrap(),
            "an incomplete Secret writes no partial key set"
        );

        let mut oversized_shape = complete.clone();
        oversized_shape
            .data
            .as_mut()
            .unwrap()
            .insert("retired-root.pk8".into(), ByteString(vec![1]));
        let error = materialize_signing_keys(&oversized_shape, &directory)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("retired-root.pk8"), "{error}");
        assert!(
            !directory.try_exists().unwrap(),
            "an open-ended Secret writes no partial key set"
        );

        let mut malformed = complete.clone();
        malformed
            .data
            .as_mut()
            .unwrap()
            .insert("snapshot.pk8".into(), ByteString(b"not a key".to_vec()));
        let error = materialize_signing_keys(&malformed, &directory)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("invalid snapshot.pk8"),
            "{error}"
        );
        assert!(
            !directory.try_exists().unwrap(),
            "a malformed Secret writes no partial key set"
        );

        let mut collapsed = complete.clone();
        let root = collapsed.data.as_ref().unwrap()["root.pk8"].clone();
        collapsed
            .data
            .as_mut()
            .unwrap()
            .insert("root.next.pk8".into(), root);
        let error = materialize_signing_keys(&collapsed, &directory)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("root.pk8")
                && error.to_string().contains("root.next.pk8")
                && error.to_string().contains("same public key"),
            "{error}"
        );
        assert!(
            !directory.try_exists().unwrap(),
            "a role-collapsed Secret writes no partial key set"
        );

        materialize_signing_keys(&complete, &directory)
            .await
            .unwrap();
        assert_eq!(
            updated_tuf::repo::Keys::in_dir(&directory)
                .unwrap()
                .roots
                .len(),
            2,
            "the signer retains both active and standby root keys"
        );

        let replacement = guard.path().join("replacement");
        updated_tuf::repo::generate_keys(&replacement)
            .await
            .unwrap();
        data.insert(
            "targets.pk8".into(),
            ByteString(
                updated_tuf::repo::read_signing_key_bytes(&replacement.join("targets.pk8"))
                    .unwrap(),
            ),
        );
        let drifted = Secret {
            data: Some(data),
            ..Default::default()
        };
        assert!(materialize_signing_keys(&drifted, &directory)
            .await
            .unwrap_err()
            .to_string()
            .contains("targets.pk8 changed in place"));
        assert_eq!(
            std::fs::read(directory.join("targets.pk8")).unwrap(),
            original_targets,
            "detected key drift never overwrites the pinned material"
        );
    }

    fn test_publication_marker(fill: char) -> PublicationMarker {
        let digest = fill.to_string().repeat(64);
        let marker = PublicationMarker {
            plan_sha256: digest.clone(),
            root_sha256: digest.clone(),
            timestamp_sha256: digest,
        };
        marker.validate().unwrap();
        marker
    }

    fn write_publication_marker(path: &Path, marker: &PublicationMarker) {
        std::fs::write(path, marker.to_bounded_json().unwrap()).unwrap();
    }

    /// Write a metadata document that declares nothing but when it expires — the only field the
    /// renewal trigger reads.
    fn signed_until(dir: &Path, file: &str, expires: chrono::DateTime<chrono::Utc>) {
        std::fs::create_dir_all(dir.join("metadata")).unwrap();
        std::fs::write(
            dir.join("metadata").join(file),
            serde_json::json!({"signed": {"expires": expires.to_rfc3339()}}).to_string(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn metadata_inside_its_renewal_window_is_re_signed_before_it_expires() {
        let repo = tempfile::tempdir().unwrap();
        let now = chrono::Utc::now();

        // Freshly signed: the content digest is the only publication trigger.
        signed_until(
            repo.path(),
            "root.json",
            now + chrono::Duration::days(METADATA_EXPIRY_DAYS),
        );
        signed_until(
            repo.path(),
            "timestamp.json",
            now + chrono::Duration::days(METADATA_EXPIRY_DAYS),
        );
        let renewals = expiring_metadata(repo.path(), now).await;
        assert!(renewals.is_empty());
        assert!(!publication_required(true, &renewals), "nothing to do");
        assert!(
            publication_required(false, &renewals),
            "changed content always publishes"
        );

        // Only the online metadata is inside its window, and the fleet is at steady state. It must
        // still publish — the published-plan digest matches forever, so without this nothing is
        // ever re-signed and the whole fleet stops loading the repository the day it expires — and
        // it must NOT renew the root, which is a version bump of the fleet's trust anchor.
        signed_until(
            repo.path(),
            "timestamp.json",
            now + chrono::Duration::days(METADATA_RENEWAL_DAYS - 1),
        );
        let renewals = expiring_metadata(repo.path(), now).await;
        assert_eq!(renewals, vec![TufRole::Online]);
        assert!(publication_required(true, &renewals));
        assert!(!renewals.contains(&TufRole::Root));

        // The root inside its own window is what selects the renewal branch.
        signed_until(
            repo.path(),
            "root.json",
            now + chrono::Duration::days(METADATA_RENEWAL_DAYS - 1),
        );
        let renewals = expiring_metadata(repo.path(), now).await;
        assert_eq!(renewals, vec![TufRole::Root, TufRole::Online]);
        assert!(publication_required(true, &renewals));

        // Already expired is still a renewal, not a special case.
        signed_until(repo.path(), "root.json", now - chrono::Duration::days(1));
        assert!(expiring_metadata(repo.path(), now)
            .await
            .contains(&TufRole::Root));

        // Absent or unreadable is never a renewal: there is nothing signed to re-sign, and the
        // initialization path (with its rollback guard) owns that case.
        std::fs::write(repo.path().join("metadata/root.json"), b"not json").unwrap();
        std::fs::remove_file(repo.path().join("metadata/timestamp.json")).unwrap();
        assert!(expiring_metadata(repo.path(), now).await.is_empty());
    }

    #[tokio::test]
    async fn publication_identity_distinguishes_absent_complete_and_partial_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let digest = "d".repeat(64);
        assert_eq!(publication_marker(tmp.path(), &digest).await.unwrap(), None);

        let metadata = tmp.path().join("repository/metadata");
        std::fs::create_dir_all(&metadata).unwrap();
        std::fs::write(metadata.join("root.json"), b"root").unwrap();
        let error = publication_marker(tmp.path(), &digest).await.unwrap_err();
        assert!(error.to_string().contains("partial"), "{error}");

        std::fs::write(metadata.join("timestamp.json"), b"timestamp").unwrap();
        assert!(publication_marker(tmp.path(), &digest)
            .await
            .unwrap()
            .is_some());
    }

    /// A root that cannot be re-signed is an operator emergency, not a reason to stop publishing.
    /// Propagating the error halted every rollout, admission, and durable write for the whole
    /// ninety-day renewal window over a signing-Secret key set that has nothing to do with the
    /// content — and dropping the role from `renewals` is what stops the un-renewable root
    /// demanding a freshly signed generation on every reconcile for the same ninety days.
    #[tokio::test]
    async fn a_root_that_cannot_be_renewed_reports_itself_without_stopping_publication() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path().join("repository");
        let keys_dir = tmp.path().join("keys");
        let keys = updated_tuf::repo::generate_keys(&keys_dir).await.unwrap();
        updated_tuf::repo::init(&repo_dir, &keys, METADATA_EXPIRY_DAYS)
            .await
            .unwrap();

        // The signing Secret was regenerated: its root keys are well formed but none of them is in
        // the root role the live root.json lists, so the renewal cannot meet the role's threshold.
        let backup = tmp.path().join("backup");
        std::fs::create_dir_all(&backup).unwrap();
        for name in ["root.pk8", "root.next.pk8"] {
            std::fs::copy(keys_dir.join(name), backup.join(name)).unwrap();
            std::fs::remove_file(keys_dir.join(name)).unwrap();
            updated_tuf::repo::generate_root_key(&keys_dir.join(name))
                .await
                .unwrap();
        }
        assert!(
            updated_tuf::repo::renew_root(&repo_dir, &keys.roots, METADATA_EXPIRY_DAYS)
                .await
                .is_err(),
            "the drifted key set must genuinely fail the renewal — this is what used to abort the \
             whole reconcile"
        );

        let mut renewals = vec![TufRole::Root];
        let failure = renew_expiring_root(&repo_dir, &keys_dir, "repo", &mut renewals)
            .await
            .expect("the failure is reported, not propagated");
        assert!(renewals.is_empty(), "{renewals:?}");
        assert!(
            !publication_required(true, &renewals),
            "an un-renewable root must stop forcing a re-signed generation every reconcile"
        );
        let condition = root_renewal_condition(Some(7), Some(&failure));
        assert_eq!(condition.condition_type, "RootRenewal");
        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason, "RenewalFailed");
        assert_eq!(root_renewal_condition(Some(7), None).status, "True");

        // Nothing was half-committed: the trust anchor is untouched, so the fleet keeps verifying
        // against the root it already pinned.
        let root: serde_json::Value =
            serde_json::from_slice(&std::fs::read(repo_dir.join("metadata/root.json")).unwrap())
                .unwrap();
        assert_eq!(root["signed"]["version"], 1);

        // The operator restores the real signing Secret: the renewal now succeeds and KEEPS its
        // role, so this pass signs and uploads the generation carrying the new root.
        for name in ["root.pk8", "root.next.pk8"] {
            std::fs::copy(backup.join(name), keys_dir.join(name)).unwrap();
        }
        let mut renewals = vec![TufRole::Root];
        assert!(
            renew_expiring_root(&repo_dir, &keys_dir, "repo", &mut renewals)
                .await
                .is_none()
        );
        assert_eq!(renewals, vec![TufRole::Root]);
        let root: serde_json::Value =
            serde_json::from_slice(&std::fs::read(repo_dir.join("metadata/root.json")).unwrap())
                .unwrap();
        assert_eq!(root["signed"]["version"], 2);
    }

    /// A root renewal rewrites `root.json` BEFORE the pass signs and uploads, so a publish that
    /// then fails leaves the local root ahead of the one the store serves. Keyed on the content
    /// digest alone, the next pass saw unchanged content and a no-longer-expiring root and never
    /// published again — while `status.routingRootSha256` (read from the LOCAL root) pinned every
    /// enrollment and capability authorization against a root the store does not serve. The marker
    /// carries the root, so the mismatch itself demands the republication that heals it.
    #[tokio::test]
    async fn a_renewed_root_that_was_never_uploaded_forces_the_next_pass_to_publish() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path();
        let repo_dir = state_dir.join("repository");
        let keys_dir = state_dir.join("keys");
        let keys = updated_tuf::repo::generate_keys(&keys_dir).await.unwrap();
        updated_tuf::repo::init(&repo_dir, &keys, METADATA_EXPIRY_DAYS)
            .await
            .unwrap();

        // The last successful publication recorded this content under this root.
        let digest = "d".repeat(64);
        let published = publication_marker(state_dir, &digest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            publication_marker(state_dir, &digest).await.unwrap(),
            Some(published.clone()),
            "nothing has moved yet"
        );
        assert!(
            !publication_required(true, &[]),
            "a steady generation publishes nothing"
        );

        // This pass renews the root and then fails to upload: the marker still describes the old
        // root, and the root is no longer inside its renewal window, so `renewals` is empty.
        let mut renewals = vec![TufRole::Root];
        assert!(
            renew_expiring_root(&repo_dir, &keys_dir, "repo", &mut renewals)
                .await
                .is_none()
        );
        assert!(expiring_metadata(&repo_dir, chrono::Utc::now())
            .await
            .is_empty());
        assert!(
            publication_marker(state_dir, &digest).await.unwrap() != Some(published.clone()),
            "the local root moved, so this repository is NOT the one that was published"
        );
        assert!(
            publication_required(
                publication_marker(state_dir, &digest).await.unwrap() == Some(published.clone()),
                &[]
            ),
            "the next pass must sign and upload the renewed root"
        );

        // Once that publish succeeds the marker is rewritten from the root as it now stands, and
        // the fleet is back at steady state.
        let published = publication_marker(state_dir, &digest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            publication_marker(state_dir, &digest).await.unwrap(),
            Some(published.clone())
        );
        assert!(!publication_required(
            publication_marker(state_dir, &digest).await.unwrap() == Some(published),
            &[]
        ));
    }

    /// The same defect on the ONLINE roles, which is worse because the trigger clears ITSELF:
    /// `sign_plan` re-signs targets/snapshot/timestamp in place with a fresh expiry BEFORE the
    /// upload, so after a failed upload `expiring_metadata` reads the freshly signed LOCAL
    /// `timestamp.json` and reports nothing expiring. Keyed on content (and the root) alone, the
    /// publish block was never entered again and the store kept serving the OLD online metadata
    /// until it hard-expired ~90 days later — at which point every agent's TUF refresh fails at
    /// once and `/enroll` answers 502 fleet-wide, with nothing inside the loop to recover. The
    /// marker carries the online metadata too, so the local re-sign that never landed IS the
    /// mismatch that demands the republication.
    #[tokio::test]
    async fn online_metadata_re_signed_but_never_uploaded_forces_the_next_pass_to_publish() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path();
        let repo_dir = state_dir.join("repository");
        let now = chrono::Utc::now();
        let digest = "d".repeat(64);
        signed_until(
            &repo_dir,
            "root.json",
            now + chrono::Duration::days(METADATA_EXPIRY_DAYS),
        );
        // The online roles are inside their renewal window; the root, renewed earlier, is not. The
        // last successful publication recorded this content under this metadata.
        signed_until(
            &repo_dir,
            "timestamp.json",
            now + chrono::Duration::days(METADATA_RENEWAL_DAYS - 1),
        );
        let published = publication_marker(state_dir, &digest)
            .await
            .unwrap()
            .unwrap();
        let renewals = expiring_metadata(&repo_dir, now).await;
        assert_eq!(renewals, vec![TufRole::Online]);
        assert!(
            publication_required(true, &renewals),
            "freshness alone must trigger a publication at steady state"
        );

        // That pass re-signs the online roles in place and then fails to upload them.
        signed_until(
            &repo_dir,
            "timestamp.json",
            now + chrono::Duration::days(METADATA_EXPIRY_DAYS),
        );
        let renewals = expiring_metadata(&repo_dir, now).await;
        assert!(
            renewals.is_empty(),
            "the re-sign cleared its own trigger, so freshness cannot ask again"
        );
        let unchanged = publication_marker(state_dir, &digest).await.unwrap() == Some(published);
        assert!(
            !unchanged,
            "the local online metadata moved, so this repository is NOT the one the store serves"
        );
        assert!(
            publication_required(unchanged, &renewals),
            "the next pass must sign and upload the re-signed online metadata"
        );

        // Once that publish succeeds the marker is rewritten from the metadata as it now stands,
        // and the fleet is back at steady state.
        let published = publication_marker(state_dir, &digest)
            .await
            .unwrap()
            .unwrap();
        assert!(!publication_required(
            publication_marker(state_dir, &digest).await.unwrap() == Some(published),
            &expiring_metadata(&repo_dir, now).await
        ));
    }

    #[test]
    fn enrollment_objects_bind_generation_bytes_agent_and_assignment() {
        let bundle = crate::EnrollmentBundle {
            schema: 1,
            agent_id: updated_contracts::identity::ResourceName::new("web-01").unwrap(),
            routing_base_url: "https://control/".into(),
            assignment: "a/agents/web-01.json".into(),
            install_root: updated_contracts::assignment::testing::runtime().install_root,
            routing_root: "{}".into(),
        };
        let bytes = bundle.to_bounded_json().unwrap();
        let generation = "a".repeat(64);
        let prefix = enrollment_generation_prefix("web-01", &generation);
        let relative = format!(
            "{prefix}{}.json",
            updated_contracts::digest::sha256_bytes(&bytes)
        );
        assert!(enrollment_object_matches(
            &relative,
            &prefix,
            &bytes,
            "web-01",
            "a/agents/web-01.json"
        ));
        assert!(!enrollment_object_matches(
            &relative,
            &prefix,
            &bytes,
            "web-02",
            "a/agents/web-01.json"
        ));
        let mut tampered = bytes;
        tampered.push(b' ');
        assert!(!enrollment_object_matches(
            &relative,
            &prefix,
            &tampered,
            "web-01",
            "a/agents/web-01.json"
        ));
    }

    #[tokio::test]
    async fn enrollment_gc_keeps_live_objects_and_respects_the_exact_namespace() {
        use object_store::memory::InMemory;

        let store = InMemory::new();
        let live = "enrollments/node/current.json";
        let obsolete = "enrollments/node/obsolete.json";
        let sibling = "enrollments-old/node/foreign.json";
        for relative in [live, obsolete, sibling] {
            store
                .put(
                    &crate::object_key("routing", relative),
                    PutPayload::from_static(b"{}"),
                )
                .await
                .unwrap();
        }
        let kept = BTreeMap::from([("node".into(), live.into())]);
        let removed = sweep_enrollment_objects(
            &store,
            "routing",
            &kept,
            chrono::Utc::now() + chrono::Duration::seconds(1),
        )
        .await
        .unwrap();
        assert_eq!(removed, 1);
        assert!(store
            .head(&crate::object_key("routing", live))
            .await
            .is_ok());
        assert!(matches!(
            store.head(&crate::object_key("routing", obsolete)).await,
            Err(object_store::Error::NotFound { .. })
        ));
        assert!(store
            .head(&crate::object_key("routing", sibling))
            .await
            .is_ok());
    }

    #[test]
    fn the_agent_ceiling_is_reported_on_the_repository_before_it_is_reached() {
        let available = enrollment_capacity_condition(Some(3), 12);
        assert_eq!(available.condition_type, "EnrollmentCapacity");
        assert_eq!(available.status, "True");
        assert!(available.message.contains("12 of at most"));
        let full = enrollment_capacity_condition(
            Some(3),
            updated_contracts::backend::MAX_BACKEND_INVENTORY_MEMBERS,
        );
        assert_eq!(full.status, "False");
        assert_eq!(full.reason, "AtCapacity");
    }

    #[test]
    fn a_failed_reconcile_does_not_erase_what_the_last_successful_one_published() {
        let observed = [
            ready_condition(Some(3), "Published", "the last generation is live"),
            enrollment_capacity_condition(
                Some(3),
                updated_contracts::backend::MAX_BACKEND_INVENTORY_MEMBERS,
            ),
        ];
        let patch =
            serde_json::to_value(failure_status(Some(4), "reconciliation failed", &observed))
                .unwrap();
        // The status is a MERGE patch: a serialized `null` DELETES the field. Sending one for the
        // agent count dropped `at_enrollment_capacity`'s only input, so `/enroll` ran uncapped from
        // the first S3 outage or lost lease until a reconcile succeeded again.
        for erased in [
            "agentCount",
            "publishedDigest",
            "routingRootSha256",
            "storageOwnership",
        ] {
            assert!(
                patch.get(erased).is_none(),
                "a failure claims nothing about {erased}, so it must be omitted, not nulled: \
                 {patch}"
            );
        }
        assert_eq!(patch["observedGeneration"], 4);
        assert_eq!(patch["conditions"][0]["reason"], "ReconciliationFailed");
        // A merge patch replaces the whole array, so the same rule converges inside it: the failure
        // owns `Ready` and nothing else. Rewriting the array with only its own entry hid the
        // enrollment ceiling for as long as the failure lasted.
        let types: Vec<&str> = patch["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|condition| condition["type"].as_str().unwrap())
            .collect();
        assert_eq!(types, vec!["Ready", "EnrollmentCapacity"], "{patch}");
        assert_eq!(patch["conditions"][1]["reason"], "AtCapacity");

        // Once that failure is stored, the next failed tick computes a partial status which omits
        // the successful publication fields. Omission preserves those fields under merge-patch
        // semantics, so the shared no-op gate must still recognize the patch as identical.
        let failed = failure_status(Some(4), "reconciliation failed", &observed);
        let stored = UpdateRepositoryStatus {
            published_digest: Some("last-live-digest".into()),
            agent_count: Some(42),
            routing_root_sha256: Some("a".repeat(64)),
            conditions: failed.conditions.clone(),
            observed_generation: failed.observed_generation,
            ..Default::default()
        };
        assert!(status_unchanged(&failed, Some(&stored)));
    }

    /// Clearing `spec.admissionPolicyRef` mid-incident must clear the verdict it produced. The
    /// conditions array is a MERGE patch assembled by `alerts::merge_conditions`, which carries
    /// forward every condition the writer does not speak for — so a writer that emitted nothing
    /// when admission was disabled left `ReleaseAdmission=False`, naming a policy object that no
    /// longer exists, on the repository and every group for ever, with no writer able to clear it.
    #[test]
    fn disabling_release_admission_clears_the_verdict_the_policy_left_behind() {
        let deployment =
            crate::DesiredDeployment::try_from(crate::tests::deployment_spec("app-v7")).unwrap();
        let stale = [condition(
            "ReleaseAdmission",
            false,
            Some(3),
            "NonCompliantBlocked",
            "UpdateAdmissionPolicy prod blocks app-v7",
        )];
        let conditions = crate::alerts::merge_conditions(
            &stale,
            vec![admission_condition(
                &crate::admission::AdmissionEvaluation::disabled(),
                Some(4),
                &deployment,
            )],
        );
        let admission: Vec<&ResourceCondition> = conditions
            .iter()
            .filter(|condition| condition.condition_type == "ReleaseAdmission")
            .collect();
        assert_eq!(admission.len(), 1, "{conditions:?}");
        assert_eq!(admission[0].status, "True");
        assert_eq!(admission[0].reason, "PolicyDisabled");
    }

    #[test]
    fn consistent_snapshot_metadata_versions_are_resolved_from_signed_parents() {
        let timestamp = serde_json::json!({"signed":{"meta":{"snapshot.json":{"version":7}}}});
        let snapshot = serde_json::json!({"signed":{"meta":{"targets.json":{"version":11}}}});
        assert_eq!(metadata_version(&timestamp, "snapshot.json").unwrap(), 7);
        assert_eq!(metadata_version(&snapshot, "targets.json").unwrap(), 11);
        assert!(metadata_version(&snapshot, "missing.json").is_err());
    }

    fn repository(bucket: &str) -> crate::UpdateRepositorySpec {
        crate::UpdateRepositorySpec {
            default_deployment: crate::DeploymentSpec {
                release_repository: crate::ReleaseRepositorySpec {
                    metadata_url: "https://example.test/metadata/".into(),
                    targets_url: "https://example.test/targets/".into(),
                    root_json: serde_json::json!({"signed": {}, "signatures": []}).to_string(),
                },
                ..crate::tests::deployment_spec("default")
            },
            signing_secret_ref: crate::LocalSecretReference {
                name: "keys".into(),
            },
            s3: crate::RepositoryStorage {
                bucket: bucket.into(),
                ..crate::tests::repository_storage()
            },
            ..crate::tests::repository()
        }
    }

    #[test]
    fn lease_is_available_only_after_its_renewal_deadline() {
        let now = chrono::Utc::now();
        let spec = new_lease_spec("first", now, 0);
        assert!(!lease_expired(&spec, now + chrono::Duration::seconds(14)));
        assert!(lease_expired(&spec, now + chrono::Duration::seconds(15)));
    }

    #[test]
    fn missing_renewal_is_expired() {
        let mut spec = new_lease_spec("first", chrono::Utc::now(), 0);
        spec.renew_time = None;
        assert!(lease_expired(&spec, chrono::Utc::now()));
    }

    #[test]
    fn publication_identity_includes_the_destination() {
        let first = desired_publication_digest(&repository("first"), "plan").unwrap();
        let second = desired_publication_digest(&repository("second"), "plan").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn operational_repository_controls_do_not_resign_an_unchanged_publication() {
        let without = repository("updates");
        let mut with = without.clone();
        with.admission_policy_ref = Some(crate::LocalObjectReference {
            name: "draupnir".into(),
        });
        assert_eq!(
            desired_publication_digest(&without, "plan").unwrap(),
            desired_publication_digest(&with, "plan").unwrap()
        );
        with.state_max_shards = 64;
        assert_eq!(
            desired_publication_digest(&without, "plan").unwrap(),
            desired_publication_digest(&with, "plan").unwrap()
        );
    }

    #[test]
    fn object_prefix_is_normalized_and_confined() {
        for valid in ["", "routing", "tenant/routing"] {
            assert!(validate_object_prefix(valid).is_ok(), "{valid}");
        }
        for invalid in ["/routing", "routing/", "a//b", "a/../b", "a\\b", "a:b"] {
            assert!(validate_object_prefix(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn admitted_state_cleanup_names_exactly_one_repository_projection() {
        let base = admitted_configmap_name("default");
        let names = admitted_state_configmap_names("default");
        let unique: BTreeSet<_> = names.iter().collect();
        assert_eq!(names.len(), 1 + 2 * MAX_ADMITTED_STATE_SHARDS);
        assert_eq!(unique.len(), names.len());
        assert_eq!(names.last(), Some(&base));
        assert!(names.contains(&admitted_state_shard_name(&base, AdmittedStateSlot::A, 0)));
        assert!(names.contains(&admitted_state_shard_name(
            &base,
            AdmittedStateSlot::B,
            MAX_ADMITTED_STATE_SHARDS - 1
        )));
        for outside in [
            admitted_configmap_name("another"),
            format!("{base}-a-64"),
            format!("{base}-a-0"),
            format!("{base}-backup"),
        ] {
            assert!(
                !names.contains(&outside),
                "cleanup must not claim {outside}"
            );
        }
        let another = admitted_state_configmap_names("another");
        assert!(names.iter().all(|name| !another.contains(name)));
    }

    #[test]
    fn finalization_drain_is_anchored_to_the_api_server_deletion_timestamp() {
        let deleted_at = chrono::Utc::now();
        let mut repository = UpdateRepository::new("default", repository("updates"));
        repository.metadata.deletion_timestamp = Some(
            k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(deleted_at),
        );
        assert_eq!(
            repository_capability_drain_remaining(&repository, deleted_at).unwrap(),
            updated_contracts::dataflow::OBJECT_CAPABILITY_DRAIN
        );
        let drained_at = deleted_at
            + chrono::Duration::from_std(updated_contracts::dataflow::OBJECT_CAPABILITY_DRAIN)
                .unwrap();
        assert_eq!(
            repository_capability_drain_remaining(&repository, drained_at).unwrap(),
            Duration::ZERO
        );
        repository.metadata.deletion_timestamp = None;
        assert!(repository_capability_drain_remaining(&repository, deleted_at).is_err());
    }

    #[test]
    fn finalizer_list_adds_once_and_removes_cleanly() {
        // Absent -> appended; already present -> no write needed.
        assert_eq!(
            finalizers_with(&[], REPOSITORY_FINALIZER),
            Some(vec![REPOSITORY_FINALIZER.to_string()])
        );
        assert_eq!(
            finalizers_with(&[REPOSITORY_FINALIZER.to_string()], REPOSITORY_FINALIZER),
            None
        );
        // A finalizer another controller owns is preserved when adding and when removing ours.
        let mixed = vec!["other/keep".to_string(), REPOSITORY_FINALIZER.to_string()];
        assert_eq!(finalizers_with(&mixed, REPOSITORY_FINALIZER), None);
        assert_eq!(
            finalizers_without(&mixed, REPOSITORY_FINALIZER),
            vec!["other/keep".to_string()]
        );
        assert_eq!(
            finalizers_without(&[], REPOSITORY_FINALIZER),
            Vec::<String>::new()
        );
        // The backend's finalizer is the same rule with a different constant: adding ours leaves
        // the repository's alone, and removing ours removes only ours.
        assert_eq!(
            finalizers_with(&mixed, BACKEND_FINALIZER),
            Some(vec![
                "other/keep".to_string(),
                REPOSITORY_FINALIZER.to_string(),
                BACKEND_FINALIZER.to_string(),
            ])
        );
        assert_eq!(
            finalizers_without(
                &[BACKEND_FINALIZER.to_string(), "other/keep".to_string()],
                BACKEND_FINALIZER
            ),
            vec!["other/keep".to_string()]
        );

        let mut resource = crate::UpdateRepository::new("fleet", repository("updates"));
        resource.metadata.resource_version = Some("17".into());
        let patch = finalizer_patch(&resource, vec![REPOSITORY_FINALIZER.into()]);
        assert_eq!(patch["metadata"]["resourceVersion"], "17");
        assert_eq!(
            patch["metadata"]["finalizers"],
            serde_json::json!([REPOSITORY_FINALIZER])
        );
    }

    #[tokio::test]
    async fn prune_prefix_removes_only_the_repositorys_objects() {
        use object_store::memory::InMemory;
        use object_store::path::Path as ObjPath;

        let store = InMemory::new();
        let put = |key: &'static str| {
            let store = &store;
            async move {
                store
                    .put(
                        &ObjPath::from(key),
                        PutPayload::from_bytes(b"x".to_vec().into()),
                    )
                    .await
                    .unwrap();
            }
        };
        put("tenant/routing/metadata/timestamp.json").await;
        put("tenant/routing/metadata/root.json").await;
        put("tenant/routing/targets/app/1.0.0").await;
        put("tenant/routing-old/metadata/root.json").await;
        // A different repository under a sibling prefix must survive.
        put("tenant/other/metadata/timestamp.json").await;

        let pruned = prune_prefix(&store, "tenant/routing").await.unwrap();
        assert_eq!(pruned, 3);

        let mut remaining = store.list(None);
        let mut keys = Vec::new();
        while let Some(entry) = remaining.next().await {
            keys.push(entry.unwrap().location.to_string());
        }
        assert_eq!(
            keys,
            vec![
                "tenant/other/metadata/timestamp.json".to_string(),
                "tenant/routing-old/metadata/root.json".to_string(),
            ]
        );

        // Re-pruning an already-clean prefix is a no-op — the resumability the finalizer relies on.
        assert_eq!(prune_prefix(&store, "tenant/routing").await.unwrap(), 0);
    }

    #[test]
    fn managed_repository_prefixes_are_canonical_and_disjoint() {
        let mut first = crate::UpdateRepository::new("fleet", repository("artifacts"));
        first.metadata.namespace = Some("tenant-a".into());
        let mut second = crate::UpdateRepository::new("fleet", repository("artifacts"));
        second.metadata.namespace = Some("tenant-b".into());
        let mut third = crate::UpdateRepository::new("fleet-staging", repository("artifacts"));
        third.metadata.namespace = Some("tenant-a".into());

        assert_eq!(
            managed_repository_destination(&first).unwrap().prefix,
            "routing/tenant-a/fleet"
        );
        assert_eq!(
            managed_repository_destination(&second).unwrap().prefix,
            "routing/tenant-b/fleet"
        );
        assert_eq!(
            managed_repository_destination(&third).unwrap().prefix,
            "routing/tenant-a/fleet-staging"
        );
    }

    #[test]
    fn storage_ownership_has_one_fresh_bind_and_one_bound_path() {
        let mut repository = crate::UpdateRepository::new("fleet", repository("artifacts"));
        repository.metadata.namespace = Some("tenant-a".into());
        let desired =
            RepositoryStorageOwnership::from(&managed_repository_destination(&repository).unwrap());

        assert!(repository_storage_ownership_needs_binding(&repository, &desired).unwrap());

        // A failed attempt before the binding patch landed may have written only a failure
        // condition. With no finalizer or published claim, retrying the same fresh bind is safe.
        repository.status = Some(failure_status(
            Some(1),
            "the API server was unavailable",
            &[],
        ));
        assert!(repository_storage_ownership_needs_binding(&repository, &desired).unwrap());

        repository.status = Some(UpdateRepositoryStatus {
            storage_ownership: Some(desired.clone()),
            ..Default::default()
        });
        assert!(!repository_storage_ownership_needs_binding(&repository, &desired).unwrap());

        let mut changed = desired.clone();
        changed.bucket = "other".into();
        assert!(repository_storage_ownership_needs_binding(&repository, &changed).is_err());

        repository.status = None;
        repository.metadata.finalizers = Some(vec![REPOSITORY_FINALIZER.into()]);
        assert!(repository_storage_ownership_needs_binding(&repository, &desired).is_err());

        repository.metadata.finalizers = None;
        repository.status = Some(UpdateRepositoryStatus {
            published_digest: Some("published".into()),
            ..Default::default()
        });
        assert!(repository_storage_ownership_needs_binding(&repository, &desired).is_err());
    }

    #[test]
    fn deletion_uses_the_controller_bound_status_scope_not_a_retargeted_spec() {
        let mut original_spec = repository("artifacts");
        original_spec.s3.endpoint = Some("https://original-store".into());
        original_spec.s3.credentials_secret_ref = Some(crate::LocalSecretReference {
            name: "original-credentials".into(),
        });
        let mut deleting = crate::UpdateRepository::new("fleet", original_spec);
        deleting.metadata.namespace = Some("tenant-a".into());
        let ownership =
            RepositoryStorageOwnership::from(&managed_repository_destination(&deleting).unwrap());
        deleting.status = Some(UpdateRepositoryStatus {
            storage_ownership: Some(ownership),
            ..Default::default()
        });

        // Current access material may rotate, but none of these spec coordinates is allowed to
        // choose the irreversible delete.
        deleting.spec.s3.bucket = "attacker-selected".into();
        deleting.spec.s3.endpoint = Some("https://attacker-selected".into());
        deleting.spec.s3.credentials_secret_ref = Some(crate::LocalSecretReference {
            name: "attacker-selected".into(),
        });
        let destination = repository_deletion_destination(&deleting).unwrap();
        assert_eq!(destination.bucket, "artifacts");
        assert_eq!(destination.prefix, "routing/tenant-a/fleet");
        assert_eq!(
            destination.endpoint.as_deref(),
            Some("https://original-store")
        );
        assert_eq!(
            destination
                .credentials_secret_ref
                .as_ref()
                .map(|reference| reference.name.as_str()),
            Some("original-credentials")
        );

        deleting.status = None;
        assert!(repository_deletion_destination(&deleting).is_none());
    }

    /// A replica whose local metadata is BEHIND the store must never publish. It led up to
    /// generation 5, lost the lease while another replica advanced the store to 40, and reacquired
    /// it: `root.json` is on disk so it looks healthy, its publication marker is stale so it
    /// believes a publish is due, and `replace_release` numbers the next generation from LOCAL
    /// metadata — so it would upload 6 over 40 and every node that ever saw 40 would reject the
    /// fleet's routing as a rollback, permanently.
    #[tokio::test]
    async fn a_local_repository_behind_the_store_refuses_to_publish() {
        use object_store::memory::InMemory;
        use object_store::path::Path as ObjPath;

        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path().join("repository");
        let keys = updated_tuf::repo::generate_keys(&tmp.path().join("keys"))
            .await
            .unwrap();
        updated_tuf::repo::init(&repo_dir, &keys, METADATA_EXPIRY_DAYS)
            .await
            .unwrap();
        assert_eq!(
            updated_tuf::repo::current_version(&repo_dir).await.unwrap(),
            1
        );
        let mut destination = crate::tests::s3_destination();
        destination.bucket = "updates".into();
        destination.prefix = "routing".into();
        let store = InMemory::new();
        let publish = |version: u64| {
            let store = &store;
            async move {
                store
                    .put(
                        &ObjPath::from("routing/metadata/timestamp.json"),
                        PutPayload::from_bytes(
                            serde_json::json!({ "signed": { "version": version } })
                                .to_string()
                                .into_bytes()
                                .into(),
                        ),
                    )
                    .await
                    .unwrap();
            }
        };

        // An empty store: nothing published, so nothing can be rolled back.
        refuse_generation_rollback(&store, &destination, &repo_dir)
            .await
            .expect("a store with no generation cannot be rolled back");

        publish(40).await;
        assert_eq!(
            store_published_version(&store, &destination).await.unwrap(),
            Some(40)
        );
        let error = refuse_generation_rollback(&store, &destination, &repo_dir)
            .await
            .expect_err("a local repository at 1 must not republish over 40");
        assert!(
            error
                .to_string()
                .contains("refusing to publish a lower generation"),
            "{error}"
        );

        // The same guard covers an EMPTY local state dir, which would re-initialize at version 1.
        let empty = tmp.path().join("fresh");
        let error = refuse_generation_rollback(&store, &destination, &empty)
            .await
            .expect_err("a fresh state dir must not re-init over a published generation");
        assert!(
            error.to_string().contains("refusing to re-initialize"),
            "{error}"
        );

        // Caught up (or ahead) is exactly what publishing is for.
        publish(1).await;
        refuse_generation_rollback(&store, &destination, &repo_dir)
            .await
            .expect("a local repository level with the store publishes normally");
    }

    /// A generation that reached the store but whose durable record was lost — reconcile is dropped
    /// at any await when the publisher lease renewal fails — must be recovered before anything is
    /// planned. Planning from a baseline that predates the live generation reads an already-advanced
    /// node as still on its predecessor and republishes it there: one signed generation backwards,
    /// no `maxUnavailable`, no health gate.
    #[tokio::test]
    async fn a_published_generation_whose_record_was_lost_is_recovered_before_planning() {
        use axum::http::{Method, StatusCode};
        use object_store::memory::InMemory;
        use object_store::path::Path as ObjPath;

        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path();
        let advanced = DurableRolloutState {
            admitted: BTreeMap::new(),
            vetoed: BTreeMap::new(),
            routing: BTreeMap::from([("n1".to_string(), "g".to_string())]),
            assignments: BTreeMap::from([("n1".to_string(), "b".repeat(64))]),
        };
        let stale = || DurableRolloutState {
            admitted: BTreeMap::new(),
            vetoed: BTreeMap::new(),
            routing: BTreeMap::from([("n1".to_string(), "g".to_string())]),
            assignments: BTreeMap::from([("n1".to_string(), "a".repeat(64))]),
        };
        let journal = |marker: &PublicationMarker, version: u64, state: &DurableRolloutState| {
            std::fs::write(
                state_dir.join(PENDING_STATE_FILE),
                serde_json::to_vec(&PendingPublication {
                    marker: marker.clone(),
                    version,
                    state: StoredDurableRolloutState::from(state),
                })
                .unwrap(),
            )
            .unwrap();
        };
        let mut destination = crate::tests::s3_destination();
        destination.bucket = "updates".into();
        destination.prefix = "routing".into();
        let store = InMemory::new();
        let serve = |version: u64| {
            let store = &store;
            async move {
                store
                    .put(
                        &ObjPath::from("routing/metadata/timestamp.json"),
                        PutPayload::from_bytes(
                            serde_json::json!({ "signed": { "version": version } })
                                .to_string()
                                .into_bytes()
                                .into(),
                        ),
                    )
                    .await
                    .unwrap();
            }
        };
        let recorded: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Default::default();
        let client = crate::tests::apiserver({
            let recorded = recorded.clone();
            move |method: &Method, _: &str, body: Vec<u8>| {
                if method != Method::GET && method != Method::DELETE {
                    recorded
                        .lock()
                        .unwrap()
                        .push(serde_json::from_slice(&body).unwrap());
                }
                (
                    StatusCode::OK,
                    serde_json::json!({ "metadata": { "name": "state", "resourceVersion": "9" } }),
                )
            }
        });
        let configmaps: Api<ConfigMap> = Api::namespaced(client, "prod");
        let recover = |durable: DurableRolloutState| {
            recover_pending_publication(
                AdmittedRecord {
                    configmaps: &configmaps,
                    name: "state",
                    namespace: "prod",
                    owner: None,
                    max_shards: AdmittedShardLimit::new(1).unwrap(),
                },
                state_dir,
                &store,
                &destination,
                durable,
                Some(AdmittedStateVersion {
                    resource_version: "7".into(),
                    index: AdmittedStateIndex {
                        active: Some(AdmittedStateSlot::A),
                        revision_sha256: Some("a".repeat(64)),
                        max_shards: 1,
                        a_shards: 1,
                        ..Default::default()
                    },
                }),
            )
        };

        // The upload never completed: the marker for that generation was never written AND the
        // store does not serve it, so nothing was served and the journal is discarded rather than
        // recorded.
        serve(39).await;
        journal(&test_publication_marker('c'), 40, &advanced);
        let (durable, version) = recover(stale()).await.unwrap();
        assert_eq!(durable.assignments["n1"], "a".repeat(64));
        assert_eq!(
            version
                .as_ref()
                .map(|version| version.resource_version.as_str()),
            Some("7")
        );
        assert!(recorded.lock().unwrap().is_empty(), "nothing to record");
        assert!(!state_dir.join(PENDING_STATE_FILE).exists());

        // Marker equality is NOT proof of upload. A pass triggered by neither changed content nor
        // expiring metadata — an admission whose nodes are all blocked by `maxUnavailable`, so the
        // plan digest is unchanged — journals a marker that is ALREADY on disk from the previous
        // successful generation. Its upload failed all the same, and the store still serves 39, so
        // adopting on the marker recorded a generation no signed metadata ever carried.
        let marker_v40 = test_publication_marker('b');
        write_publication_marker(&state_dir.join(PUBLISHED_GENERATION_FILE), &marker_v40);
        journal(&marker_v40, 40, &advanced);
        let (durable, version) = recover(stale()).await.unwrap();
        assert_eq!(
            durable.assignments["n1"],
            "a".repeat(64),
            "the store serves 39, so this journal describes an upload that never landed"
        );
        assert_eq!(
            version
                .as_ref()
                .map(|version| version.resource_version.as_str()),
            Some("7")
        );
        assert!(recorded.lock().unwrap().is_empty(), "nothing to record");
        assert!(!state_dir.join(PENDING_STATE_FILE).exists());

        // The upload DID complete — the store serves the exact generation the journal describes —
        // but the record was lost. The published state is adopted and written back, and planning
        // proceeds from it.
        serve(40).await;
        journal(&marker_v40, 40, &advanced);
        let (durable, version) = recover(stale()).await.unwrap();
        assert_eq!(
            durable.assignments["n1"],
            "b".repeat(64),
            "the node the lost generation advanced is never planned as still on its predecessor"
        );
        assert_eq!(
            version
                .as_ref()
                .map(|version| version.resource_version.as_str()),
            Some("9"),
            "and the new resourceVersion is carried forward"
        );
        let recorded = recorded.lock().unwrap().clone();
        assert_eq!(
            recorded.len(),
            4,
            "allocation, shard, pointer swap, and cleanup index are the atomic write"
        );
        let shard: ConfigMap = serde_json::from_value(recorded[1].clone()).unwrap();
        let stored: StoredDurableRolloutState =
            serde_json::from_slice(&shard.binary_data.unwrap()["state.bin"].0).unwrap();
        assert!(stored
            .assignments
            .values()
            .flatten()
            .any(|node| node == "n1"));
        assert!(
            !state_dir.join(PENDING_STATE_FILE).exists(),
            "the journal is evaluated once, so it can never re-apply itself over a later write"
        );
    }

    /// The publication marker is written AFTER the upload returns, so a process death in that gap
    /// (an OOM kill, an evicted pod) leaves the store serving generation N while the marker still
    /// names N-1. Deciding on the marker alone read that as "never uploaded" and DELETED the
    /// journal, so planning fell back to a baseline predating the live generation and republished
    /// an already-advanced node on its predecessor. The store is asked instead: it serves the
    /// journalled version, so the state is adopted and the interrupted marker write is finished.
    #[tokio::test]
    async fn a_generation_the_store_serves_is_recovered_even_when_the_marker_never_landed() {
        use axum::http::{Method, StatusCode};
        use object_store::memory::InMemory;
        use object_store::path::Path as ObjPath;

        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path();
        // The marker still names the PREDECESSOR: the process died before it was rewritten.
        let marker_v39 = test_publication_marker('a');
        let marker_v40 = test_publication_marker('b');
        write_publication_marker(&state_dir.join(PUBLISHED_GENERATION_FILE), &marker_v39);
        std::fs::write(
            state_dir.join(PENDING_STATE_FILE),
            serde_json::to_vec(&PendingPublication {
                marker: marker_v40.clone(),
                version: 40,
                state: StoredDurableRolloutState::from(&DurableRolloutState {
                    admitted: BTreeMap::new(),
                    vetoed: BTreeMap::new(),
                    routing: BTreeMap::from([("n1".to_string(), "g".to_string())]),
                    assignments: BTreeMap::from([("n1".to_string(), "b".repeat(64))]),
                }),
            })
            .unwrap(),
        )
        .unwrap();

        let mut destination = crate::tests::s3_destination();
        destination.bucket = "updates".into();
        destination.prefix = "routing".into();
        let store = InMemory::new();
        // The store genuinely serves generation 40: `publish_repository` uploads timestamp.json
        // last, so on return the generation IS being served.
        store
            .put(
                &ObjPath::from("routing/metadata/timestamp.json"),
                PutPayload::from_bytes(
                    serde_json::json!({ "signed": { "version": 40 } })
                        .to_string()
                        .into_bytes()
                        .into(),
                ),
            )
            .await
            .unwrap();

        let client = crate::tests::apiserver(move |_: &Method, _: &str, _: Vec<u8>| {
            (
                StatusCode::OK,
                serde_json::json!({ "metadata": { "name": "state", "resourceVersion": "9" } }),
            )
        });
        let configmaps: Api<ConfigMap> = Api::namespaced(client, "prod");
        let (durable, version) = recover_pending_publication(
            AdmittedRecord {
                configmaps: &configmaps,
                name: "state",
                namespace: "prod",
                owner: None,
                max_shards: AdmittedShardLimit::new(1).unwrap(),
            },
            state_dir,
            &store,
            &destination,
            DurableRolloutState {
                admitted: BTreeMap::new(),
                vetoed: BTreeMap::new(),
                routing: BTreeMap::from([("n1".to_string(), "g".to_string())]),
                assignments: BTreeMap::from([("n1".to_string(), "a".repeat(64))]),
            },
            Some(AdmittedStateVersion {
                resource_version: "7".into(),
                index: AdmittedStateIndex {
                    active: Some(AdmittedStateSlot::A),
                    revision_sha256: Some("a".repeat(64)),
                    max_shards: 1,
                    a_shards: 1,
                    ..Default::default()
                },
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            durable.assignments["n1"],
            "b".repeat(64),
            "the live generation's state is adopted, not discarded as never-uploaded"
        );
        assert_eq!(
            version
                .as_ref()
                .map(|version| version.resource_version.as_str()),
            Some("9")
        );
        assert_eq!(
            read_publication_marker(&state_dir.join(PUBLISHED_GENERATION_FILE))
                .await
                .unwrap(),
            Some(marker_v40),
            "and the interrupted marker write is finished, so no identical republish follows"
        );
        assert!(!state_dir.join(PENDING_STATE_FILE).exists());
    }

    #[tokio::test]
    async fn a_malformed_pending_journal_blocks_planning_and_is_retained() {
        use axum::http::{Method, StatusCode};
        use object_store::memory::InMemory;

        let tmp = tempfile::tempdir().unwrap();
        let journal = tmp.path().join(PENDING_STATE_FILE);
        std::fs::write(&journal, b"{ definitely-not-json").unwrap();
        let client = crate::tests::apiserver(|_: &Method, _: &str, _: Vec<u8>| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"message": "the malformed journal must fail before Kubernetes"}),
            )
        });
        let configmaps: Api<ConfigMap> = Api::namespaced(client, "prod");
        let mut destination = crate::tests::s3_destination();
        destination.bucket = "updates".into();
        destination.prefix = "routing".into();
        let error = recover_pending_publication(
            AdmittedRecord {
                configmaps: &configmaps,
                name: "state",
                namespace: "prod",
                owner: None,
                max_shards: AdmittedShardLimit::new(1).unwrap(),
            },
            tmp.path(),
            &InMemory::new(),
            &destination,
            DurableRolloutState::default(),
            None,
        )
        .await
        .err()
        .expect("a corrupt recovery record is not equivalent to no interrupted publication");
        assert!(
            error
                .to_string()
                .contains("invalid pending publication journal"),
            "{error}"
        );
        assert!(
            journal.exists(),
            "the evidence is retained for repair instead of silently rebaselining"
        );
    }

    #[test]
    fn enrollment_without_a_trust_anchor_is_an_error_not_a_silent_skip() {
        assert_eq!(enrollment_anchor(0, None).unwrap(), None);
        assert_eq!(enrollment_anchor(0, Some("anchor")).unwrap(), None);
        assert_eq!(
            enrollment_anchor(3, Some("anchor")).unwrap(),
            Some("anchor")
        );
        let error = enrollment_anchor(3, None).unwrap_err();
        assert!(
            error.0.contains("routingRootSha256"),
            "the operator must be told exactly what is missing: {error}"
        );
    }

    /// The published assignments stay inverted even though the durable state is sharded: a
    /// 64-character identity is written once per deployment instead of once per node, preserving
    /// useful capacity under every configured bound.
    #[test]
    fn published_assignments_round_trip_and_intern_their_digests() {
        let identity = "a".repeat(64);
        let assignments: BTreeMap<String, String> = (0..50)
            .map(|index| (format!("node-{index:03}"), identity.clone()))
            .collect();
        let encoded = encode_assignments(&assignments);
        assert_eq!(encoded.len(), 1);
        assert_eq!(decode_assignments(encoded.clone()).unwrap(), assignments);
        let inverted = serde_json::to_string(&encoded).unwrap().len();
        let flat = serde_json::to_string(&assignments).unwrap().len();
        assert!(
            inverted * 2 < flat,
            "storing one digest per deployment must be far smaller than one per node \
             ({inverted} vs {flat} bytes)"
        );
    }

    #[test]
    fn durable_state_names_cover_full_length_repository_names_without_collisions() {
        let first = format!("{}a", "x".repeat(252));
        let second = format!("{}b", "x".repeat(252));
        let first_base = admitted_configmap_name(&first);
        let second_base = admitted_configmap_name(&second);
        assert_eq!(first_base.len(), 248);
        assert_eq!(second_base.len(), 248);
        assert_ne!(
            first_base, second_base,
            "the truncated tail is content-addressed"
        );
        assert_eq!(
            admitted_state_shard_name(&first_base, AdmittedStateSlot::B, 63).len(),
            253
        );
    }

    #[test]
    fn duplicate_nodes_in_stored_assignments_are_refused() {
        let duplicated = BTreeMap::from([
            ("a".repeat(64), vec!["node".into()]),
            ("b".repeat(64), vec!["node".into()]),
        ]);
        assert!(decode_assignments(duplicated)
            .unwrap_err()
            .contains("more than one assignment"));
    }

    #[test]
    fn every_durable_rollout_document_has_one_closed_shape() {
        let desired = crate::DesiredDeployment::try_from(crate::tests::deployment_spec("v1"))
            .expect("valid fixture deployment");
        let admitted = crate::rollout::AdmittedDeployment {
            current: desired,
            previous: Vec::new(),
        };

        let mut nested = serde_json::to_value(&admitted).unwrap();
        nested["retiredCompatibilityField"] = true.into();
        assert!(serde_json::from_value::<crate::rollout::AdmittedDeployment>(nested).is_err());
        let mut missing = serde_json::to_value(&admitted).unwrap();
        missing.as_object_mut().unwrap().remove("previous");
        assert!(serde_json::from_value::<crate::rollout::AdmittedDeployment>(missing).is_err());

        let state = DurableRolloutState {
            admitted: BTreeMap::from([("group".into(), admitted)]),
            routing: BTreeMap::from([("node".into(), "group".into())]),
            assignments: BTreeMap::from([("node".into(), "a".repeat(64))]),
            ..Default::default()
        };
        let stored = StoredDurableRolloutState::from(&state);
        let mut stored_json = serde_json::to_value(&stored).unwrap();
        stored_json["legacyAssignments"] = serde_json::json!({});
        assert!(serde_json::from_value::<StoredDurableRolloutState>(stored_json).is_err());

        let pending = PendingPublication {
            marker: test_publication_marker('a'),
            version: 1,
            state: stored,
        };
        let mut marker_json = serde_json::to_value(&pending.marker).unwrap();
        marker_json["legacyDigest"] = "d".repeat(64).into();
        assert!(serde_json::from_value::<PublicationMarker>(marker_json).is_err());
        let mut pending_json = serde_json::to_value(&pending).unwrap();
        pending_json["fallbackState"] = serde_json::json!({});
        assert!(serde_json::from_value::<PendingPublication>(pending_json).is_err());

        let index = AdmittedStateIndex::default();
        let mut index_json = serde_json::to_value(&index).unwrap();
        index_json["legacySlot"] = "a".into();
        assert!(serde_json::from_value::<AdmittedStateIndex>(index_json).is_err());
        for required_nullable_field in ["active", "revisionSha256"] {
            let mut index_json = serde_json::to_value(&index).unwrap();
            index_json
                .as_object_mut()
                .unwrap()
                .remove(required_nullable_field);
            assert!(
                serde_json::from_value::<AdmittedStateIndex>(index_json).is_err(),
                "the writer's nullable {required_nullable_field} field is still required"
            );
        }
    }

    #[test]
    fn admitted_shard_width_is_validated_once_and_converts_without_panicking() {
        assert!(AdmittedShardLimit::new(0).is_err());
        assert!(AdmittedShardLimit::new((MAX_ADMITTED_STATE_SHARDS + 1) as u8).is_err());

        for configured in [1, MAX_ADMITTED_STATE_SHARDS as u8] {
            let limit = AdmittedShardLimit::new(configured).unwrap();
            assert_eq!(limit.stored(), configured);
            assert_eq!(limit.count(), usize::from(configured));
        }
    }

    #[test]
    fn durable_state_capacity_fails_before_any_kubernetes_mutation() {
        let state = DurableRolloutState {
            routing: (0..5_000)
                .map(|index| {
                    (
                        format!(
                            "n{index:04}.{}.{}.{}",
                            "a".repeat(60),
                            "b".repeat(60),
                            "c".repeat(60)
                        ),
                        "g".to_string(),
                    )
                })
                .collect(),
            ..Default::default()
        };
        // Reconcile calls this pure preflight before signing, object-store upload, or the first API
        // call; store_admitted_state accepts only its successful result.
        let error = prepare_admitted_state(&state, AdmittedShardLimit::new(1).unwrap())
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("StateCapacityExceeded"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn durable_state_store_writes_exactly_the_configured_projection() {
        use axum::http::{Method, StatusCode};

        let writes: Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>> = Default::default();
        let client = crate::tests::apiserver({
            let writes = writes.clone();
            move |method: &Method, path: &str, body: Vec<u8>| {
                if method == Method::GET {
                    return (
                        StatusCode::NOT_FOUND,
                        serde_json::json!({
                            "apiVersion": "v1",
                            "kind": "Status",
                            "status": "Failure",
                            "reason": "NotFound",
                            "code": 404
                        }),
                    );
                }
                let mut object: serde_json::Value = serde_json::from_slice(&body).unwrap();
                writes
                    .lock()
                    .unwrap()
                    .push((path.to_string(), object.clone()));
                object["metadata"]["resourceVersion"] = "9".into();
                (StatusCode::OK, object)
            }
        });
        let configmaps: Api<ConfigMap> = Api::namespaced(client, "prod");
        let state = DurableRolloutState {
            routing: BTreeMap::from([("node".into(), "group".into())]),
            assignments: BTreeMap::from([("node".into(), "a".repeat(64))]),
            ..Default::default()
        };
        let prepared = prepare_admitted_state(&state, AdmittedShardLimit::new(3).unwrap()).unwrap();
        let version = store_admitted_state(&configmaps, "state", "prod", prepared, None, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(version.index.active, Some(AdmittedStateSlot::A));
        assert_eq!(version.index.max_shards, 3);
        assert_eq!(version.index.a_shards, 3);
        assert_eq!(version.index.b_shards, 0);

        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 5, "allocation + three shards + pointer swap");
        let shards: Vec<ConfigMap> = writes[1..4]
            .iter()
            .map(|(_, object)| serde_json::from_value(object.clone()).unwrap())
            .collect();
        assert_eq!(
            shards.iter().map(ResourceExt::name_any).collect::<Vec<_>>(),
            ["state-a-00", "state-a-01", "state-a-02"]
        );
        let encoded: Vec<u8> = shards
            .iter()
            .flat_map(|shard| shard.binary_data.as_ref().unwrap()["state.bin"].0.clone())
            .collect();
        let stored: StoredDurableRolloutState = serde_json::from_slice(&encoded).unwrap();
        assert!(DurableRolloutState::try_from(stored).unwrap() == state);
        let index: AdmittedStateIndex = serde_json::from_str(
            writes.last().unwrap().1["data"]["index.json"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let revision = updated_contracts::digest::sha256_bytes(&encoded);
        assert_eq!(index.revision_sha256.as_deref(), Some(revision.as_str()));
    }
}
