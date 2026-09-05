use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicBool;
use std::{
    io,
    path::{Path, PathBuf},
};

use updated::config::Routing;
use updated_contracts::dataflow::{
    DownloadCapability, FileSnapshot, InputPublication, InputSelection, MAX_CAPABILITY_BODY_BYTES,
    MAX_DATAFLOW_BODY_BYTES,
};
use updated_contracts::telemetry::REPORT_CADENCE_JITTER_PERCENT;

const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const RETRY_BASE: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Debug)]
pub(crate) enum InputError {
    Superseded,
    Unavailable(String),
}

impl From<String> for InputError {
    fn from(message: String) -> Self {
        Self::Unavailable(message)
    }
}

impl std::fmt::Display for InputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Superseded => {
                f.write_str("the input assignment was superseded; restart to refresh it")
            }
            Self::Unavailable(message) => f.write_str(message),
        }
    }
}

// Keep the exact authenticated object, including its private blinding, so every disk read can
// verify the signed commitment again. Selection metadata never contains plaintext credentials.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedInputs {
    selection: InputSelection,
    body: String,
}

impl CachedInputs {
    fn snapshot(&self) -> Result<FileSnapshot, String> {
        self.selection.validate()?;
        if self.selection.is_empty() && self.body.is_empty() {
            return Ok(FileSnapshot::default());
        }
        InputPublication::from_bounded_body(self.body.as_bytes(), &self.selection)
            .map(|publication| publication.snapshot)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryInputs {
    attempt_id: String,
    inputs: CachedInputs,
}

const CACHE_LIMIT: usize = 2 * MAX_DATAFLOW_BODY_BYTES + 16 * 1024;

fn read_private_record<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    let bytes = match foundation::file::read_bounded_regular(
        path,
        CACHE_LIMIT,
        foundation::file::FinalSymlink::Refuse,
    ) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid private input record"))
}

fn write_private_record(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() > CACHE_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private input record exceeds limit",
        ));
    }
    std::fs::create_dir_all(foundation::durable::parent_dir(path))?;
    foundation::durable::atomic_write(path, ".inputs-", &bytes)
}

/// The node's only assigned-input owner.
///
/// The mTLS gateway authorizes the current signed selection and returns a 60-second exact-object
/// S3 capability plus the control-plane-authenticated byte digest. The manager authenticates the
/// anonymous download before parsing it. Every request names the exact assignment this agent
/// verified, so a cached predecessor authorization cannot return stale values; the manager then
/// validates the snapshot against the signed selection before making it visible to a reconciler
/// invocation.
pub(crate) struct RuntimeDataManager {
    gateway_base_url: Option<String>,
    control_client: Option<reqwest::Client>,
    object_client: Option<reqwest::Client>,
    current: FileSnapshot,
    current_selection: InputSelection,
    current_body: String,
    cache_path: PathBuf,
}

impl RuntimeDataManager {
    pub(crate) fn new(
        routing: &Routing,
        inputs: &InputSelection,
        cache_path: &Path,
    ) -> Result<Self, String> {
        let (gateway_base_url, control_client, object_client) =
            if routing.is_local()? {
                (None, None, None)
            } else {
                (
                    Some(routing.base_url.clone()),
                    Some(routing.mtls.reqwest_control_client().map_err(|error| {
                        format!("building assigned-input mTLS client: {error}")
                    })?),
                    Some(routing.mtls.reqwest_capability_client().map_err(|error| {
                        format!("building assigned-input HTTPS client: {error}")
                    })?),
                )
            };
        if gateway_base_url.is_none() && !inputs.is_empty() {
            return Err(
                "this deployment declares assigned inputs, but a local routing repository has no \
                 capability endpoint"
                    .into(),
            );
        }
        Ok(Self {
            gateway_base_url,
            control_client,
            object_client,
            current: FileSnapshot::default(),
            current_selection: InputSelection::default(),
            current_body: String::new(),
            cache_path: cache_path.to_path_buf(),
        })
    }

    pub(crate) async fn acquire(
        &mut self,
        assignment_sha256: &str,
        inputs: &InputSelection,
        shutdown: &AtomicBool,
    ) -> Result<bool, InputError> {
        let mut failures = 0u32;
        while let Err(error) = self.reconcile(assignment_sha256, inputs).await {
            if matches!(error, InputError::Superseded) {
                return Err(error);
            }
            let backoff = crate::schedule::jitter(
                crate::schedule::network_backoff(RETRY_BASE, failures),
                REPORT_CADENCE_JITTER_PERCENT,
            );
            failures = failures.saturating_add(1);
            crate::warn(&format!(
                "fetching assigned inputs failed ({error}); retrying in {}s",
                backoff.as_secs()
            ));
            if crate::schedule::sleep_interruptible(backoff, shutdown).await {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn inputs(&self) -> &FileSnapshot {
        &self.current
    }

    pub(crate) async fn reconcile(
        &mut self,
        assignment_sha256: &str,
        inputs: &InputSelection,
    ) -> Result<(), InputError> {
        inputs.validate()?;
        if inputs == &self.current_selection {
            self.current.validate_selection(inputs)?;
            return Ok(());
        }
        let cached = read_private_record::<CachedInputs>(&self.cache_path)
            .ok()
            .flatten()
            .filter(|cached| cached.selection == *inputs);
        let (next, needs_write) = match cached.filter(|cached| cached.snapshot().is_ok()) {
            Some(cached) => (cached, false),
            None if inputs.is_empty() => (
                CachedInputs {
                    selection: inputs.clone(),
                    body: String::new(),
                },
                true,
            ),
            None => (self.fetch(assignment_sha256, inputs).await?, true),
        };
        let snapshot = next.snapshot()?;
        // A node may mutate only after its authenticated inputs survive a process or host crash.
        if needs_write {
            write_private_record(&self.cache_path, &next).map_err(|error| error.to_string())?;
        }
        self.current = snapshot;
        self.current_selection = inputs.clone();
        self.current_body = next.body;
        Ok(())
    }

    /// Pin the exact files before an update journal can authorize its first mutation. The pin
    /// outlives cache replacement by a newer assignment and stays through the rollback guard.
    pub(crate) fn pin(&self, path: &Path, attempt_id: &str) -> io::Result<()> {
        if !updated::rand::is_token(attempt_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid input recovery attempt",
            ));
        }
        let inputs = CachedInputs {
            selection: self.current_selection.clone(),
            body: self.current_body.clone(),
        };
        inputs
            .snapshot()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        write_private_record(
            path,
            &RecoveryInputs {
                attempt_id: attempt_id.into(),
                inputs,
            },
        )
    }

    pub(crate) fn restore_pin(&mut self, path: &Path, attempt_id: &str) -> io::Result<bool> {
        let Some(record) = read_private_record::<RecoveryInputs>(path)? else {
            return Ok(false);
        };
        if record.attempt_id != attempt_id {
            return Ok(false); // A pre-journal crash can leave an unused pin.
        }
        let snapshot = record
            .inputs
            .snapshot()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        self.current = snapshot;
        self.current_selection = record.inputs.selection;
        self.current_body = record.inputs.body;
        Ok(true)
    }

    pub(crate) fn selection(&self) -> &InputSelection {
        &self.current_selection
    }

    async fn fetch(
        &self,
        assignment_sha256: &str,
        inputs: &InputSelection,
    ) -> Result<CachedInputs, InputError> {
        tokio::time::timeout(
            FETCH_TIMEOUT,
            self.fetch_unbounded(assignment_sha256, inputs),
        )
        .await
        .map_err(|_| {
            format!(
                "fetching assigned inputs exceeded its {}s timeout",
                FETCH_TIMEOUT.as_secs_f64()
            )
        })?
    }

    async fn fetch_unbounded(
        &self,
        assignment_sha256: &str,
        inputs: &InputSelection,
    ) -> Result<CachedInputs, InputError> {
        let gateway_base_url = self
            .gateway_base_url
            .as_ref()
            .ok_or_else(|| "assigned inputs require an HTTPS capability endpoint".to_string())?;
        let endpoint =
            updated_contracts::dataflow::inputs_url(gateway_base_url, assignment_sha256)?;
        let response = self
            .control_client
            .as_ref()
            .expect("endpoint and client are paired")
            .get(endpoint)
            .send()
            .await
            .map_err(|error| {
                updated::http::redacted_reqwest_error("requesting the input capability", &error)
                    .to_string()
            })?;
        // A current gateway will never authorize this obsolete commitment again. Boot must
        // reload its signed assignment, not retry the same hash indefinitely.
        if response.status() == reqwest::StatusCode::CONFLICT {
            return Err(InputError::Superseded);
        }
        let capability_body = updated::http::read_bounded(
            response,
            "assigned input capability",
            MAX_CAPABILITY_BODY_BYTES,
        )
        .await
        .map_err(|error| error.to_string())?;
        let capability = DownloadCapability::from_bounded_json(&capability_body)?;
        authenticate_input_capability(&capability, inputs)?;
        let response = self
            .object_client
            .as_ref()
            .expect("endpoint and object client are paired")
            .get(&capability.url)
            .send()
            .await
            .map_err(|error| {
                updated::http::redacted_reqwest_error("fetching assigned inputs", &error)
                    .to_string()
            })?;
        let bytes = updated::http::read_bounded(
            response,
            "assigned input snapshot",
            MAX_DATAFLOW_BODY_BYTES,
        )
        .await
        .map_err(|error| error.to_string())?;
        decode_snapshot(&capability, inputs, &bytes)?;
        Ok(CachedInputs {
            selection: inputs.clone(),
            body: String::from_utf8(bytes)
                .map_err(|_| "input publication is not UTF-8".to_string())?,
        })
    }
}

fn decode_snapshot(
    capability: &DownloadCapability,
    inputs: &InputSelection,
    bytes: &[u8],
) -> Result<FileSnapshot, String> {
    authenticate_input_capability(capability, inputs)?;
    updated::http::authenticate_download_bytes(capability, bytes, "assigned input object")
        .map_err(|error| error.to_string())?;
    InputPublication::from_bounded_body(bytes, inputs).map(|publication| publication.snapshot)
}

fn authenticate_input_capability(
    capability: &DownloadCapability,
    inputs: &InputSelection,
) -> Result<(), String> {
    (capability.sha256 == inputs.object_sha256)
        .then_some(())
        .ok_or_else(|| {
            "input capability does not match the object committed by the signed assignment".into()
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn cached_inputs(value: &[u8]) -> CachedInputs {
        let snapshot = FileSnapshot {
            files: [(
                "password".into(),
                updated_contracts::dataflow::FileValue::from_bytes(value).unwrap(),
            )]
            .into(),
        };
        let publication = InputPublication::from_snapshot(snapshot, &[7; 32]).unwrap();
        CachedInputs {
            selection: publication.selection().unwrap(),
            body: String::from_utf8(publication.to_bounded_body().unwrap()).unwrap(),
        }
    }

    fn offline_manager(cache: &Path) -> RuntimeDataManager {
        RuntimeDataManager::new(
            &routing(&crate::test_support::local_repository_base()),
            &InputSelection::default(),
            cache,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn authenticated_cache_survives_restart_without_network_and_unchanged_reads_do_no_io() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime-inputs.json");
        let cached = cached_inputs(b"private credential");
        write_private_record(&path, &cached).unwrap();
        let mut restarted = offline_manager(&path);
        restarted
            .acquire(&"a".repeat(64), &cached.selection, &AtomicBool::new(false))
            .await
            .unwrap();
        assert_eq!(restarted.inputs(), &cached.snapshot().unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // Make filesystem access fail. An unchanged hot-path selection must use only memory.
        foundation::durable::remove_path(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        restarted
            .reconcile(&"b".repeat(64), &cached.selection)
            .await
            .unwrap();
        assert_eq!(restarted.inputs(), &cached.snapshot().unwrap());
        let changed = cached_inputs(b"different credential");
        assert!(restarted
            .reconcile(&"b".repeat(64), &changed.selection)
            .await
            .is_err());
        assert_eq!(restarted.inputs(), &cached.snapshot().unwrap());
    }

    #[tokio::test]
    async fn recovery_pin_retains_its_inputs_when_the_live_cache_changes() {
        let directory = tempfile::tempdir().unwrap();
        let cache = directory.path().join("cache");
        let pin = directory.path().join("pin");
        let original = cached_inputs(b"old credential");
        write_private_record(&cache, &original).unwrap();
        let mut manager = offline_manager(&cache);
        manager
            .reconcile(&"a".repeat(64), &original.selection)
            .await
            .unwrap();
        manager.pin(&pin, &"c".repeat(64)).unwrap();
        write_private_record(&cache, &cached_inputs(b"new credential")).unwrap();
        let mut restarted = offline_manager(&cache);
        assert!(!restarted.restore_pin(&pin, &"d".repeat(64)).unwrap());
        assert!(restarted.restore_pin(&pin, &"c".repeat(64)).unwrap());
        assert_eq!(restarted.inputs(), &original.snapshot().unwrap());
        let corrupt = RecoveryInputs {
            attempt_id: "c".repeat(64),
            inputs: CachedInputs {
                selection: original.selection.clone(),
                body: cached_inputs(b"tampered").body,
            },
        };
        write_private_record(&pin, &corrupt).unwrap();
        assert!(restarted.restore_pin(&pin, &"c".repeat(64)).is_err());
        write_private_record(&cache, &corrupt.inputs).unwrap();
        assert!(offline_manager(&cache)
            .reconcile(&"a".repeat(64), &original.selection)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_superseded_boot_input_assignment_exits_for_refresh() {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
            }
            reader
                .get_mut()
                .write_all(
                    b"HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let snapshot = FileSnapshot {
            files: [(
                "password".into(),
                updated_contracts::dataflow::FileValue::from_bytes(b"test").unwrap(),
            )]
            .into_iter()
            .collect(),
        };
        let selection = InputPublication::from_snapshot(snapshot, &[7u8; 32])
            .unwrap()
            .selection()
            .unwrap();
        let mut manager = RuntimeDataManager {
            gateway_base_url: Some(base),
            control_client: Some(reqwest::Client::new()),
            object_client: Some(reqwest::Client::new()),
            current: FileSnapshot::default(),
            current_selection: InputSelection::default(),
            current_body: String::new(),
            cache_path: crate::test_support::nonexistent_root().join("inputs.json"),
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            manager.acquire(&"a".repeat(64), &selection, &AtomicBool::new(false)),
        )
        .await;
        assert!(
            matches!(result, Ok(Err(InputError::Superseded))),
            "{result:?}"
        );
        assert!(manager.current.files.is_empty());
        server.join().unwrap();
    }

    fn routing(base_url: &str) -> Routing {
        Routing {
            root: "/var/lib/updated/routing".into(),
            base_url: base_url.into(),
            assignment: "assignments/agents/node.json".into(),
            transport_timeout: std::time::Duration::from_secs(30),
            mtls: updated::tls::Identity::new("client.pem", "client.key", "ca.pem"),
        }
    }

    #[test]
    fn local_repositories_refuse_inputs_they_cannot_fetch() {
        let local = crate::test_support::local_repository_base();
        let input = InputSelection {
            generation: "a".repeat(64),
            object_sha256: "b".repeat(64),
            files: ["host".to_string()].into_iter().collect(),
        };
        assert!(RuntimeDataManager::new(
            &routing(&local),
            &input,
            &crate::test_support::nonexistent_root()
        )
        .is_err());
        assert!(RuntimeDataManager::new(
            &routing(&local),
            &InputSelection::default(),
            &crate::test_support::nonexistent_root()
        )
        .is_ok());
    }

    #[test]
    fn object_store_cannot_substitute_assigned_input_bytes() {
        let snapshot = FileSnapshot {
            files: [(
                "password".into(),
                updated_contracts::dataflow::FileValue::from_bytes(b"real").unwrap(),
            )]
            .into_iter()
            .collect(),
        };
        let publication = InputPublication::from_snapshot(snapshot.clone(), &[7u8; 32]).unwrap();
        let inputs = publication.selection().unwrap();
        let bytes = publication.to_bounded_body().unwrap();
        let capability = DownloadCapability {
            schema: DownloadCapability::SCHEMA,
            url: "https://objects.example/input?X-Amz-Signature=secret".into(),
            sha256: inputs.object_sha256.clone(),
        };
        assert_eq!(
            decode_snapshot(&capability, &inputs, &bytes).unwrap(),
            snapshot
        );

        let substituted = InputPublication::from_snapshot(
            FileSnapshot {
                files: [(
                    "password".into(),
                    updated_contracts::dataflow::FileValue::from_bytes(b"attacker").unwrap(),
                )]
                .into_iter()
                .collect(),
            },
            &[7u8; 32],
        )
        .unwrap()
        .to_bounded_body()
        .unwrap();
        assert!(decode_snapshot(&capability, &inputs, &substituted).is_err());

        let substituted_capability = DownloadCapability {
            sha256: updated_contracts::digest::sha256_bytes(&substituted),
            ..capability
        };
        assert!(
            decode_snapshot(&substituted_capability, &inputs, &substituted).is_err(),
            "even a capability matching attacker bytes cannot override the TUF-signed commitment"
        );
    }

    #[tokio::test]
    async fn an_unchanged_signed_selection_uses_the_last_authenticated_snapshot() {
        let snapshot = FileSnapshot {
            files: [(
                "password".into(),
                updated_contracts::dataflow::FileValue::from_bytes(b"already authenticated")
                    .unwrap(),
            )]
            .into_iter()
            .collect(),
        };
        let selection = InputPublication::from_snapshot(snapshot.clone(), &[7u8; 32])
            .unwrap()
            .selection()
            .unwrap();
        let mut manager = RuntimeDataManager::new(
            &routing(&crate::test_support::local_repository_base()),
            &InputSelection::default(),
            &crate::test_support::nonexistent_root(),
        )
        .unwrap();
        manager.current = snapshot.clone();
        manager.current_selection = selection.clone();

        manager
            .reconcile(&"a".repeat(64), &selection)
            .await
            .expect("no capability endpoint is needed for unchanged authenticated bytes");
        assert_eq!(manager.inputs(), &snapshot);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn boot_loads_assigned_inputs_before_both_recovery_hooks() {
        use crate::test_support::{digest, lineage};
        use std::os::unix::fs::PermissionsExt;
        use updated::bundle::ExpectedBundle;
        use updated::bundle_store::BundleStore;
        use updated::state::InstalledState;

        let directory = tempfile::tempdir().unwrap();
        let mut opts = crate::tests::options();
        opts.paths =
            updated::config::Paths::resolve(directory.path(), &directory.path().join("identity"));
        opts.application.install_root = directory.path().to_path_buf();
        opts.timeouts = crate::BoundedTimeouts::new(updated::config::Timeouts {
            // This gate launches real helper and shell processes, including with coverage and
            // FIPS enabled in CI. Its deadline must allow process startup on a busy runner.
            health_grace: std::time::Duration::from_secs(5),
            health_interval: std::time::Duration::from_millis(50),
            ..updated::config::Timeouts::default()
        });
        let snapshot = FileSnapshot {
            files: [(
                "password".into(),
                updated_contracts::dataflow::FileValue::from_bytes(b"recovery-credential").unwrap(),
            )]
            .into(),
        };
        let publication = InputPublication::from_snapshot(snapshot.clone(), &[7; 32]).unwrap();
        let selection = publication.selection().unwrap();
        opts.application.input_selection = selection.clone();
        // The manager owns authenticated bytes, while the boot's invocation snapshot starts
        // empty exactly as parse_args initializes it. Boot must acquire before either hook.
        opts.runtime_data.current = snapshot;
        opts.runtime_data.current_selection = selection;
        opts.runtime_data.current_body =
            String::from_utf8(publication.to_bounded_body().unwrap()).unwrap();
        opts.runtime_data.cache_path = opts.paths.runtime_inputs.clone();
        assert!(opts.inputs.files.is_empty());

        let source = directory.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("payload"), "configuration").unwrap();
        let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        let stage_payload = |version| {
            let archive = directory.path().join(format!("payload-{version}.tar.zst"));
            updated::bundle::create_bundle(&source, &archive, "app", version, &platform).unwrap();
            let release = BundleStore::for_app(&opts.paths)
                .install(
                    &archive,
                    &ExpectedBundle {
                        product: "app",
                        version,
                        platform: &platform,
                    },
                )
                .unwrap();
            (release, updated::hash::sha256_file(&archive).unwrap())
        };
        let script = r#"#!/bin/sh
set -eu
input=$UPDATED_INPUT_DIR
state=$UPDATED_STATE_DIR
operation=$UPDATED_OPERATION
[ "$(cat "$input/password")" = recovery-credential ]
case "$operation" in
  rollback|converge)
    cp "$input/password" "$state/$operation-observed"
    printf '%s' '{"api":1,"command":"succeed","changed":false}' | "$UPDATED_RECONCILER_HELPER" reconciler-helper
    ;;
  healthcheck) cp "$input/password" "$state/healthcheck-observed"; test -f "$state/healthy" ;;
esac
"#;
        let hook = source.join("hook");
        std::fs::write(&hook, script).unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
        let command = serde_json::json!({"argv":["./hook"],"timeoutSeconds":5});
        std::fs::write(
            source.join(updated::command_adapter::CONFIG),
            serde_json::json!({"schema":1,
            "deploy":command,"health":command,"replay":{"policy":"safe"},
            "recovery":{"policy":"command","command":command,"replay":{"policy":"safe"}}})
            .to_string(),
        )
        .unwrap();
        let (previous, previous_sha) = stage_payload("1.0.0");
        let (candidate, candidate_sha) = stage_payload("2.0.0");
        let reconciler = Box::new(updated::command_adapter::execution_for(&source, "app").unwrap());
        opts.helper_executable = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("updated-agent");
        let installed = InstalledState::proven(
            lineage(),
            previous.clone(),
            previous_sha.clone(),
            reconciler.clone(),
        );
        let mut store = crate::Store::open(opts.paths.clone()).unwrap();
        updated::state::record_first_install(&opts.paths.installed).unwrap();
        // Seed the pre-crash fixture; all recovery writes below use Store's policy boundary.
        #[allow(clippy::disallowed_methods)]
        {
            updated::state::write_installed(&opts.paths.installed, &installed).unwrap();
        }
        store.activate(&installed.release).unwrap();
        // Exercise the real steady-state hook/gate path, including a no-op converge and a
        // grace longer than the check cadence. A report must see the newly observed verdict,
        // not the false flag set immediately before mutation.
        let state_dir = opts.paths.reconciler_state_dir("app");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(state_dir.join("healthy"), b"ready").unwrap();
        opts.inputs = opts.runtime_data.inputs().clone();
        let mut health = crate::HealthWatch::after_boot_gate(&opts.timeouts, false);
        for _ in 0..2 {
            let result = crate::reconverge_environment(&opts, &store, &mut health)
                .await
                .unwrap();
            assert!(!result.changed());
            assert!(
                health.last_ready,
                "a successful post-converge gate must be reported healthy"
            );
        }
        std::fs::remove_file(state_dir.join("healthy")).unwrap();
        crate::reconverge_environment(&opts, &store, &mut health)
            .await
            .unwrap();
        assert!(
            !health.last_ready,
            "an unhealthy post-converge gate must remain unready"
        );
        // Boot still starts with no invocation inputs: only its acquisition can supply them.
        opts.inputs = FileSnapshot::default();
        let mut tx = updated::transaction::Transaction {
            id: digest("attempt"),
            previous_release: previous,
            previous_archive_sha256: previous_sha,
            previous_repository_lineage: lineage(),
            candidate_release: candidate,
            candidate_rejection_sha256: updated_contracts::digest::deployment_rejection_sha256(
                &candidate_sha,
            )
            .unwrap(),
            candidate_archive_sha256: candidate_sha,
            candidate_repository_lineage: lineage(),
            candidate_rejection_required: false,
            previous_reconciler: reconciler.clone(),
            candidate_reconciler: reconciler,
            rollback_health_failures: 0,
            phase: updated::transaction::Phase::Prepared,
        };
        // Execute the candidate once so recovery consumes actual durable mutation evidence.
        opts.inputs = opts.runtime_data.inputs().clone();
        crate::update::run_reconciler_mutation(
            &tx.candidate_reconciler,
            &opts,
            updated_contracts::reconciler::MutationOperation::Converge,
            crate::update::ReconcilerInvocation {
                reason: updated_contracts::reconciler::Reason::Update,
                id: &tx.id,
                candidate: crate::update::ReleaseTarget {
                    release: &tx.candidate_release,
                    archive_sha256: &tx.candidate_archive_sha256,
                },
                predecessor: crate::update::ReleaseTarget {
                    release: &tx.previous_release,
                    archive_sha256: &tx.previous_archive_sha256,
                },
            },
            None,
        )
        .unwrap();
        opts.inputs = FileSnapshot::default();
        opts.runtime_data
            .pin(&opts.paths.recovery_inputs, &tx.id)
            .unwrap();
        // Drop all in-memory input evidence and change the live selection. Recovery must use
        // the persisted transaction pin without asking the unavailable gateway for either one.
        opts.runtime_data.current = FileSnapshot::default();
        opts.runtime_data.current_selection = InputSelection::default();
        opts.runtime_data.current_body.clear();
        opts.application.input_selection = InputSelection::default();
        store.write_journal(&tx).unwrap();
        store.activate(&tx.candidate_release).unwrap();
        tx.advance(updated::transaction::Phase::RollbackPlanned)
            .unwrap();
        store.write_journal(&tx).unwrap();
        let state_dir = opts.paths.reconciler_state_dir("app");
        let error = crate::run(opts).await.unwrap_err();
        assert!(
            error.to_string().contains("operator attention required"),
            "{error}"
        );
        for operation in ["rollback", "healthcheck"] {
            assert_eq!(
                std::fs::read(state_dir.join(format!("{operation}-observed"))).unwrap(),
                b"recovery-credential"
            );
        }
        assert!(updated::command_adapter::read_attention(directory.path())
            .unwrap()
            .is_some());
    }
}
