//! Runtime types materialized exclusively from a TUF-verified managed configuration.
//! The only node-local configuration is the URL-and-key enrollment bootstrap.

use std::path::{Path, PathBuf};
use std::time::Duration;

use updated_contracts::assignment::{ManagedRuntime, ManagedStorage};

/// Fully verified, materialized runtime configuration.
#[derive(Debug)]
pub struct Config {
    pub deployment: String,
    /// SHA-256 of the exact TUF-authenticated assignment document this runtime was materialized
    /// from. Assigned-input requests name it so a gateway authorization cached for a predecessor
    /// can never feed stale values to this configuration.
    pub assignment_sha256: String,
    pub routing: Routing,
    pub application: Application,
    /// The retention bounds the signed runtime carries, held as the contract's own type. Bounds
    /// for inactive immutable material: releases needed by installed state, rollback state, or an
    /// active transaction are always protected regardless of these limits, which apply only to
    /// disposable history. A node-local twin of this struct — the same five fields under a local
    /// name, copied across field by field — is the drift
    /// `node_adapter_does_not_redeclare_or_reexport_wire_contracts` forbids: a sixth retention
    /// bound added to the contract would compile clean and be silently dropped on the node.
    pub storage: ManagedStorage,
    pub timeouts: Timeouts,
}

/// Bootstrap trust for the small routing repository. `base_url` is the only
/// repository URL configured on a node; its `metadata/` and `targets/` children
/// contain a TUF repository whose verified assignment selects the release CDN.
#[derive(Debug, Clone)]
pub struct Routing {
    pub root: PathBuf,
    pub base_url: String,
    /// Exact TUF target to resolve (for example `assignments/agents/agent-123.json`).
    pub assignment: String,
    pub transport_timeout: Duration,
    /// The agent's mTLS identity for reaching the private routing gateway — mandatory, never
    /// plaintext. Release clients may reuse its CA bundle as TLS trust, but never its client
    /// certificate: release objects are fetched anonymously from the assignment-selected origin.
    pub mtls: crate::tls::Identity,
}

impl Routing {
    /// Whether this routing repository is local (a `file:` URL or an absolute directory path)
    /// rather than a network gateway. See [`base_url_is_local`].
    pub fn is_local(&self) -> Result<bool, String> {
        base_url_is_local(&self.base_url)
    }
}

/// Whether a routing `base_url` names a local repository (a `file:` URL or an absolute directory
/// path) rather than a network gateway. The single definition of "local" — the offline-repair path,
/// assigned-input manager, and enrollment all gate on it, and must agree: one deciding to reach the
/// network while another assumes offline would split the trust model. Classification is fallible:
/// an invalid location is neither silently "remote" nor silently "local".
pub fn base_url_is_local(base_url: &str) -> Result<bool, String> {
    updated_contracts::assignment::canonical_repository_base(base_url)
        .map(|url| url.scheme() == "file")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod repository_location_tests {
    use super::base_url_is_local;

    #[test]
    fn locality_uses_the_canonical_repository_grammar() {
        #[cfg(windows)]
        let native_file_base = "FILE:///C:/updated/";
        #[cfg(not(windows))]
        let native_file_base = "FILE:///opt/updated/";

        assert!(base_url_is_local(native_file_base).unwrap());
        assert!(!base_url_is_local("https://EXAMPLE.com:443/").unwrap());
        assert!(base_url_is_local("file:relative").is_err());
        assert!(base_url_is_local("http://example.com/").is_err());
    }
}

/// Fully resolved repository input. Values of this type are constructed only
/// after parsing a TUF-verified [`RepositoryAssignment`].
#[derive(Debug, Clone)]
pub struct RepositorySource {
    pub root: PathBuf,
    pub metadata_url: String,
    pub targets_url: String,
    pub metadata_limit: u64,
    pub target_limit: u64,
    pub transport_timeout: Duration,
    /// Whether the first HTTP hop is the mTLS gateway that mints an exact S3 read capability, or
    /// an already-direct release repository. This is explicit so a client identity can never be
    /// offered to a host merely because it appeared in a signed release assignment.
    pub access: RepositoryAccess,
    pub mtls: crate::tls::Identity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryAccess {
    GatewayCapability,
    Direct,
}

impl Application {
    /// The launch spec and probes the signed runtime carries. The single construction path for
    /// [`Application`] — used both when the config is first materialized and when a running agent
    /// reconciles a control-plane reassignment.
    pub fn from_runtime(runtime: &ManagedRuntime) -> Application {
        Application {
            product: runtime.product.clone(),
            channel: runtime.channel.clone(),
            install_root: runtime.install_root.clone(),
            input_selection: runtime.inputs.clone(),
        }
    }
}

impl Timeouts {
    /// The cadence and health-gate windows the signed runtime carries. Single construction path,
    /// shared by materialization and steady-state reassignment.
    pub fn from_runtime(runtime: &ManagedRuntime) -> Timeouts {
        Timeouts {
            check_interval: Duration::from_secs(runtime.timeouts.check_interval_seconds),
            health_grace: Duration::from_secs(runtime.timeouts.health_grace_seconds),
            health_successes: runtime.timeouts.health_successes,
            health_interval: Duration::from_secs(runtime.timeouts.health_interval_seconds),
            refresh_retry: Duration::from_secs(runtime.timeouts.refresh_retry_seconds),
            confirmation_window: Duration::from_secs(runtime.timeouts.confirmation_window_seconds),
            agent_check_interval: Duration::from_secs(
                runtime.timeouts.agent_check_interval_seconds,
            ),
        }
    }
}

impl Config {
    /// The whole local configuration one signed runtime materializes into.
    pub fn materialize(
        runtime: &ManagedRuntime,
        deployment: &str,
        assignment_sha256: &str,
        routing: Routing,
    ) -> Result<Config, String> {
        // This is the sole boundary where portable signed paths become node-local filesystem
        // authority. Publication validation deliberately accepts absolute roots for every
        // supported OS; materialization must additionally require this node's path semantics.
        runtime.validate_for_current_platform()?;
        if !updated_contracts::is_canonical_sha256(assignment_sha256) {
            return Err("materialized assignment identity is not a canonical SHA-256".into());
        }
        // The release root is NOT materialized here. `TrustedRepository::assigned` writes the root
        // it actually pins, into the per-assignment datastore, from the assignment it just
        // verified. Writing a second copy from here — out of a config that may have come from an
        // unverified persisted file — produced a durable trust anchor nothing ever read.
        Ok(Config {
            deployment: deployment.to_owned(),
            assignment_sha256: assignment_sha256.to_owned(),
            routing,
            application: Application::from_runtime(runtime),
            storage: runtime.storage.clone(),
            timeouts: Timeouts::from_runtime(runtime),
        })
    }
}

/// The program being kept current.
#[derive(Debug)]
pub struct Application {
    pub product: String,
    pub channel: String,
    /// Root containing active-release, immutable versions, staging, and durable state.
    pub install_root: PathBuf,
    /// Descriptor of the file bundle authorized by the signed assignment. The corresponding bytes
    /// live in private S3 and are fetched through a short-lived exact-object capability.
    pub input_selection: updated_contracts::dataflow::InputSelection,
}

/// Every tunable duration in the system, in one place. Omit any (or the whole
/// `[timeouts]` table) to take the default.
#[derive(Debug, Clone)]
pub struct Timeouts {
    /// How often to check for an application update.
    pub check_interval: Duration,
    /// Window for the `healthcheck` hook to report the deployed release ready after an apply. The
    /// hook is the only health source (see the Execution contract in
    /// `docs/node-reconciler-protocol.md`), so this is also the full detection latency for a release
    /// that never comes up — a longer grace buys a slow starter more room, and costs exactly that
    /// much delay on a release that will never answer. Set it to minutes if the release needs it.
    pub health_grace: Duration,
    /// Consecutive good health responses required to declare the app ready (a
    /// readiness `successThreshold`). Default 1 — the first good answer commits;
    /// raise it to require sustained health before trusting a new version.
    pub health_successes: u32,
    /// Spacing between those confirmation probes (a readiness `periodSeconds`), so
    /// `health_successes > 1` proves health over time, not a 100 ms burst. Ignored
    /// when `health_successes` is 1.
    pub health_interval: Duration,
    /// Backoff base for retrying a transient metadata transport failure.
    pub refresh_retry: Duration,
    /// How long a just-committed update stays unconfirmed. A failed boot gate inside it — a
    /// `healthcheck` verdict on the next agent boot — reverts to the predecessor (one strike);
    /// surviving it confirms the update and drops the rollback image.
    pub confirmation_window: Duration,
    /// How often to check for an agent release.
    pub agent_check_interval: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            check_interval: Duration::from_secs(15),
            // Forgiving enough for a reconciler that takes a few seconds to bring the workload
            // up; the first good `healthcheck` answer returns immediately, so a longer window
            // never slows a healthy release. Raise it for a workload that legitimately takes tens
            // of seconds or minutes to start.
            health_grace: Duration::from_secs(10),
            health_successes: 1,
            health_interval: Duration::from_secs(1),
            refresh_retry: Duration::from_secs(5),
            confirmation_window: Duration::from_secs(120),
            agent_check_interval: Duration::from_secs(3600),
        }
    }
}

/// The one canonical immutable-release layout shared by agent and one-shot mode.
#[derive(Debug, Clone)]
pub struct Paths {
    pub install_root: PathBuf,
    pub versions: PathBuf,
    pub staging: PathBuf,
    /// Per-release writable working directories for the managed application — the launch `cwd`.
    /// Deliberately a sibling of `versions/`, never a child of it: `versions/<release>` is the
    /// content-addressed tree `bundle::verify_release` re-hashes on every check, so a single file
    /// an ordinary application writes to its own working directory would make the agent
    /// condemn, re-download and republish the release forever. See [`crate::provider::BundleStore`].
    pub work: PathBuf,
    pub active_release: PathBuf,
    pub download: PathBuf,
    /// The durable-state directory itself. Every record below that lives directly in it is also
    /// named here as a file path; new records join it via this field, never by taking a `.parent()`
    /// of one of the files.
    pub state_dir: PathBuf,
    /// The installed-releases record, `state_dir/installed.json`.
    pub installed: PathBuf,
    pub datastore: PathBuf,
    pub routing_datastore: PathBuf,
    pub assignment: PathBuf,
    pub journal: PathBuf,
    pub install_journal: PathBuf,
    pub rejected: PathBuf,
    /// Durable platform-owned evidence for the latest successful state-changing reconciler run.
    pub last_reconciliation: PathBuf,
    pub provider_versions: PathBuf,
    pub provider_staging: PathBuf,
    pub provider_download: PathBuf,
    /// The same writable working directories for lifecycle-provider releases, which are re-verified
    /// on exactly the same terms every time one is invoked.
    pub provider_work: PathBuf,
    /// Root of the reconcilers' private per-product state directories — the parent of every
    /// `--state-dir`. Part of the layout rather than an invoker-local string because
    /// `docs/node-reconciler-protocol.md` promises a hook this directory is "preserved across
    /// replays and boots": moving it silently discards every hook's durable sub-progress.
    pub provider_state_root: PathBuf,
    /// Where the agent's internal snapshots of reconciler output directories land, partitioned by
    /// the candidate's immutable archive identity. Hooks see only fresh ordinary directories.
    pub provider_outputs: PathBuf,
}

/// Where the last live routing assignment is kept: beside the enrollment material in the
/// launcher's state directory, never under `install_root`.
///
/// This file is read *before any network fetch* to decide what the managed application is
/// launched with — its args, assigned input selection, and acceptable product/channel. Nothing
/// local can re-verify it at that moment, so it may only live
/// where every other boot input already lives: the enrollment directory that also holds the
/// node config, the enrollment bundle, and the node's private key. Kept under `install_root`
/// it would let write access to a directory full of otherwise-recoverable state choose the
/// managed process's arguments and secrets.
pub fn persisted_assignment_path(enrollment_state: &Path) -> PathBuf {
    enrollment_state.join("repository-assignment.json")
}

impl Paths {
    /// The canonical layout, derived from the only two roots it depends on: the install root that
    /// holds every replaceable artifact, and the enrollment state directory that holds every
    /// boot-time input. This is the single definition — production, tooling and tests all call it,
    /// so no second copy of the layout can drift from it.
    pub fn resolve(install_root: &Path, enrollment_state: &Path) -> Paths {
        let state_dir = install_root.join("state");
        Paths {
            install_root: install_root.to_path_buf(),
            versions: install_root.join("versions"),
            staging: install_root.join("staging"),
            work: install_root.join("work"),
            active_release: install_root.join("active-release"),
            download: install_root.join("staging/bundle.download"),
            installed: state_dir.join("installed.json"),
            state_dir: state_dir.clone(),
            datastore: state_dir.join("tuf"),
            // Routing trust is needed before `install_root` can be derived from the live signed
            // assignment, so its rollback floor belongs beside enrollment state, not below the
            // install root whose location that assignment defines.
            routing_datastore: enrollment_state.join("routing-tuf"),
            assignment: persisted_assignment_path(enrollment_state),
            journal: state_dir.join("transaction.json"),
            install_journal: state_dir.join("install.json"),
            rejected: state_dir.join("rejected"),
            last_reconciliation: state_dir.join("reconciliation.json"),
            provider_versions: install_root.join("providers/versions"),
            provider_staging: install_root.join("providers/staging"),
            provider_download: install_root.join("providers/staging/bundle.download"),
            provider_work: install_root.join("providers/work"),
            provider_state_root: install_root.join("providers/state"),
            provider_outputs: install_root.join("providers/outputs"),
        }
    }

    /// One reconciler's `--state-dir`: private to the product, so two lifecycle providers on one
    /// node never share scratch.
    pub fn reconciler_state_dir(&self, product: &str) -> PathBuf {
        self.provider_state_root.join(product)
    }

    /// Agent-internal canonical snapshot for one release manifest's last successful output
    /// directory. The manifest digest is the identity every lifecycle invocation already carries,
    /// so writers, telemetry readers, and retention all name this file the same way.
    pub fn reconciler_output_snapshot(&self, manifest_sha256: &str) -> PathBuf {
        self.provider_outputs
            .join(format!("{manifest_sha256}.json"))
    }
}

impl Config {
    /// Resolve the canonical bundle layout. The installer creates `install_root` and
    /// seeds its first active release before starting the service.
    pub fn resolve_paths(&self) -> Paths {
        // `routing.root` is the routing anchor materialized into the enrollment state directory,
        // so its parent is that directory — the one place boot-time inputs may come from.
        Paths::resolve(
            &self.application.install_root,
            foundation::durable::parent_dir(&self.routing.root),
        )
    }
}

/// Append `suffix` to a path's final component. Used for independent lock/download
/// siblings in the agent self-update path.
pub fn with_suffix(base: &Path, suffix: &str) -> PathBuf {
    let mut value = base.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}
