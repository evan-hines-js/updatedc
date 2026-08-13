//! Application acquisition: everything before activation.
//!
//! The long-running and update-before-launch front ends own different process lifecycles, but the
//! steps up to activation are identical and live here: exact assignment selection, policy
//! authorization, rejection filtering, verified download, and bounded bundle installation.

use std::io;

use updated::bundle::{ExpectedBundle, InstallError, ReleaseId};
use updated::config::{Application, Paths};
use updated::provider::BundleStore;
use updated_tuf::select::target_sha;
use updated_tuf::{DefaultPolicy, TrustedRepository, VerifiedTarget};

pub(crate) struct ApplicationRequest<'a> {
    pub(crate) repository: &'a TrustedRepository,
    pub(crate) application: &'a Application,
    pub(crate) paths: &'a Paths,
    pub(crate) current_version: Option<&'a str>,
}

#[derive(Debug)]
pub(crate) struct PreparedApplication {
    pub(crate) release: ReleaseId,
    pub(crate) version: String,
    pub(crate) archive_sha256: String,
}

#[derive(Debug)]
pub(crate) enum PrepareError {
    Repository(updated_tuf::Error),
    /// The archive is bad, and these bytes may be rejected durably. Constructed only from
    /// [`updated::bundle::InstallError::Archive`].
    Bundle {
        version: String,
        archive_sha256: String,
        source: io::Error,
    },
    /// This node could not stage the bundle. Carries no archive hash *by construction*, so it
    /// cannot become a rejection however the caller handles it.
    Storage(io::Error),
}

#[derive(Debug)]
pub(crate) enum AcquireBundleError {
    Repository(updated_tuf::Error),
    /// The archive is bad: the only variant a caller may turn into a durable rejection.
    Invalid {
        archive_sha256: String,
        source: io::Error,
    },
    /// Staging failed locally — a full disk, a revoked directory, a failing device. Always
    /// retryable, never a verdict on the bytes, so it carries no hash to reject.
    Storage(io::Error),
}

impl std::fmt::Display for AcquireBundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Repository(error) => write!(f, "{error}"),
            Self::Invalid { source, .. } => write!(f, "invalid verified bundle: {source}"),
            Self::Storage(error) => write!(f, "staging the verified bundle failed: {error}"),
        }
    }
}

impl std::error::Error for AcquireBundleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Repository(error) => Some(error),
            Self::Invalid { source, .. } | Self::Storage(source) => Some(source),
        }
    }
}

impl PrepareError {
    /// The `(version, archive_sha256)` a caller may record as permanently rejected, or `None`
    /// when the failure said nothing about the bytes.
    ///
    /// A rejection is durable and never expires, so this is deliberately answerable only from
    /// the one variant built out of evidence about the archive: a transport failure, a local
    /// staging failure, or a drifted committed tree can never reach it.
    pub(crate) fn rejected_archive(&self) -> Option<(&str, &str)> {
        match self {
            Self::Bundle {
                version,
                archive_sha256,
                ..
            } => Some((version, archive_sha256)),
            Self::Repository(_) | Self::Storage(_) => None,
        }
    }
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Repository(error) => write!(f, "{error}"),
            Self::Bundle {
                version, source, ..
            } => write!(f, "staging application bundle {version} failed: {source}"),
            Self::Storage(error) => write!(f, "staging the application bundle failed: {error}"),
        }
    }
}

impl std::error::Error for PrepareError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Repository(error) => Some(error),
            Self::Bundle { source, .. } | Self::Storage(source) => Some(source),
        }
    }
}

/// Prepare the exact application assigned by the verified control plane.
///
/// `Ok(None)` means the current version is already desired or these exact bytes were
/// previously rejected. Activation and rejection persistence remain front-end policy.
pub(crate) async fn prepare_assigned_application(
    request: ApplicationRequest<'_>,
    mut is_rejected: impl FnMut(&str) -> bool,
) -> Result<Option<PreparedApplication>, PrepareError> {
    let policy = DefaultPolicy::current(&request.application.product, &request.application.channel);
    // Rejection filtering now happens inside selection: exact-pin returns None when
    // the assigned bytes are rejected (hold predecessor), and ordered fallback skips
    // rejected targets as it descends. Diagnostics are dropped here; the agent's
    // own selection path logs skips.
    let Some(selected) = request
        .repository
        .assigned_application(
            &policy,
            request.current_version,
            |_message| {},
            |target, _version| is_rejected(&target_sha(target)),
        )
        .map_err(PrepareError::Repository)?
    else {
        return Ok(None);
    };
    let platform = foundation::platform::platform_key();
    let store =
        BundleStore::for_app(request.paths).with_target_limit(request.repository.target_limit());
    let id = acquire_verified_bundle(
        request.repository,
        &selected.target,
        &request.paths.download,
        &store,
        &ExpectedBundle {
            product: &request.application.product,
            version: &selected.version,
            platform: &platform,
        },
    )
    .await
    .map_err(|error| match error {
        AcquireBundleError::Repository(error) => PrepareError::Repository(error),
        AcquireBundleError::Storage(error) => PrepareError::Storage(error),
        AcquireBundleError::Invalid {
            archive_sha256,
            source,
        } => PrepareError::Bundle {
            version: selected.version.clone(),
            archive_sha256,
            source,
        },
    })?;
    Ok(Some(PreparedApplication {
        release: id,
        version: selected.version,
        archive_sha256: selected.sha256,
    }))
}

/// Download and install one metadata-authenticated bundle through the canonical
/// bounded bundle store. Every bundle kind uses this operation.
///
/// The store already separates a verdict on the archive from a failure of this node; that split
/// is carried through here rather than flattened, because the caller turns one of them into a
/// permanent, never-expiring rejection of the release.
pub(crate) async fn acquire_verified_bundle(
    repository: &TrustedRepository,
    target: &VerifiedTarget,
    destination: &std::path::Path,
    store: &BundleStore,
    expected: &ExpectedBundle<'_>,
) -> Result<ReleaseId, AcquireBundleError> {
    repository
        .download_target(target, destination)
        .await
        .map_err(AcquireBundleError::Repository)?;
    store
        .install(destination, expected)
        .map_err(|error| match error {
            InstallError::Archive(source) => AcquireBundleError::Invalid {
                archive_sha256: target_sha(target),
                source,
            },
            InstallError::Storage(source) => AcquireBundleError::Storage(source),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the split: a rejection is durable and never expires, so nothing but
    /// evidence about the archive itself may reach `rejected_archive`. A staging failure that
    /// could be attributed to the bytes once permanently bricked a healthy release on every node
    /// that hit it.
    #[test]
    fn only_a_verdict_on_the_archive_is_ever_rejectable() {
        assert_eq!(
            PrepareError::Storage(io::Error::other("no space left on device")).rejected_archive(),
            None
        );
        assert_eq!(
            PrepareError::Repository(updated_tuf::Error::Transport("timed out".into()))
                .rejected_archive(),
            None
        );
        let sha = "a".repeat(64);
        assert_eq!(
            PrepareError::Bundle {
                version: "1.2.3".into(),
                archive_sha256: sha.clone(),
                source: io::Error::other("bundle manifest disagrees with authenticated metadata"),
            }
            .rejected_archive(),
            Some(("1.2.3", sha.as_str()))
        );
    }

    /// A local staging failure keeps its identity all the way across the crate boundary, so no
    /// caller can rediscover a hash to reject from it.
    #[test]
    fn a_storage_failure_carries_no_archive_hash_at_any_layer() {
        let acquired = AcquireBundleError::Storage(io::Error::other("staging root is unusable"));
        let prepared = match acquired {
            AcquireBundleError::Storage(error) => PrepareError::Storage(error),
            other => panic!("unexpected classification: {other}"),
        };
        assert!(prepared.rejected_archive().is_none());
        assert!(prepared
            .to_string()
            .contains("staging the application bundle failed"));
    }
}
