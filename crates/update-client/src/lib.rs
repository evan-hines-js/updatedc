//! Shared application acquisition core.
//!
//! The supervised and update-before-launch front ends intentionally own different
//! process lifecycles. Everything before activation is identical and lives here:
//! exact assignment selection, policy authorization, rejection filtering, verified
//! download, and bounded bundle installation.

use std::io;

use updated::bundle::{ExpectedBundle, ReleaseId, StagedRelease};
use updated::config::{Application, Paths, Repository};
use updated::provider::BundleStore;
use updated_tuf::select::target_sha;
use updated_tuf::{DefaultPolicy, TrustedRepository, VerifiedTarget};

pub struct ApplicationRequest<'a> {
    pub repository: &'a TrustedRepository,
    pub application: &'a Application,
    pub repository_config: &'a Repository,
    pub paths: &'a Paths,
    pub current_version: Option<&'a str>,
}

#[derive(Debug)]
pub struct PreparedApplication {
    pub release: ReleaseId,
    pub version: String,
    pub archive_sha256: String,
    /// The provider set signed with this app version, present only when ordered fallback
    /// descended below the assigned head. The caller stages *these* providers instead of the
    /// assignment's `provider_set`, so a rolled-back app runs its own signed providers.
    pub provider_set: Option<updated::config::TargetReference>,
}

#[derive(Debug)]
pub enum PrepareError {
    Repository(updated_tuf::Error),
    Bundle {
        version: String,
        archive_sha256: String,
        source: io::Error,
    },
}

#[derive(Debug)]
pub enum AcquireBundleError {
    Repository(updated_tuf::Error),
    Invalid {
        archive_sha256: String,
        source: io::Error,
    },
}

impl std::fmt::Display for AcquireBundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Repository(error) => write!(f, "{error}"),
            Self::Invalid { source, .. } => write!(f, "invalid verified bundle: {source}"),
        }
    }
}

impl std::error::Error for AcquireBundleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Repository(error) => Some(error),
            Self::Invalid { source, .. } => Some(source),
        }
    }
}

impl PrepareError {
    pub fn rejected_archive(&self) -> Option<(&str, &str)> {
        match self {
            Self::Bundle {
                version,
                archive_sha256,
                ..
            } => Some((version, archive_sha256)),
            Self::Repository(_) => None,
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
        }
    }
}

impl std::error::Error for PrepareError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Repository(error) => Some(error),
            Self::Bundle { source, .. } => Some(source),
        }
    }
}

/// Prepare the exact application assigned by the verified control plane.
///
/// `Ok(None)` means the current version is already desired or these exact bytes were
/// previously rejected. Activation and rejection persistence remain front-end policy.
pub async fn prepare_assigned_application(
    request: ApplicationRequest<'_>,
    mut is_rejected: impl FnMut(&str) -> bool,
) -> Result<Option<PreparedApplication>, PrepareError> {
    let policy = DefaultPolicy::current(&request.application.product, &request.application.channel);
    // Rejection filtering now happens inside selection: exact-pin returns None when
    // the assigned bytes are rejected (hold predecessor), and ordered fallback skips
    // rejected targets as it descends. Diagnostics are dropped here; the supervisor's
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
    let store = BundleStore::for_app(request.paths)
        .with_target_limit(request.repository_config.target_limit);
    let StagedRelease { id, .. } = acquire_verified_bundle(
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
        provider_set: selected.provider_set,
    }))
}

/// Download and install one metadata-authenticated bundle through the canonical
/// bounded bundle store. Every bundle kind uses this operation.
pub async fn acquire_verified_bundle(
    repository: &TrustedRepository,
    target: &VerifiedTarget,
    destination: &std::path::Path,
    store: &BundleStore,
    expected: &ExpectedBundle<'_>,
) -> Result<StagedRelease, AcquireBundleError> {
    repository
        .download_target(target, destination)
        .await
        .map_err(AcquireBundleError::Repository)?;
    store
        .install(destination, expected)
        .map_err(|source| AcquireBundleError::Invalid {
            archive_sha256: target_sha(target),
            source,
        })
}
