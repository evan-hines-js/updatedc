use super::*;

pub(crate) enum AppOutcome {
    Upgraded {
        version: String,
        host_action: updated_contracts::reconciler::HostAction,
    },
    Unchanged,
    /// The update cannot proceed and cannot be recovered from in this process. The agent exits
    /// non-zero with its durable evidence intact; the launcher relaunches it (throttled by its
    /// backoff) and boot recovery re-derives the recovery from that evidence.
    Fatal(String),
    /// A post-activation update failure: the candidate is rejected and its rollback journal is
    /// durable. This disposable agent terminates *cleanly* so the launcher relaunches it and
    /// boot recovery performs the (single) rollback. Distinct from `Fatal` only in that it is an
    /// expected, planned restart rather than a failure — the exit code is the difference an
    /// operator sees.
    RestartForRecovery,
}

fn is_self_version(installed: &updated::state::Installed, candidate: &str) -> bool {
    matches!(
        installed,
        updated::state::Installed::Present(state) if state.release.version == candidate
    )
}

/// Reuse the committed application as the candidate for a provider-only revision. The provider
/// still changes through the normal transaction; this helper only proves that the application
/// half is already the exact archive the assignment names.
fn provider_only_candidate(
    installed: &updated::state::Installed,
    assigned_application_sha256: &str,
    reconciler: &updated::state::ProviderRelease,
) -> Option<crate::acquire::PreparedApplication> {
    let updated::state::Installed::Present(state) = installed else {
        return None;
    };
    (state.archive_sha256 == assigned_application_sha256 && state.lifecycle.as_ref() != reconciler)
        .then(|| crate::acquire::PreparedApplication {
            release: state.release.clone(),
            version: state.release.version.clone(),
            archive_sha256: state.archive_sha256.clone(),
        })
}

/// Why staging a version's lifecycle providers failed.
///
/// The distinction is load-bearing for cold install: a caller that rejects the application archive
/// on ANY failure turns a brief CDN outage or a full disk into a permanent, never-expiring
/// rejection of every release it walks past — the node then has nothing installable even once the
/// network is back. Only a verdict about the *content* may reject.
pub(crate) enum ProviderStagingError {
    /// The provider set is genuinely unusable: malformed, invalid, or naming a reconciler already
    /// rejected.
    Unusable(String),
    /// An I/O, network, or storage failure. It says nothing about the release; retry later.
    Transient(String),
}

impl std::fmt::Display for ProviderStagingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unusable(message) | Self::Transient(message) => f.write_str(message),
        }
    }
}

/// Decode bytes already verified against the signed provider-set digest and persist the only
/// permanent verdict this layer can prove about that document.
///
/// Resolution and download failures stay outside this function because either may be repaired
/// without changing the signed digest. Once digest-verified bytes fail the bounded contract,
/// however, those exact bytes can never become a valid provider set. Recording that fact here
/// keeps selection's never-retry check and heartbeat's rejection report on the same evidence path.
fn decode_provider_set(
    store: &mut Store,
    lineage: &updated::state::RepositoryLineage,
    provider_set_sha256: &str,
    bytes: &[u8],
) -> Result<updated_contracts::artifact::ProviderSet, ProviderStagingError> {
    match updated_contracts::artifact::ProviderSet::from_bounded_json(bytes) {
        Ok(set) => Ok(set),
        Err(error) => {
            let message = format!("desired provider set is invalid: {error}");
            store
                .reject_artifact(lineage, provider_set_sha256)
                .map_err(|reject_error| {
                    ProviderStagingError::Transient(format!(
                        "{message}; recording its rejection also failed: {reject_error}"
                    ))
                })?;
            Err(ProviderStagingError::Unusable(message))
        }
    }
}

/// Reject a reconciler archive and the exact provider-set document that binds it as one unusable
/// deployed unit. The archive verdict prevents any set from retrying the same bad bytes; the set
/// verdict lets application selection skip only candidates that resolve through this binding,
/// without poisoning an otherwise healthy application archive.
fn reject_provider_unit(
    store: &mut Store,
    lineage: &updated::state::RepositoryLineage,
    provider_set_sha256: &str,
    provider_archive_sha256: &str,
    message: String,
) -> ProviderStagingError {
    for (kind, digest) in [
        ("node reconciler", provider_archive_sha256),
        ("provider set", provider_set_sha256),
    ] {
        if let Err(error) = store.reject_artifact(lineage, digest) {
            return ProviderStagingError::Transient(format!(
                "{message}; recording the {kind} rejection also failed: {error}"
            ));
        }
    }
    ProviderStagingError::Unusable(message)
}

pub(crate) async fn stage_providers(
    opts: &Options,
    repo: &TrustedRepository,
    store: &mut Store,
    version_provider_set: Option<&updated_contracts::artifact::TargetReference>,
) -> Result<updated::state::ProviderRelease, ProviderStagingError> {
    use ProviderStagingError::Transient;
    let unusable = ProviderStagingError::Unusable;
    let assignment = repo
        .assignment_context()
        .ok_or_else(|| unusable("release repository has no desired deployment".into()))?;
    let lineage = assignment.repository_lineage();
    let assignment = assignment.document();
    std::fs::create_dir_all(&opts.paths.provider_staging).map_err(|e| {
        Transient(format!(
            "creating lifecycle provider staging directory failed: {e}"
        ))
    })?;
    // The set staged here is the one that governs the app version the caller already selected
    // (`acquire::select_assigned_application`, which is where that single decision is made). When
    // ordered fallback descends below the assigned head (the head bytes are unusable), the
    // descended app version's own signed provider set governs — app and providers roll back as
    // one signed unit rather than pairing an old app with the head's newer providers. At the
    // assigned head that set is `None` and the assignment's own pointer governs, keeping providers
    // independently revisable there.
    let provider_ref = version_provider_set
        .cloned()
        .unwrap_or_else(|| assignment.provider_set.clone());
    let set_target = repo
        .exact_target(&provider_ref)
        .map_err(|e| unusable(format!("resolving desired provider set failed: {e}")))?;
    if set_target.length > updated_contracts::artifact::ProviderSet::MAX_DOCUMENT_BYTES as u64 {
        return Err(unusable(format!(
            "desired provider set is {} bytes, past the {}-byte contract limit",
            set_target.length,
            updated_contracts::artifact::ProviderSet::MAX_DOCUMENT_BYTES
        )));
    }
    if store.is_rejected(lineage, &provider_ref.sha256) {
        return Err(unusable(
            "desired provider set was previously rejected".into(),
        ));
    }
    // A failed fetch or read is about the link and the disk, never about the release.
    let mut downloaded_set = repo
        .download_target(&set_target, &opts.paths.provider_download)
        .await
        .map_err(|e| Transient(format!("acquiring desired provider set failed: {e}")))?;
    let bytes = downloaded_set
        .read_bounded(updated_contracts::artifact::ProviderSet::MAX_DOCUMENT_BYTES)
        .map_err(|e| Transient(format!("reading desired provider set failed: {e}")))?;
    let set = decode_provider_set(store, lineage, &provider_ref.sha256, &bytes)?;
    let provider = set.reconciler;
    let target = repo
        .exact_target(&provider.artifact)
        .map_err(|e| unusable(format!("resolving node reconciler failed: {e}")))?;
    let sha = target_sha(&target);
    if store.is_rejected(lineage, &sha) {
        return Err(reject_provider_unit(
            store,
            lineage,
            &provider_ref.sha256,
            &sha,
            "desired node reconciler was previously rejected".into(),
        ));
    }
    let product = target
        .custom
        .get("product")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| unusable("node reconciler metadata has no product".into()))?;
    // The reconciler product becomes both a signed identity and a directory name under the install
    // root. Use the one identity grammar: mere traversal confinement would still admit Windows
    // aliases (`app`/`APP`, `con`) that map distinct signed products onto one state directory.
    if !updated_contracts::identity::is_segment(product) {
        return Err(unusable(
            "node reconciler metadata product is not a canonical portable identity".into(),
        ));
    }
    let version = target
        .custom
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| unusable("node reconciler metadata has no version".into()))?;
    let platform = foundation::platform::platform_key();
    let provider_store = updated::provider::BundleStore::for_lifecycle(&opts.paths)
        .with_target_limit(repo.target_limit());
    let staged_bundle = crate::acquire::acquire_verified_bundle(
        repo,
        &target,
        &opts.paths.provider_download,
        &provider_store,
        &updated::bundle::ExpectedBundle {
            product,
            version,
            platform: &platform,
        },
    )
    .await
    .map_err(|error| {
        // Only invalid *content* is a verdict on the bundle; a failed acquisition is transient.
        if matches!(&error, crate::acquire::AcquireBundleError::Invalid { .. }) {
            return reject_provider_unit(
                store,
                lineage,
                &provider_ref.sha256,
                &sha,
                format!("staging node reconciler failed: {error}"),
            );
        }
        Transient(format!("acquiring node reconciler failed: {error}"))
    })?;
    let release = updated::state::ProviderRelease {
        provider_set_sha256: provider_ref.sha256,
        product: product.to_string(),
        release: staged_bundle,
        archive_sha256: sha,
        args: provider.args,
        timeout_millis: provider.timeout_millis,
    };
    // The staged reconciler, as the caller must record it: this value is what the update
    // transaction commits alongside the application release, so the pair activate and roll back
    // together.
    Ok(release)
}

/// Select, authorize, download, and apply the newest application target, if any.
pub(crate) async fn check_application(
    opts: &Options,
    repo: &TrustedRepository,
    store: &mut Store,
    before_deployment: impl FnOnce(),
) -> AppOutcome {
    let assignment = match repo.assignment_context() {
        Some(assignment) => assignment,
        None => return AppOutcome::Fatal("release repository has no desired deployment".into()),
    };
    let lineage = assignment.repository_lineage();
    let assignment = assignment.document();
    let installed = store.installed();
    let ordered_current = match &installed {
        updated::state::Installed::Present(state) => state.version_floor_for(lineage),
        updated::state::Installed::Missing | updated::state::Installed::Invalid => None,
    };
    // A persisted rejection applies to one malformed artifact or one exact failed deployment, so
    // it pins the installation neither below a healthy intermediate release nor against a new
    // combination that reuses one of the same artifacts.
    let request = crate::acquire::ApplicationRequest {
        repository: repo,
        application: &opts.application,
        paths: &opts.paths,
        stance: ordered_current.map_or(updated_tuf::select::Stance::Nothing, |version| {
            updated_tuf::select::Stance::Installed(version)
        }),
    };
    let selected = match crate::acquire::select_assigned_application(
        &request,
        |application_sha256, provider_set_sha256| {
            store.rejects_selection(lineage, application_sha256, provider_set_sha256)
        },
    ) {
        Ok(selected) => selected,
        Err(error) => {
            warn(&format!(
                "selecting the assigned application failed: {error}"
            ));
            return AppOutcome::Unchanged;
        }
    };
    // Provider-only deployment revisions reconcile here as well — which is why the set is staged
    // even when nothing was selected. Application bytes and their provider set are one release
    // unit and use the same durable transaction; the transaction can safely name identical app
    // bytes on both sides because the provider identity is the part that differs.
    let reconciler = match stage_providers(
        opts,
        repo,
        store,
        selected.as_ref().and_then(|s| s.provider_set.as_ref()),
    )
    .await
    {
        Ok(staged) => staged,
        Err(error) => {
            warn(&error.to_string());
            return AppOutcome::Unchanged;
        }
    };
    // Every provider is now present before downloading the application. Nothing below this point
    // writes transaction intent or touches the live deployment.
    let (prepared, provider_only) = match selected {
        Some(selected) => {
            let prepared = match crate::acquire::prepare_assigned_application(&request, selected)
                .await
            {
                Ok(prepared) => prepared,
                Err(error) => {
                    if let Some((version, archive_sha256)) = error.rejected_archive() {
                        if let Err(reject_error) = store.reject_artifact(lineage, archive_sha256) {
                            return AppOutcome::Fatal(format!(
                                "rejecting malformed application bundle {version}: {reject_error}"
                            ));
                        }
                    }
                    warn(&error.to_string());
                    return AppOutcome::Unchanged;
                }
            };
            (prepared, false)
        }
        None => {
            let Some(prepared) =
                provider_only_candidate(&installed, &assignment.application.sha256, &reconciler)
            else {
                return AppOutcome::Unchanged;
            };
            if store.rejects_deployment(
                lineage,
                &prepared.archive_sha256,
                &reconciler.provider_set_sha256,
            ) {
                return AppOutcome::Unchanged;
            }
            (prepared, true)
        }
    };

    // Crossing repository lineages may legitimately select the exact bytes already
    // running (notably when a freshly enrolled node joins its first group). That is a
    // state rebind, not an executable replacement: a full transaction would manufacture
    // a release as its own rollback predecessor. Commit the authenticated lineage while
    // leaving the active pointer and process untouched.
    if !provider_only {
        if let updated::state::Installed::Present(installed_state) = &installed {
            if let Some(rebound) = installed_state.rebind_if_same_artifact(
                lineage.clone(),
                &prepared.release,
                &prepared.archive_sha256,
                &reconciler,
            ) {
                if let Err(error) = store.commit_installed(&rebound) {
                    return AppOutcome::Fatal(format!(
                        "committing repository lineage for the running release: {error}"
                    ));
                }
                log(&format!(
                    "adopted repository lineage for already-running {}",
                    installed_state.release.version
                ));
                return AppOutcome::Unchanged;
            }
            // A version is an immutable release identity. Across a repository-lineage change the
            // selector has no old-lineage version floor, so it may encounter differently packed bytes
            // carrying the running version. Those bytes are neither an upgrade nor a valid rollback
            // predecessor. Hold the running release rather than entering a self-update transaction.
            if is_self_version(&installed, &prepared.version) {
                warn(&format!(
                    "ignoring application target {}: the installed version already has different \
                     release bytes or lifecycle state",
                    prepared.version
                ));
                return AppOutcome::Unchanged;
            }
        }
    }

    let updated::state::Installed::Present(installed_state) = &installed else {
        return AppOutcome::Fatal(
            "an update candidate was selected without a valid installed predecessor".into(),
        );
    };
    let from = installed_state.release.version.as_str();
    // This is the single boundary between side-effect-free staging and deployment mutation.
    // Stop background observers before any lifecycle transaction hook can run.
    before_deployment();
    if provider_only {
        log(&format!(
            "applying lifecycle provider update for {}",
            prepared.version
        ));
    } else {
        log(&format!("applying update {from} -> {}", prepared.version));
    }
    let mut port = ReleaseReconciler::new(opts, &reconciler, Reason::Update);
    let outcome = apply_update(
        &mut port,
        store,
        &prepared.release,
        &prepared.archive_sha256,
        lineage.clone(),
        reconciler.clone(),
    )
    .await;
    match outcome {
        Ok(Outcome::Committed { host_action }) => {
            log(&format!("upgraded to {}", prepared.version));
            AppOutcome::Upgraded {
                version: prepared.version,
                host_action,
            }
        }
        Ok(Outcome::RollbackPending) => {
            // The candidate activated and then failed: it is rejected and its rollback journal is
            // durable. Terminate so the launcher relaunches us and boot recovery rolls back to the
            // predecessor — the one rollback path.
            warn(&format!(
                "update to {} failed after activation; restarting to roll back to {from}",
                prepared.version
            ));
            AppOutcome::RestartForRecovery
        }
        Err(e) => {
            error(&format!("update transaction error: {e}"));
            AppOutcome::Fatal(e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed(version: &str) -> updated::state::Installed {
        updated::state::Installed::Present(Box::new(updated::state::InstalledState::confirmed(
            updated::state::RepositoryLineage::from_metadata_url("https://releases.example/")
                .expect("fixture metadata URL is valid"),
            updated::bundle::ReleaseId {
                version: version.into(),
                manifest_sha256: "1".repeat(64),
            },
            "2".repeat(64),
            Box::new(updated::state::ProviderRelease {
                provider_set_sha256: "5".repeat(64),
                product: "lifecycle".into(),
                release: updated::bundle::ReleaseId {
                    version: "1.0.0".into(),
                    manifest_sha256: "3".repeat(64),
                },
                archive_sha256: "4".repeat(64),
                args: Vec::new(),
                timeout_millis: 1_000,
            }),
        )))
    }

    #[test]
    fn installed_version_cannot_be_its_own_update_candidate() {
        let installed = installed("1.0.0");
        assert!(is_self_version(&installed, "1.0.0"));
        assert!(!is_self_version(&installed, "2.0.0"));
    }

    #[test]
    fn a_provider_only_revision_reuses_the_exact_running_application_as_one_transaction() {
        let installed = installed("1.0.0");
        let updated::state::Installed::Present(state) = &installed else {
            unreachable!()
        };
        let assigned_application_sha256 = state.archive_sha256.clone();
        let mut revised = state.lifecycle.as_ref().clone();
        revised.provider_set_sha256 = "6".repeat(64);

        let candidate = provider_only_candidate(&installed, &assigned_application_sha256, &revised)
            .expect("changed providers over identical app bytes are a real candidate");
        assert_eq!(candidate.release, state.release);
        assert_eq!(candidate.archive_sha256, state.archive_sha256);

        assert!(provider_only_candidate(
            &installed,
            &assigned_application_sha256,
            state.lifecycle.as_ref()
        )
        .is_none());
        assert!(provider_only_candidate(&installed, &"7".repeat(64), &revised).is_none());
    }

    #[test]
    fn verified_malformed_provider_set_bytes_are_rejected_at_the_decode_boundary() {
        let lineage =
            updated::state::RepositoryLineage::from_metadata_url("https://releases.example/")
                .expect("fixture metadata URL is valid");
        let digest = "a".repeat(64);
        let mut store = Store::default();

        let result = decode_provider_set(&mut store, &lineage, &digest, br#"{}"#);

        assert!(matches!(result, Err(ProviderStagingError::Unusable(_))));
        assert!(store.is_rejected(&lineage, &digest));
    }

    #[test]
    fn bad_reconciler_bytes_reject_both_halves_of_the_provider_binding() {
        let lineage =
            updated::state::RepositoryLineage::from_metadata_url("https://releases.example/")
                .expect("fixture metadata URL is valid");
        let provider_set = "a".repeat(64);
        let reconciler = "b".repeat(64);
        let mut store = Store::default();

        let error = reject_provider_unit(
            &mut store,
            &lineage,
            &provider_set,
            &reconciler,
            "invalid reconciler".into(),
        );

        assert!(matches!(error, ProviderStagingError::Unusable(_)));
        assert!(store.is_rejected(&lineage, &provider_set));
        assert!(store.is_rejected(&lineage, &reconciler));
    }
}
