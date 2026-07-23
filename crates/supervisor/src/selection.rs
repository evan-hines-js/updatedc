use super::*;

pub(crate) enum AppOutcome {
    Upgraded {
        version: String,
    },
    Unchanged,
    Fatal(String),
    /// A post-activation update failure: the candidate is rejected and its rollback journal is
    /// durable. This disposable supervisor must terminate cleanly so the guardian relaunches it and
    /// boot recovery performs the (single) rollback. Distinct from `Fatal`, which *holds* the
    /// process alive for an unrecoverable/non-idempotent condition.
    RestartForRecovery,
}

/// The operator providers staged for a release from its signed provider set. Every capability
/// is optional; a release may ship none, a lifecycle provider, a health-check provider, or both.
#[derive(Default, Clone)]
pub(crate) struct StagedProviders {
    pub(crate) lifecycle: Option<updated::state::ProviderRelease>,
    pub(crate) healthcheck: Option<updated::state::ProviderRelease>,
}

pub(crate) async fn stage_providers(
    opts: &Options,
    repo: &TrustedRepository,
    store: &mut dyn Store,
    ordered_current: Option<&str>,
) -> Result<StagedProviders, String> {
    let assignment = repo
        .assignment()
        .ok_or_else(|| "release repository has no desired deployment".to_string())?;
    let lineage = updated::state::RepositoryLineage::from_metadata_url(&assignment.metadata_url);
    std::fs::create_dir_all(&opts.paths.provider_staging)
        .map_err(|e| format!("creating lifecycle provider staging directory failed: {e}"))?;
    // Resolve the provider set against the app version that will actually be selected. When
    // ordered fallback descends below the assigned head (the head bytes are unusable), the
    // descended app version's own signed provider set governs — app and providers roll back as
    // one signed unit rather than pairing an old app with the head's newer providers. At the
    // assigned head, `provider_set` is `None` and the assignment's own pointer governs, keeping
    // providers independently revisable there. Selection is deterministic and side-effect free.
    let policy =
        updated_tuf::DefaultPolicy::current(&opts.application.product, &opts.application.channel);
    let provider_ref = repo
        .assigned_application(
            &policy,
            ordered_current,
            |_message| {},
            |target, _version| store.is_rejected(&lineage, &target_sha(target)),
        )
        .map_err(|e| format!("selecting application to resolve its provider set failed: {e}"))?
        .and_then(|selected| selected.provider_set)
        .unwrap_or_else(|| assignment.provider_set.clone());
    let set_target = repo
        .exact_target(&provider_ref)
        .map_err(|e| format!("resolving desired provider set failed: {e}"))?;
    repo.download_target(&set_target, &opts.paths.provider_download)
        .await
        .map_err(|e| format!("acquiring desired provider set failed: {e}"))?;
    let bytes = std::fs::read(&opts.paths.provider_download)
        .map_err(|e| format!("reading desired provider set failed: {e}"))?;
    let set: updated::config::ProviderSet = serde_json::from_slice(&bytes)
        .map_err(|e| format!("desired provider set is invalid: {e}"))?;
    set.validate()
        .map_err(|error| format!("desired provider set is invalid: {error}"))?;
    let mut staged = StagedProviders::default();
    for provider in set.overrides {
        let target = repo.exact_target(&provider.artifact).map_err(|e| {
            format!(
                "resolving {:?} provider override failed: {e}",
                provider.capability
            )
        })?;
        let sha = target_sha(&target);
        if store.is_rejected(&lineage, &sha) {
            return Err(format!(
                "desired {:?} provider override was previously rejected",
                provider.capability
            ));
        }
        let product = target
            .custom
            .get("product")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("provider {:?} metadata has no product", provider.capability))?;
        let version = target
            .custom
            .get("version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("provider {:?} metadata has no version", provider.capability))?;
        let platform = foundation::platform::platform_key();
        let provider_store = updated::provider::BundleStore::for_lifecycle(&opts.paths)
            .with_target_limit(opts.repository.target_limit);
        let staged_bundle = update_client::acquire_verified_bundle(
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
            if matches!(&error, update_client::AcquireBundleError::Invalid { .. }) {
                if let Err(reject_error) = store.reject(&lineage, &sha) {
                    return format!("staging {:?} provider override failed: {error}; recording its rejection also failed: {reject_error}", provider.capability);
                }
            }
            format!(
                "acquiring {:?} provider override failed: {error}",
                provider.capability
            )
        })?;
        let release = updated::state::ProviderRelease {
            product: product.to_string(),
            release: staged_bundle.id,
            archive_sha256: sha,
            args: provider.args,
            timeout_millis: provider.timeout_millis,
        };
        match provider.capability {
            updated::config::ProviderCapability::Lifecycle => staged.lifecycle = Some(release),
            updated::config::ProviderCapability::HealthCheck => staged.healthcheck = Some(release),
        }
    }
    Ok(staged)
}

/// Select, authorize, download, and apply the newest application target, if any.
pub(crate) async fn check_application(
    opts: &Options,
    repo: &TrustedRepository,
    store: &mut dyn Store,
    app: &mut App,
) -> AppOutcome {
    let assignment = match repo.assignment() {
        Some(assignment) => assignment,
        None => return AppOutcome::Fatal("release repository has no desired deployment".into()),
    };
    let lineage = updated::state::RepositoryLineage::from_metadata_url(&assignment.metadata_url);
    let installed = store.installed();
    let ordered_current = match &installed {
        updated::state::Installed::Present(state) => state.version_floor_for(&lineage),
        updated::state::Installed::Missing | updated::state::Installed::Invalid => None,
    };
    // A persisted rejection applies to the failed bytes only (keyed by hash), so it
    // pins the installation neither below a healthy intermediate release nor against
    // a corrected republish of the same version.
    // Provider-only deployment revisions reconcile here as well. Staging is
    // content-addressed and side-effect free; no lifecycle phase runs until an app
    // transaction consumes this exact resolved provider.
    let providers = match stage_providers(opts, repo, store, ordered_current).await {
        Ok(providers) => providers,
        Err(error) => {
            warn(&error);
            return AppOutcome::Unchanged;
        }
    };
    // A provider-set revision may be published independently of an application
    // release. Stage and validate it above, but never manufacture an application
    // transaction when the assigned application version is already running. In
    // particular, a corrected or nondeterministically repacked target with the same
    // version cannot be its own rollback predecessor.
    // Every provider is now present before downloading the application. Nothing
    // below this point writes transaction intent or touches the live deployment.
    let prepared = match update_client::prepare_assigned_application(
        update_client::ApplicationRequest {
            repository: repo,
            application: &opts.application,
            repository_config: &opts.repository,
            paths: &opts.paths,
            current_version: ordered_current,
        },
        |sha256| store.is_rejected(&lineage, sha256),
    )
    .await
    {
        Ok(Some(prepared)) => prepared,
        Ok(None) => return AppOutcome::Unchanged,
        Err(error) => {
            if let Some((version, archive_sha256)) = error.rejected_archive() {
                if let Err(reject_error) = store.reject(&lineage, archive_sha256) {
                    return AppOutcome::Fatal(format!(
                        "rejecting malformed application bundle {version}: {reject_error}"
                    ));
                }
            }
            warn(&error.to_string());
            return AppOutcome::Unchanged;
        }
    };

    // Crossing repository lineages may legitimately select the exact bytes already
    // running (notably when a freshly enrolled node joins its first group). That is a
    // state rebind, not an executable replacement: a full transaction would manufacture
    // a release as its own rollback predecessor. Commit the authenticated lineage while
    // leaving the active pointer and process untouched.
    if let updated::state::Installed::Present(installed) = &installed {
        if let Some(rebound) = installed.rebind_if_same_artifact(
            lineage.clone(),
            &prepared.release,
            &prepared.archive_sha256,
        ) {
            if let Err(error) = store.commit_installed(&rebound) {
                return AppOutcome::Fatal(format!(
                    "committing repository lineage for the running release: {error}"
                ));
            }
            log(&format!(
                "adopted repository lineage for already-running {}",
                installed.release.version
            ));
            return AppOutcome::Unchanged;
        }
    }

    let from = match &installed {
        updated::state::Installed::Present(state) => state.release.version.as_str(),
        updated::state::Installed::Missing | updated::state::Installed::Invalid => "none",
    };
    log(&format!("applying update {from} -> {}", prepared.version));
    // Drive the transaction over the live-application port; scope the tower so its borrow of
    // `app` is released before the arms below read `app.pid()`.
    let outcome = {
        let mut tower = DefaultProvider::new(
            app,
            opts,
            providers.lifecycle.as_ref(),
            providers.healthcheck.as_ref(),
        );
        apply_update(
            &mut tower,
            store,
            &prepared.release,
            &prepared.archive_sha256,
            lineage.clone(),
            providers.lifecycle.clone(),
            providers.healthcheck.clone(),
        )
        .await
    };
    match outcome {
        Ok(Outcome::Committed) => {
            if let Err(e) = store.clear_rejection(&lineage, &prepared.archive_sha256) {
                warn(&format!(
                    "upgraded to {}, but clearing its stale rejection failed: {e}",
                    prepared.version
                ));
            }
            log(&format!(
                "upgraded to {} (pid {})",
                prepared.version,
                app.pid()
            ));
            AppOutcome::Upgraded {
                version: prepared.version,
            }
        }
        Ok(Outcome::RejectedBeforeActivation) => {
            // Rejected before the candidate ever activated: the predecessor never stopped, so this
            // is a no-op for the running application. The rejection is already durable.
            warn(&format!(
                "rejected {} before activation; {from} remains running",
                prepared.version
            ));
            AppOutcome::Unchanged
        }
        Ok(Outcome::RollbackPending) => {
            // The candidate activated and then failed: it is rejected and its rollback journal is
            // durable. Terminate so the guardian relaunches us and boot recovery rolls back to the
            // predecessor — the one rollback path.
            warn(&format!(
                "update to {} failed after activation; restarting to roll back to {from}",
                prepared.version
            ));
            AppOutcome::RestartForRecovery
        }
        Ok(Outcome::Deferred) => {
            warn(&format!(
                "deferred update to {}; operator lifecycle state was not ready",
                prepared.version
            ));
            AppOutcome::Unchanged
        }
        Err(e) => {
            error(&format!("update transaction error: {e}"));
            AppOutcome::Fatal(e.to_string())
        }
    }
}
