use super::*;

pub(crate) enum AppOutcome {
    Upgraded { version: String },
    Unchanged,
    Fatal(String),
}

async fn stage_lifecycle_provider(
    opts: &Options,
    repo: &TrustedRepository,
    store: &mut dyn Store,
) -> Result<Option<updated::state::LifecycleProviderRelease>, String> {
    let assignment = repo
        .assignment()
        .ok_or_else(|| "release repository has no desired deployment".to_string())?;
    std::fs::create_dir_all(&opts.paths.provider_staging)
        .map_err(|e| format!("creating lifecycle provider staging directory failed: {e}"))?;
    let set_target = repo
        .exact_target(&assignment.provider_set)
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
    let mut lifecycle = None;
    for provider in set.overrides {
        let target = repo.exact_target(&provider.artifact).map_err(|e| {
            format!(
                "resolving {:?} provider override failed: {e}",
                provider.capability
            )
        })?;
        let sha = target_sha(&target);
        if store.is_rejected(&sha) {
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
        let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        let provider_store = updated::provider::BundleStore::for_lifecycle(&opts.paths)
            .with_target_limit(opts.repository.target_limit);
        let staged = update_client::acquire_verified_bundle(
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
                if let Err(reject_error) = store.reject(&sha) {
                    return format!("staging {:?} provider override failed: {error}; recording its rejection also failed: {reject_error}", provider.capability);
                }
            }
            format!(
                "acquiring {:?} provider override failed: {error}",
                provider.capability
            )
        })?;
        match provider.capability {
            updated::config::ProviderCapability::Lifecycle => {
                lifecycle = Some(updated::state::LifecycleProviderRelease {
                    product: product.to_string(),
                    release: staged.id,
                    archive_sha256: sha,
                    args: provider.args,
                    timeout_millis: provider.timeout_millis,
                });
            }
        }
    }
    Ok(lifecycle)
}

/// Select, authorize, download, and apply the newest application target, if any.
pub(crate) async fn check_application(
    opts: &Options,
    repo: &TrustedRepository,
    store: &mut dyn Store,
    app: &mut App,
    current: &Option<String>,
) -> AppOutcome {
    // A persisted rejection applies to the failed bytes only (keyed by hash), so it
    // pins the installation neither below a healthy intermediate release nor against
    // a corrected republish of the same version.
    // Provider-only deployment revisions reconcile here as well. Staging is
    // content-addressed and side-effect free; no lifecycle phase runs until an app
    // transaction consumes this exact resolved provider.
    let lifecycle = match stage_lifecycle_provider(opts, repo, store).await {
        Ok(lifecycle) => lifecycle,
        Err(error) => {
            warn(&error);
            return AppOutcome::Unchanged;
        }
    };
    if matches!(
        opts.application.activation,
        updated::config::Activation::Reexec
    ) && lifecycle.is_none()
    {
        warn("desired reexec deployment has no lifecycle provider; the running release remains active");
        return AppOutcome::Unchanged;
    }
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
            current_version: current.as_deref(),
        },
        |sha256| store.is_rejected(sha256),
    )
    .await
    {
        Ok(Some(prepared)) => prepared,
        Ok(None) => return AppOutcome::Unchanged,
        Err(error) => {
            if let Some((version, archive_sha256)) = error.rejected_archive() {
                if let Err(reject_error) = store.reject(archive_sha256) {
                    return AppOutcome::Fatal(format!(
                        "rejecting malformed application bundle {version}: {reject_error}"
                    ));
                }
            }
            warn(&error.to_string());
            return AppOutcome::Unchanged;
        }
    };

    let from = current.as_deref().unwrap_or("none");
    log(&format!("applying update {from} -> {}", prepared.version));
    // Drive the transaction over the live-application port; scope the tower so its borrow of
    // `app` is released before the arms below read `app.pid()`.
    let outcome = {
        let mut tower = DefaultProvider::new(app, opts, lifecycle.as_ref());
        apply_update(
            &mut tower,
            store,
            &prepared.release,
            &prepared.archive_sha256,
            lifecycle.clone(),
        )
        .await
    };
    match outcome {
        Ok(Outcome::Committed) => {
            if let Err(e) = store.clear_rejection(&prepared.archive_sha256) {
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
        Ok(failure @ (Outcome::RolledBack | Outcome::RejectedBeforeActivation)) => {
            // The transaction persisted rejection before beginning any rollback. This
            // layer reports the already-durable result; it never owns transaction state.
            match failure {
                Outcome::RolledBack => warn(&format!(
                    "rolling back to {from}: update to {} failed activation or health",
                    prepared.version
                )),
                Outcome::RejectedBeforeActivation => warn(&format!(
                    "rejected {} before activation; {from} remains running",
                    prepared.version
                )),
                Outcome::Committed => unreachable!(),
                Outcome::Deferred => unreachable!(),
            }
            AppOutcome::Unchanged
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
