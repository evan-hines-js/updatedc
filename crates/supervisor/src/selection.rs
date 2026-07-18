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
        repo.download_target(&target, &opts.paths.provider_download)
            .await
            .map_err(|e| {
                format!(
                    "acquiring {:?} provider override failed: {e}",
                    provider.capability
                )
            })?;
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
        let staged = updated::provider::BundleStore::for_lifecycle(&opts.paths)
            .with_target_limit(opts.repository.target_limit)
            .install(
                &opts.paths.provider_download,
                &updated::bundle::ExpectedBundle { product, version, platform: &platform },
            ).map_err(|e| {
            if let Err(reject_error) = store.reject(&sha) {
                return format!("staging {:?} provider override failed: {e}; recording its rejection also failed: {reject_error}", provider.capability);
            }
            format!("staging {:?} provider override failed and its bytes were rejected: {e}", provider.capability)
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
    let policy = DefaultPolicy::current(
        opts.application.product.clone(),
        opts.application.channel.clone(),
    );
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
    let selected = match repo.assigned_application(&policy, current.as_deref()) {
        Ok(Some(selected)) => selected,
        Ok(None) => return AppOutcome::Unchanged,
        Err(error) => {
            warn(&format!("selecting desired application failed: {error}"));
            return AppOutcome::Unchanged;
        }
    };
    if store.is_rejected(&selected.sha256) {
        return AppOutcome::Unchanged;
    }
    // Every provider is now present before downloading the application. Nothing
    // below this point writes transaction intent or touches the live deployment.
    if let Err(error) = repo.stage_release(&selected, &opts.paths.download).await {
        warn(&format!("acquiring application release failed: {error}"));
        return AppOutcome::Unchanged;
    }
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let release = match updated::provider::BundleStore::for_app(&opts.paths)
        .with_target_limit(opts.repository.target_limit)
        .install(
            &opts.paths.download,
            &updated::bundle::ExpectedBundle {
                product: &opts.application.product,
                version: &selected.version,
                platform: &platform,
            },
        ) {
        Ok(release) => release,
        Err(error) => {
            warn(&format!(
                "staging application bundle {} failed: {error}",
                selected.version
            ));
            if let Err(reject_error) = store.reject(&selected.sha256) {
                return AppOutcome::Fatal(format!(
                    "rejecting malformed application bundle {}: {reject_error}",
                    selected.version
                ));
            }
            return AppOutcome::Unchanged;
        }
    };

    let from = current.as_deref().unwrap_or("none");
    log(&format!("applying update {from} -> {}", selected.version));
    // Drive the transaction over the live-application port; scope the tower so its borrow of
    // `app` is released before the arms below read `app.pid()`.
    let outcome = {
        let mut tower = DefaultProvider::new(app, opts, lifecycle.as_ref());
        apply_update(
            &mut tower,
            store,
            &release.id,
            &selected.sha256,
            lifecycle.clone(),
        )
        .await
    };
    match outcome {
        Ok(Outcome::Committed) => {
            if let Err(e) = store.clear_rejection(&selected.sha256) {
                warn(&format!(
                    "upgraded to {}, but clearing its stale rejection failed: {e}",
                    selected.version
                ));
            }
            log(&format!(
                "upgraded to {} (pid {})",
                selected.version,
                app.pid()
            ));
            AppOutcome::Upgraded {
                version: selected.version,
            }
        }
        Ok(failure @ (Outcome::RolledBack | Outcome::RejectedBeforeActivation)) => {
            // The transaction persisted rejection before beginning any rollback. This
            // layer reports the already-durable result; it never owns transaction state.
            match failure {
                Outcome::RolledBack => warn(&format!(
                    "rolling back to {from}: update to {} failed activation or health",
                    selected.version
                )),
                Outcome::RejectedBeforeActivation => warn(&format!(
                    "rejected {} before activation; {from} remains running",
                    selected.version
                )),
                Outcome::Committed => unreachable!(),
                Outcome::Deferred => unreachable!(),
            }
            AppOutcome::Unchanged
        }
        Ok(Outcome::Deferred) => {
            warn(&format!(
                "deferred update to {}; operator lifecycle state was not ready",
                selected.version
            ));
            AppOutcome::Unchanged
        }
        Err(e) => {
            error(&format!("update transaction error: {e}"));
            AppOutcome::Fatal(e.to_string())
        }
    }
}
