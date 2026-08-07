use super::*;

pub(crate) enum AppOutcome {
    Upgraded {
        version: String,
    },
    Unchanged,
    /// The update cannot proceed and cannot be recovered from in this process. The supervisor
    /// exits non-zero with its durable evidence intact; the guardian relaunches it (throttled by
    /// its backoff) and boot recovery re-derives the recovery from that evidence.
    Fatal(String),
    /// A post-activation update failure: the candidate is rejected and its rollback journal is
    /// durable. This disposable supervisor terminates *cleanly* so the guardian relaunches it and
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

/// Why staging a version's lifecycle providers failed.
///
/// The distinction is load-bearing for cold install: a caller that rejects the application archive
/// on ANY failure turns a brief CDN outage or a full disk into a permanent, never-expiring
/// rejection of every release it walks past — the node then has nothing installable even once the
/// network is back. Only a verdict about the *content* may reject.
pub(crate) enum ProviderStagingError {
    /// The provider set is genuinely unusable: malformed, invalid, or naming a reconciler already
    /// rejected.
    ///
    /// `version_bound` says whether descending could possibly help. A set resolved from an
    /// application version's own signed metadata is that version's problem, so rejecting it and
    /// descending finds a version whose set is good. A set that came from the ASSIGNMENT is
    /// version-independent: every version fails on it identically, so rejecting them one by one
    /// walks a fresh node to the bottom of the descent and permanently excludes every release it
    /// has — for a cause that has nothing to do with any of them.
    Unusable {
        message: String,
        version_bound: bool,
    },
    /// An I/O, network, or storage failure. It says nothing about the release; retry later.
    Transient(String),
}

impl std::fmt::Display for ProviderStagingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unusable { message, .. } | Self::Transient(message) => f.write_str(message),
        }
    }
}

pub(crate) async fn stage_providers(
    opts: &Options,
    repo: &TrustedRepository,
    store: &mut dyn Store,
    ordered_current: Option<&str>,
) -> Result<
    (
        updated::state::ProviderRelease,
        Option<updated_tuf::TargetReference>,
    ),
    ProviderStagingError,
> {
    use ProviderStagingError::Transient;
    // Until the provider set's origin is known, no failure can be blamed on an application version.
    let unusable = |message: String| ProviderStagingError::Unusable {
        message,
        version_bound: false,
    };
    let assignment = repo
        .assignment()
        .ok_or_else(|| unusable("release repository has no desired deployment".into()))?;
    let lineage = updated::state::RepositoryLineage::from_metadata_url(&assignment.metadata_url);
    std::fs::create_dir_all(&opts.paths.provider_staging).map_err(|e| {
        Transient(format!(
            "creating lifecycle provider staging directory failed: {e}"
        ))
    })?;
    // Resolve the provider set against the app version that will actually be selected. When
    // ordered fallback descends below the assigned head (the head bytes are unusable), the
    // descended app version's own signed provider set governs — app and providers roll back as
    // one signed unit rather than pairing an old app with the head's newer providers. At the
    // assigned head, `provider_set` is `None` and the assignment's own pointer governs, keeping
    // providers independently revisable there. Selection is deterministic and side-effect free.
    let policy =
        updated_tuf::DefaultPolicy::current(&opts.application.product, &opts.application.channel);
    let selected_provider_ref = repo
        .assigned_application(
            &policy,
            ordered_current,
            |_message| {},
            |target, _version| store.is_rejected(&lineage, &target_sha(target)),
        )
        .map_err(|e| {
            unusable(format!(
                "selecting application to resolve its provider set failed: {e}"
            ))
        })?
        .and_then(|selected| selected.provider_set);
    let provider_ref = selected_provider_ref
        .clone()
        .unwrap_or_else(|| assignment.provider_set.clone());
    // From here the set's origin is known: a version's own signed metadata (descending can help)
    // or the assignment (it cannot).
    let version_bound = selected_provider_ref.is_some();
    let unusable = |message: String| ProviderStagingError::Unusable {
        message,
        version_bound,
    };
    let set_target = repo
        .exact_target(&provider_ref)
        .map_err(|e| unusable(format!("resolving desired provider set failed: {e}")))?;
    // A failed fetch or read is about the link and the disk, never about the release.
    repo.download_target(&set_target, &opts.paths.provider_download)
        .await
        .map_err(|e| Transient(format!("acquiring desired provider set failed: {e}")))?;
    let bytes = std::fs::read(&opts.paths.provider_download)
        .map_err(|e| Transient(format!("reading desired provider set failed: {e}")))?;
    let set: updated_contracts::artifact::ProviderSet = serde_json::from_slice(&bytes)
        .map_err(|e| unusable(format!("desired provider set is invalid: {e}")))?;
    set.validate()
        .map_err(|error| unusable(format!("desired provider set is invalid: {error}")))?;
    let provider = set.reconciler;
    let target = repo
        .exact_target(&provider.artifact)
        .map_err(|e| unusable(format!("resolving node reconciler failed: {e}")))?;
    let sha = target_sha(&target);
    if store.is_rejected(&lineage, &sha) {
        return Err(unusable(
            "desired node reconciler was previously rejected".into(),
        ));
    }
    let product = target
        .custom
        .get("product")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| unusable("node reconciler metadata has no product".into()))?;
    // The reconciler product becomes a directory name under the install root (per-product state),
    // so it is confined by the same shared traversal guard as every other joined path component —
    // a signed-but-hostile `../…` product must not escape.
    if !updated_contracts::path::is_safe_component(product) {
        return Err(unusable(
            "node reconciler metadata product is not a safe path component".into(),
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
                if let Err(reject_error) = store.reject(&lineage, &sha) {
                    return unusable(format!("staging node reconciler failed: {error}; recording its rejection also failed: {reject_error}"));
                }
                return unusable(format!("staging node reconciler failed: {error}"));
            }
            Transient(format!("acquiring node reconciler failed: {error}"))
        })?;
    let release = updated::state::ProviderRelease {
        product: product.to_string(),
        release: staged_bundle.id,
        archive_sha256: sha,
        args: provider.args,
        timeout_millis: provider.timeout_millis,
    };
    // Returned so the caller can confirm the application it goes on to prepare is the same version
    // this set was resolved for — the two selections are independent and can drift apart.
    Ok((release, selected_provider_ref))
}

/// Select, authorize, download, and apply the newest application target, if any.
pub(crate) async fn check_application(
    opts: &Options,
    repo: &TrustedRepository,
    store: &mut dyn Store,
    app: &mut App,
    before_deployment: impl FnOnce(),
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
    let (reconciler, staged_for) = match stage_providers(opts, repo, store, ordered_current).await {
        Ok(staged) => staged,
        Err(error) => {
            warn(&error.to_string());
            return AppOutcome::Unchanged;
        }
    };
    // Stage and validate the provider set above, but only an application release transition may
    // commit it. A provider-only change cannot safely use the application transaction: it would
    // manufacture the running release as its own rollback predecessor. Keeping that invariant
    // here leaves one lifecycle transaction path, with distinct predecessor and candidate
    // releases, and the provider revision is naturally picked up by the next application release.
    // Every provider is now present before downloading the application. Nothing
    // below this point writes transaction intent or touches the live deployment.
    let prepared = match crate::acquire::prepare_assigned_application(
        crate::acquire::ApplicationRequest {
            repository: repo,
            application: &opts.application,
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

    // The providers were staged from one selection and the application from another. Those two
    // selections can disagree: preparing the application records a rejection for a malformed
    // bundle and descends, so the version that emerged here may sit below the one whose provider
    // set is on disk. Committing that pair would run a release against another version's signed
    // hooks. Nothing has been mutated yet, so retry on the next tick — by then the rejection is
    // durable and both selections agree.
    if prepared.provider_set != staged_for {
        warn(&format!(
            "the staged provider set does not belong to the selected application {}; re-resolving \
             both on the next check",
            prepared.version
        ));
        return AppOutcome::Unchanged;
    }

    // Crossing repository lineages may legitimately select the exact bytes already
    // running (notably when a freshly enrolled node joins its first group). That is a
    // state rebind, not an executable replacement: a full transaction would manufacture
    // a release as its own rollback predecessor. Commit the authenticated lineage while
    // leaving the active pointer and process untouched.
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

    let from = match &installed {
        updated::state::Installed::Present(state) => state.release.version.as_str(),
        updated::state::Installed::Missing | updated::state::Installed::Invalid => "none",
    };
    // This is the single boundary between side-effect-free staging and deployment mutation.
    // Stop background observers before any lifecycle transaction hook can run.
    before_deployment();
    log(&format!("applying update {from} -> {}", prepared.version));
    // Drive the transaction over the live-application port; scope the tower so its borrow of
    // `app` is released before the arms below read `app.pid()`.
    let outcome = {
        let mut tower = DefaultProvider::new(app, opts, &reconciler);
        apply_update(
            &mut tower,
            store,
            &prepared.release,
            &prepared.archive_sha256,
            lineage.clone(),
            reconciler.clone(),
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
                "upgraded to {} (pid {:?})",
                prepared.version,
                app.pid()
            ));
            AppOutcome::Upgraded {
                version: prepared.version,
            }
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
            updated::state::RepositoryLineage::from_metadata_url("https://releases.example/"),
            updated::bundle::ReleaseId {
                version: version.into(),
                manifest_sha256: "1".repeat(64),
            },
            "2".repeat(64),
            Box::new(updated::state::ProviderRelease {
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
}
