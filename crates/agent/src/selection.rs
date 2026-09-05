use super::*;

pub(crate) enum AppOutcome {
    Upgraded {
        version: String,
        host_action: updated_contracts::reconciler::HostAction,
    },
    Unchanged,
    /// The update cannot proceed and cannot be recovered from in this process. The agent exits
    /// non-zero with its durable evidence intact; the platform service restarts it (throttled by its
    /// backoff) and boot recovery re-derives the recovery from that evidence.
    Fatal(String),
    /// A post-activation update failure: the candidate is rejected and its rollback journal is
    /// durable. This disposable agent terminates *cleanly* so the platform service restarts it and
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
    let installed = match store.installed() {
        Ok(installed) => installed,
        Err(error) => {
            return AppOutcome::Fatal(format!(
                "reading installed state before application selection: {error}"
            ));
        }
    };
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
    let selected =
        match crate::acquire::select_assigned_application(&request, |application_sha256| {
            store.rejects_deployment(lineage, application_sha256)
        }) {
            Ok(selected) => selected,
            Err(error) => {
                warn(&format!(
                    "selecting the assigned application failed: {error}"
                ));
                return AppOutcome::Unchanged;
            }
        };
    let Some(selected) = selected else {
        return AppOutcome::Unchanged;
    };
    let prepared = match crate::acquire::prepare_assigned_application(&request, selected).await {
        Ok(prepared) => prepared,
        Err(error) => {
            if let Some((_, sha)) = error.rejected_archive() {
                if let Err(e) = store.reject_artifact(lineage, sha) {
                    return AppOutcome::Fatal(e.to_string());
                }
            }
            warn(&error.to_string());
            return AppOutcome::Unchanged;
        }
    };
    let reconciler = prepared.reconciler.clone();
    // Crossing repository lineages may legitimately select the exact bytes already
    // running (notably when a freshly enrolled node joins its first group). That is a
    // state rebind, not an executable replacement: a full transaction would manufacture
    // a release as its own rollback predecessor. Commit the authenticated lineage while
    // leaving the active pointer and process untouched.
    {
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
            // predecessor. Hold the running release rather than entering an application update.
            if is_self_version(&installed, &prepared.version) {
                warn(&format!(
                    "ignoring application target {}: the installed version already has different \
                     payload bytes or reconciler state",
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
    // Stop background observers before any reconciler transaction hook can run.
    before_deployment();
    log(&format!("applying update {from} -> {}", prepared.version));
    let mut port = ReleaseReconciler::new(opts, &reconciler, Reason::Update);
    let outcome = execute_update(
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
            // durable. Terminate so the platform service restarts us and boot recovery rolls back to the
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
