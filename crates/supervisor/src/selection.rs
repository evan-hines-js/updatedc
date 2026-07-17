use super::*;

pub(crate) enum AppOutcome {
    Upgraded { version: String },
    Unchanged,
    Fatal(String),
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
    let selected = repo
        .stage_update(
            &policy,
            current.as_deref(),
            &opts.paths.download,
            |m| log(&format!("application update: {m}")),
            |t, _| store.is_rejected(&target_sha(t)),
        )
        .await;
    let Some(staged) = (match selected {
        Ok(selected) => selected,
        Err(e) => {
            warn(&format!("acquiring application release failed: {e}"));
            return AppOutcome::Unchanged;
        }
    }) else {
        return AppOutcome::Unchanged;
    };
    let version = staged.version;
    let sha = staged.sha256;
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let release = match updated::bundle::stage_bundle(
        &opts.paths.download,
        &opts.paths.staging,
        &opts.paths.versions,
        &updated::bundle::ExpectedBundle {
            product: &opts.application.product,
            version: &version,
            platform: &platform,
        },
        &updated::bundle::BundleLimits {
            archive_bytes: opts.repository.target_limit,
            ..Default::default()
        },
    ) {
        Ok(release) => release,
        Err(error) => {
            warn(&format!(
                "staging application bundle {version} failed: {error}"
            ));
            if let Err(reject_error) = store.reject(&sha) {
                return AppOutcome::Fatal(format!(
                    "rejecting malformed application bundle {version}: {reject_error}"
                ));
            }
            return AppOutcome::Unchanged;
        }
    };

    let from = current.as_deref().unwrap_or("none");
    log(&format!("applying update {from} -> {version}"));
    // Drive the transaction over the live-application port; scope the tower so its borrow of
    // `app` is released before the arms below read `app.pid()`.
    let outcome = {
        let mut tower = LiveTower::new(app, opts);
        apply_update(&mut tower, store, &release.id, &sha).await
    };
    match outcome {
        Ok(Outcome::Committed) => {
            if let Err(e) = store.clear_rejection(&sha) {
                warn(&format!(
                    "upgraded to {version}, but clearing its stale rejection failed: {e}"
                ));
            }
            log(&format!("upgraded to {version} (pid {})", app.pid()));
            AppOutcome::Upgraded { version }
        }
        Ok(failure @ (Outcome::RolledBack | Outcome::RejectedBeforeActivation)) => {
            // Persist the rejection BEFORE logging the rollback, so the log reflects a
            // durable outcome: a crash in this window must not leave a "rolling back"
            // record with no rejection actually recorded (it would just re-apply the
            // bad release on the next check).
            if let Err(e) = store.reject(&sha) {
                error(&format!(
                    "rolled back {version}, but could not durably reject its bytes: {e}"
                ));
                return AppOutcome::Fatal(format!(
                    "persisting rejection for rolled-back {version}: {e}"
                ));
            }
            match failure {
                Outcome::RolledBack => warn(&format!(
                    "rolling back to {from}: update to {version} failed activation or health"
                )),
                Outcome::RejectedBeforeActivation => warn(&format!(
                    "rejected {version} before activation; {from} remains running"
                )),
                Outcome::Committed => unreachable!(),
            }
            AppOutcome::Unchanged
        }
        Err(e) => {
            error(&format!("update transaction error: {e}"));
            AppOutcome::Fatal(e.to_string())
        }
    }
}
