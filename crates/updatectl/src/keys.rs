//! Role key material on its way to a keys directory. Everything is staged under a pending prefix
//! and only promoted once the publish it belongs to has landed, so an interrupted bootstrap is
//! re-runnable rather than half-populated.

use crate::*;

/// Refuse a `--keys-dir` that already holds any role key.
///
/// `trust-root` mints a *fresh* trust root, and the operator who runs it after a key disclosure
/// is running it precisely to retire the exposed key. Reusing a leftover file there would pin the
/// compromised key into the new root and report success, so the reuse is refused outright rather
/// than made a flag: minting into a clean directory is the only way to get a root whose keys are
/// all new, and `--force` is about replacing the published *repository*, never about overwriting
/// private keys in place.
///
/// This runs immediately before minting — after every S3 round trip — and again before the minted
/// keys are moved into place, so there is no window in which a file that appeared mid-run is
/// adopted. It cannot be a leftover from an aborted `trust-root`: that ceremony stages its keys
/// (see `PendingRoleKeys`) and writes nothing at these paths unless the publish landed. What an
/// aborted run *can* leave is its staging directory, which `sweep_stale_staging` removes and this
/// check deliberately ignores.
pub(crate) fn ensure_keys_dir_is_empty(dir: &Path) -> Result<(), Error> {
    let mut present = Vec::new();
    for key in role_key_names(dir)? {
        if foundation::file::path_entry_exists(&dir.join(&key))? {
            present.push(key);
        }
    }
    if present.is_empty() {
        return Ok(());
    }
    Err(format!(
        "--keys-dir {} already holds role keys ({}); `trust-root` mints a fresh trust root and \
         will not reuse an existing key — a root minted over a disclosed key would still be \
         signed by it. Point --keys-dir at an empty directory (move the old keys aside if they \
         are still needed to serve the current repository). No key reaches these paths without a \
         successful publish, so these are not the remains of an interrupted run — that leaves \
         only a `.trust-root.pending.*` staging directory, which the next run removes on its own.",
        dir.display(),
        present.join(", ")
    )
    .into())
}

/// The staging stem `trust-root` mints its role key set under, inside `--keys-dir`.
pub(crate) const ROLE_KEYS_STEM: &str = "trust-root";

/// One piece of private key material staged on its way to the operator, and the crash-consistency
/// protocol both key ceremonies deliver material with — written once, so the two cannot drift.
///
/// The protocol has five steps and every one of them is load bearing:
///
/// 1. **Sweep.** A mint first removes anything left under `.<stem>.pending.` in the same
///    directory. `Drop` covers every failure the process survives, but a signal does not go
///    through it: a Ctrl-C or a runner timeout during the S3 leg of a ceremony kills the process
///    outright and leaves private key material on disk. The emptiness pre-flights look only at the
///    delivery names, so without the sweep each interrupted run left one more, against the
///    documented promise that an operator never has to hand-delete key material. Sweeping is safe
///    on two counts: *provenance* — only this tool writes under the prefix, so an entry is its own
///    abandoned staging; and *value* — a run still under the pending prefix never reached `commit`
///    and so published nothing, because step 4 renames out of the prefix before anything that can
///    fail. Those are keys of a root that never existed.
/// 2. **Mint under a name this process picks.** `<stem>.pending.<pid>.<nanos>`, created
///    exclusively by the caller's mint, so no file or directory another local principal planted
///    can be adopted into a fresh root.
/// 3. **Drop removes it.** A ceremony is mint-then-publish and the publish is allowed to fail for
///    routine reasons (S3 transients, a generation guard aborting on another publisher). Such a
///    failure delivers nothing, so the identical re-run mints again and completes the ceremony.
/// 4. **Publish the name before anything fallible.** The moment the repository is live this
///    material is the only copy of a LIVE root's keys, so it is renamed to `.<stem>.published.` —
///    a prefix step 1 does not sweep — before the delivery moves that can fail. Under the pending
///    name, the next automated re-run swept away the live root's keys.
/// 5. **Deliver.** Ceremony-specific, and the one part that differs: `trust-root` moves five role
///    keys into `--keys-dir`, `rotate-root` moves one successor key to `--new-key-out`.
pub(crate) struct PendingKeyMaterial {
    /// The directory the staging entry lives in; also the namespace the sweep scans.
    pub(crate) dir: PathBuf,
    /// Names the `.<stem>.pending.`/`.<stem>.published.` prefixes.
    pub(crate) stem: String,
    /// Where the material is right now: the pending name, or the published one after `publish`.
    pub(crate) staged: PathBuf,
    pub(crate) committed: bool,
}

impl PendingKeyMaterial {
    /// Sweep abandoned staging (step 1) and name a fresh, private staging path (step 2). The
    /// caller mints its material at [`Self::path`]; until it does, dropping this guard is a no-op
    /// on a path that does not exist.
    pub(crate) fn stage(dir: &Path, stem: &str, command: &'static str) -> Result<Self, Error> {
        sweep_stale_staging(dir, stem, command)?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default();
        let staged = dir.join(format!(
            "{}{}.{nonce}",
            pending_prefix(stem),
            std::process::id()
        ));
        Ok(Self {
            dir: dir.to_path_buf(),
            stem: stem.to_string(),
            staged,
            committed: false,
        })
    }

    /// Where the material is: the staging path before [`Self::publish`], the published one after.
    pub(crate) fn path(&self) -> &Path {
        &self.staged
    }

    /// Step 4: take the material out of the swept namespace, because what it holds is now the only
    /// copy of a live root's keys. Called first thing in a `commit`, before any delivery step that
    /// can fail; the caller wraps the error with what the operator must do about it.
    pub(crate) fn publish(&mut self) -> Result<(), Error> {
        let suffix = self
            .staged
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                format!(
                    "staged key-material path has no UTF-8 file name: {}",
                    self.staged.display()
                )
            })?;
        let pending = pending_prefix(&self.stem);
        let suffix = suffix.strip_prefix(&pending).ok_or_else(|| {
            format!(
                "staged key-material path {} escaped its pending namespace",
                self.staged.display()
            )
        })?;
        let published = self
            .dir
            .join(format!("{}{suffix}", published_prefix(&self.stem)));
        std::fs::rename(&self.staged, &published).map_err(|error| {
            format!(
                "renaming the staged key material {} to {}: {error}",
                self.staged.display(),
                published.display()
            )
        })?;
        self.staged = published;
        self.committed = true;
        Ok(())
    }
}

impl Drop for PendingKeyMaterial {
    /// Step 3. Whatever was minted — a directory of five keys or a single key file — goes with the
    /// process unless it was published.
    fn drop(&mut self) {
        if !self.committed {
            let _ = remove_staged(&self.staged);
        }
    }
}

/// The staging prefix: what a mint names its material under, and the one namespace the sweep
/// removes from.
pub(crate) fn pending_prefix(stem: &str) -> String {
    format!(".{stem}.pending.")
}

/// The name staged material is renamed to the moment its repository is published, before any step
/// of the delivery that can fail. It shares no prefix with the pending name, so the material a
/// half-finished `commit` leaves behind — the only copy a live trust root has — is outside what
/// the sweep removes, and an automated re-run cannot destroy it.
pub(crate) fn published_prefix(stem: &str) -> String {
    format!(".{stem}.published.")
}

/// Remove one staged entry, whichever shape the ceremony minted.
pub(crate) fn remove_staged(path: &Path) -> std::io::Result<()> {
    foundation::durable::remove_path(path)
}

/// Step 1 of [`PendingKeyMaterial`]: remove the staged material of runs that died before they
/// could clean up. Concurrent runs of one ceremony against one directory are not a supported
/// configuration (they race for the same destination paths regardless), so the sweep does not
/// coordinate with them.
pub(crate) fn sweep_stale_staging(dir: &Path, stem: &str, command: &str) -> Result<(), Error> {
    let pending = pending_prefix(stem);
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("reading {}: {error}", dir.display()).into()),
    };
    for entry in entries {
        let entry = entry.map_err(|error| format!("reading {}: {error}", dir.display()))?;
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(&pending))
        {
            continue;
        }
        let path = entry.path();
        remove_staged(&path).map_err(|error| {
            format!(
                "removing {}, the key material an interrupted `{command}` left behind: {error}",
                path.display()
            )
        })?;
        eprintln!(
            "removed {}: private key material staged by a `{command}` that was interrupted before \
             it published, so it is the material of a root that never existed",
            path.display()
        );
    }
    Ok(())
}

/// The five role keys of a fresh trust root, minted into a private staging directory inside
/// `--keys-dir` and moved into place only once the new repository has been published.
///
/// The staging protocol is [`PendingKeyMaterial`]'s; what this adds is the bootstrap's own
/// delivery — five role keys into `--keys-dir` — and its own no-adoption rule: the staging
/// directory is created exclusively under a name this process picks, and `repo::generate_keys`
/// creates every key with `create_new`, so no file another local principal planted, before the run
/// or during it, can end up signed into the new root. The emptiness of `--keys-dir` is checked
/// here, after every S3 round trip, and again at commit, so the check and the mint are not
/// separated by seconds of network wall clock.
pub(crate) struct PendingRoleKeys {
    pub(crate) material: PendingKeyMaterial,
    pub(crate) destination: PathBuf,
    pub(crate) keys: repo::Keys,
}

impl PendingRoleKeys {
    /// Mint the full role key set into a fresh staging directory under `destination`.
    pub(crate) async fn mint(destination: &Path) -> Result<Self, Error> {
        tokio::fs::create_dir_all(destination)
            .await
            .map_err(|error| format!("creating --keys-dir {}: {error}", destination.display()))?;
        let material = PendingKeyMaterial::stage(destination, ROLE_KEYS_STEM, "trust-root")?;
        ensure_keys_dir_is_empty(destination)?;

        // Exclusive: a directory another principal pre-planted at this name is a hard error, not
        // a place this ceremony mints into.
        std::fs::create_dir(material.path()).map_err(|error| {
            format!(
                "staging fresh role keys at {}: {error}",
                material.path().display()
            )
        })?;
        // Dropping `material` from here on removes whatever the mint managed to write.
        let keys = repo::generate_keys(material.path()).await?;
        Ok(Self {
            material,
            destination: destination.to_path_buf(),
            keys,
        })
    }

    pub(crate) fn keys(&self) -> &repo::Keys {
        &self.keys
    }

    /// Move the staged keys into `--keys-dir`. Called only after the fresh repository is
    /// published, at which point the keys must be delivered to the operator: if a role key
    /// appeared at the destination since the pre-flight check, the staged set is kept and named
    /// rather than clobbered.
    pub(crate) fn commit(mut self) -> Result<(), Error> {
        self.material.publish().map_err(|error| {
            format!(
                "the repository was initialized and published, but {error}. The role keys are in \
                 {} — that is the only copy, so move them somewhere safe and load them into Vault \
                 before running `trust-root` again in this --keys-dir.",
                self.material.path().display()
            )
        })?;
        ensure_keys_dir_is_empty(&self.destination).map_err(|error| {
            format!(
                "{error}\nThe repository WAS initialized and published. Its role keys are in {} \
                 — that is the only copy, so move them somewhere safe and load them into Vault.",
                self.material.path().display()
            )
        })?;
        for name in role_key_names(self.material.path())? {
            std::fs::rename(
                self.material.path().join(&name),
                self.destination.join(&name),
            )
            .map_err(|error| {
                format!(
                    "the repository was initialized and published, but moving role key \
                     {name} to {}: {error}. The remaining keys are in {} — move them \
                     somewhere safe and load them into Vault.",
                    self.destination.display(),
                    self.material.path().display()
                )
            })?;
        }
        // The staging directory is empty now, and a failure to remove it is reported rather than
        // discarded: whatever is still in there is private key material of a LIVE trust root, and
        // an operator told the bootstrap succeeded would never think to look for it.
        if let Err(error) = std::fs::remove_dir(self.material.path()) {
            eprintln!(
                "warning: the role keys were delivered to {}, but removing the staging directory \
                 {} failed: {error}. Check it for key material before reusing this --keys-dir.",
                self.destination.display(),
                self.material.path().display()
            );
        }
        Ok(())
    }
}

/// `--new-key-out` must name a path that does not exist. Whatever ends up there becomes a root
/// key at threshold 1 for the whole fleet, so it has to be a key this ceremony minted — a file
/// found at the path is of unknown provenance (planted by another local principal on a shared
/// runner, or a stale copy of an online role key) and is never adopted, whatever its mode.
pub(crate) fn ensure_new_key_out_is_free(path: &Path) -> Result<(), Error> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("inspecting --new-key-out {}: {error}", path.display()).into()),
        Ok(_) => Err(format!(
            "--new-key-out {} already exists; `rotate-root` signs the key at this path into the \
             new root at threshold 1 and will only ever do that for a key it minted itself, so a \
             pre-existing file is refused rather than adopted. A rotation whose publish did not \
             land writes nothing here — retry the identical command. If this is a successor key \
             from a completed rotation, point --new-key-out at a fresh path. Nothing was minted, \
             signed, or uploaded.",
            path.display()
        )
        .into()),
    }
}

/// The successor root key, minted into a private staging file next to `--new-key-out` and moved
/// there only once the rotated root has been published.
///
/// The staging protocol is [`PendingKeyMaterial`]'s; what this adds is the rotation's own
/// delivery. It is what makes the ceremony — the one that answers a suspected root-key disclosure
/// — retryable without trusting a file on disk: a publish that fails uploads nothing, so the root
/// is *not* rotated, the guard's drop removes the staged key, `--new-key-out` is still free, and
/// the identical re-run mints a fresh successor and completes the ceremony. No path exists by
/// which a key the ceremony did not mint reaches the new root.
pub(crate) struct PendingRootKey {
    pub(crate) material: PendingKeyMaterial,
    pub(crate) destination: PathBuf,
}

/// The one staging namespace for root successors. Concurrent ceremonies in one key directory are
/// unsupported, so destination-derived variants only created stale-material paths that could evade
/// the next ceremony's sweep.
const ROOT_SUCCESSOR_STEM: &str = "root-successor";

impl PendingRootKey {
    /// Mint a fresh ed25519 key into a staging file. `repo::generate_root_key` creates it
    /// exclusively at mode 0600, so a name another principal pre-planted is a hard error here
    /// rather than an adoption.
    pub(crate) async fn mint(destination: &Path) -> Result<Self, Error> {
        let dir = destination.parent().unwrap_or_else(|| Path::new("."));
        let material = PendingKeyMaterial::stage(dir, ROOT_SUCCESSOR_STEM, "rotate-root")?;
        repo::generate_root_key(material.path()).await?;
        Ok(Self {
            material,
            destination: destination.to_path_buf(),
        })
    }

    pub(crate) fn path(&self) -> &Path {
        self.material.path()
    }

    /// Move the staged key to `--new-key-out`. Called only after the rotated root is published,
    /// at which point the key must be delivered to the operator: if the destination was taken
    /// since the pre-flight check, the staged file is kept and named rather than clobbered or
    /// deleted.
    pub(crate) fn commit(mut self) -> Result<(), Error> {
        self.material.publish().map_err(|error| {
            format!(
                "the root was rotated and published, but {error}. The key is at {} — move it \
                 somewhere safe and load it into Vault as the new standby.",
                self.material.path().display()
            )
        })?;
        ensure_new_key_out_is_free(&self.destination).map_err(|error| {
            format!(
                "{error}\nThe root WAS rotated and published. The successor key is at {} — move \
                 it somewhere safe and load it into Vault as the new standby.",
                self.material.path().display()
            )
        })?;
        std::fs::rename(self.material.path(), &self.destination).map_err(|error| {
            format!(
                "the root was rotated and published, but moving the successor key to {}: {error}. \
                 The key is at {} — move it somewhere safe and load it into Vault as the new \
                 standby.",
                self.destination.display(),
                self.material.path().display()
            )
        })?;
        Ok(())
    }
}
