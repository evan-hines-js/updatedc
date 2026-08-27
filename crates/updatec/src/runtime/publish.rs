//! Signing and mirroring one generation of the release repository, and keeping its TUF metadata
//! fresh. The compare-and-swap on `timestamp.json` is what makes a generation atomic to a node.

use super::*;

/// Mirror a fully signed repository. `timestamp.json` is uploaded last with a compare-and-swap
/// against the exact object version observed before any write, making it the fenced publication
/// commit point seen by TUF clients. A former lease holder may finish an already-accepted network
/// request after cancellation, but it cannot replace a timestamp another publisher advanced.
pub async fn publish_repository(
    store: &dyn ObjectStore,
    destination: &S3Destination,
    repository_dir: &Path,
) -> Result<(), StorageError> {
    let plan = publication_plan(repository_dir)
        .await
        .map_err(from_publish)?;
    // A metadata-only checkout does not fetch immutable artifacts it is retaining. Prove every
    // such content-addressed object is already at this exact destination before writing anything;
    // otherwise the new metadata would commit a target no client can download.
    for target in &plan.retained_targets {
        let relative = target
            .path
            .strip_prefix(repository_dir)
            .map_err(|e| StorageError(format!("invalid retained repository path: {e}")))?;
        let key = repository_object_key(&destination.prefix, relative)?;
        let digest = content_addressed_target_digest(relative)?.ok_or_else(|| {
            StorageError(format!(
                "retained repository object {} is not below targets/",
                relative.display()
            ))
        })?;
        verify_remote_target(store, &key, relative, &digest, target.length)
            .await
            .map_err(|error| {
                StorageError(format!(
                    "retained target {} failed its signed length and digest check: {error}",
                    relative.display()
                ))
            })?;
    }
    let (timestamp, uploads) = plan
        .uploads
        .split_last()
        .ok_or_else(|| StorageError("publication plan has no timestamp commit".into()))?;
    let timestamp_relative = timestamp
        .strip_prefix(repository_dir)
        .map_err(|error| StorageError(format!("invalid timestamp path: {error}")))?;
    if timestamp_relative != Path::new("metadata/timestamp.json") {
        return Err(StorageError(format!(
            "publication plan's final object is {}, not metadata/timestamp.json",
            timestamp_relative.display()
        )));
    }
    let timestamp_key = repository_object_key(&destination.prefix, timestamp_relative)?;

    let mut root_file = None;
    let mut validated_targets = HashMap::new();
    for file in uploads {
        let relative = file
            .strip_prefix(repository_dir)
            .map_err(|e| StorageError(format!("invalid repository path: {e}")))?;
        if relative == Path::new("metadata/root.json") {
            if root_file.replace(file.as_path()).is_some() {
                return Err(StorageError(
                    "publication plan contains more than one metadata/root.json".into(),
                ));
            }
            continue;
        }
        if let Some(expected) = content_addressed_target_digest(relative)? {
            let (actual, length) = sha256_local_regular(file).await?;
            if actual != expected {
                return Err(StorageError(format!(
                    "publication target {} hashes to {actual}, not the {expected} encoded in its object name",
                    relative.display()
                )));
            }
            validated_targets.insert(relative.to_path_buf(), length);
        } else if !relative.starts_with("metadata") {
            return Err(StorageError(format!(
                "publication object {} is outside metadata/ and targets/",
                relative.display()
            )));
        }
    }
    let root_file = root_file
        .ok_or_else(|| StorageError("publication plan has no metadata/root.json".into()))?;
    let root_key = crate::object_key(&destination.prefix, "metadata/root.json");

    // Capture BOTH mutable-object versions before the first write. Versioned metadata is
    // create-only and targets are content-addressed below; these two CAS records therefore fence
    // every mutable part of the publication. Reading the timestamp first also rejects a publisher
    // whose local generation is already behind the store rather than allowing it to CAS a newer
    // generation back to an older one.
    let timestamp_write =
        prepare_conditional_publication_file(store, &timestamp_key, timestamp).await?;
    validate_timestamp_transition(&timestamp_key, &timestamp_write)?;
    let root_write = prepare_conditional_publication_file(store, &root_key, root_file).await?;

    for file in uploads {
        let relative = file
            .strip_prefix(repository_dir)
            .map_err(|e| StorageError(format!("invalid repository path: {e}")))?;
        if relative == Path::new("metadata/root.json") {
            continue;
        }
        let key = repository_object_key(&destination.prefix, relative)?;
        if let Some(length) = validated_targets.get(relative) {
            let expected = content_addressed_target_digest(relative)?.ok_or_else(|| {
                StorageError(format!(
                    "validated target {} lost its content-addressed identity",
                    relative.display()
                ))
            })?;
            publish_content_addressed_target(store, &key, relative, file, &expected, *length)
                .await?;
        } else {
            publish_immutable_metadata(store, &key, relative, file).await?;
        }
    }

    // root.json is the bootstrap pointer and may legitimately change during a root rotation. It
    // is still conditional, and is written only after every immutable object it can expose exists.
    commit_conditional_publication_file(store, &root_key, "routing root", root_write).await?;
    // timestamp.json remains the final visibility commit for the online TUF roles.
    commit_conditional_publication_file(store, &timestamp_key, "timestamp", timestamp_write)
        .await?;
    Ok(())
}

/// Convert a local repository path into its one exact object-store identity. Repository metadata
/// names UTF-8 targets, so replacing undecodable local bytes would publish a different name than
/// the file being validated and can collide with a genuine U+FFFD path. Refuse it at the shared
/// boundary instead.
fn repository_object_key(
    prefix: &str,
    relative: &Path,
) -> Result<object_store::path::Path, StorageError> {
    let mut parts = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(StorageError(format!(
                "repository object path is not relative and normalized: {}",
                relative.display()
            )));
        };
        let part = part.to_str().ok_or_else(|| {
            StorageError(format!(
                "repository object path is not UTF-8: {}",
                relative.display()
            ))
        })?;
        parts.push(part);
    }
    if parts.is_empty() {
        return Err(StorageError("repository object path is empty".into()));
    }
    Ok(crate::object_key(prefix, &parts.join("/")))
}

pub(crate) struct ConditionalPublicationFile {
    pub(crate) file: std::path::PathBuf,
    pub(crate) bytes: Vec<u8>,
    pub(crate) previous: Option<Vec<u8>>,
    pub(crate) mode: PutMode,
}

/// Capture a mutable publication object's bytes and exact remote version before publication. The
/// old bytes make a retry of an already-landed write idempotent without issuing another mutation.
pub(crate) async fn prepare_conditional_publication_file(
    store: &dyn ObjectStore,
    key: &object_store::path::Path,
    file: &Path,
) -> Result<ConditionalPublicationFile, StorageError> {
    let bytes = read_local_bounded(file, LOCAL_TUF_METADATA_MAX_BYTES)
        .await
        .map_err(|error| StorageError(format!("reading {}: {error}", file.display())))?;
    match store.get(key).await {
        Ok(current) => {
            let (metadata, previous) =
                crate::collect_object_bounded(current, key, LOCAL_TUF_METADATA_MAX_BYTES as u64)
                    .await
                    .map_err(|error| {
                        StorageError(format!("reading current publication object {key}: {error}"))
                    })?;
            Ok(ConditionalPublicationFile {
                file: file.to_path_buf(),
                bytes,
                previous: Some(previous),
                mode: PutMode::Update(UpdateVersion {
                    e_tag: metadata.e_tag,
                    version: metadata.version,
                }),
            })
        }
        Err(object_store::Error::NotFound { .. }) => Ok(ConditionalPublicationFile {
            file: file.to_path_buf(),
            bytes,
            previous: None,
            mode: PutMode::Create,
        }),
        Err(error) => Err(StorageError(format!(
            "reading current publication object {key}: {error}"
        ))),
    }
}

pub(crate) fn validate_timestamp_transition(
    key: &object_store::path::Path,
    write: &ConditionalPublicationFile,
) -> Result<(), StorageError> {
    let local_version = signed_version(&write.bytes).ok_or_else(|| {
        StorageError(format!(
            "local publication timestamp {} has no signed.version",
            write.file.display()
        ))
    })?;
    let Some(previous) = write.previous.as_deref() else {
        return Ok(());
    };
    let remote_version = signed_version(previous).ok_or_else(|| {
        StorageError(format!(
            "current publication timestamp {key} has no signed.version"
        ))
    })?;
    if remote_version > local_version {
        return Err(StorageError(format!(
            "refusing to replace publication generation {remote_version} with older local generation {local_version}"
        )));
    }
    if remote_version == local_version && previous != write.bytes {
        return Err(StorageError(format!(
            "publication generation {local_version} already exists with different signed bytes"
        )));
    }
    Ok(())
}

/// Commit one small mutable TUF object through an atomic conditional PUT. Multipart completion has
/// no portable precondition in `object_store`, so these bounded objects deliberately use one PUT.
pub(crate) async fn commit_conditional_publication_file(
    store: &dyn ObjectStore,
    key: &object_store::path::Path,
    role: &str,
    write: ConditionalPublicationFile,
) -> Result<(), StorageError> {
    if write.previous.as_deref() == Some(write.bytes.as_slice()) {
        return Ok(());
    }
    match store
        .put_opts(
            key,
            PutPayload::from(write.bytes),
            PutOptions {
                mode: write.mode,
                ..Default::default()
            },
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(
            error @ (object_store::Error::AlreadyExists { .. }
            | object_store::Error::Precondition { .. }),
        ) => Err(StorageError(format!(
            "publication {role} {key} changed while this generation was uploading; another writer won the fence: {error}"
        ))),
        Err(error) => Err(StorageError(format!(
            "committing publication {role} {}: {error}",
            write.file.display()
        ))),
    }
}

/// Publish versioned TUF metadata exactly once. A retry accepts the object only when its bytes are
/// identical; a second signer cannot replace a same-version role and thereby invalidate the
/// timestamp/snapshot another publisher committed.
pub(crate) async fn publish_immutable_metadata(
    store: &dyn ObjectStore,
    key: &object_store::path::Path,
    relative: &Path,
    file: &Path,
) -> Result<(), StorageError> {
    let bytes = read_local_bounded(file, LOCAL_TUF_METADATA_MAX_BYTES)
        .await
        .map_err(|error| StorageError(format!("reading {}: {error}", file.display())))?;
    let payload = bytes.clone();
    match store
        .put_opts(key, PutPayload::from(payload), PutMode::Create.into())
        .await
    {
        Ok(_) => Ok(()),
        Err(object_store::Error::AlreadyExists { .. }) => {
            let existing =
                crate::read_object_bounded(store, key, LOCAL_TUF_METADATA_MAX_BYTES as u64)
                    .await
                    .map_err(|error| {
                        StorageError(format!(
                            "reading existing immutable metadata {}: {error}",
                            relative.display()
                        ))
                    })?;
            if existing == bytes {
                Ok(())
            } else {
                Err(StorageError(format!(
                    "immutable metadata {} already exists with different bytes",
                    relative.display()
                )))
            }
        }
        Err(error) => Err(StorageError(format!(
            "creating immutable metadata {}: {error}",
            relative.display()
        ))),
    }
}

pub(crate) fn content_addressed_target_digest(
    relative: &Path,
) -> Result<Option<String>, StorageError> {
    let Ok(target) = relative.strip_prefix("targets") else {
        return Ok(None);
    };
    let target = target.to_str().ok_or_else(|| {
        StorageError(format!(
            "publication target path {} is not UTF-8",
            relative.display()
        ))
    })?;
    let digest = target
        .split_once('.')
        .map(|(digest, _)| digest)
        .ok_or_else(|| {
            StorageError(format!(
                "publication target {} has no content-address digest",
                relative.display()
            ))
        })?;
    if !updated_contracts::is_canonical_sha256(digest) {
        return Err(StorageError(format!(
            "publication target {} has a non-canonical SHA-256 object name",
            relative.display()
        )));
    }
    Ok(Some(digest.to_string()))
}

pub(crate) async fn sha256_local_regular(file: &Path) -> Result<(String, u64), StorageError> {
    let path = file.to_path_buf();
    let opened = tokio::task::spawn_blocking(move || {
        foundation::file::open_regular(&path, foundation::file::FinalSymlink::Refuse)
    })
    .await
    .map_err(|error| StorageError(format!("opening {}: {error}", file.display())))?
    .map_err(|error| StorageError(format!("opening {}: {error}", file.display())))?;
    let mut source = tokio::fs::File::from_std(opened);
    let mut digest = updated_contracts::digest::Sha256Hasher::new();
    let mut length = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .await
            .map_err(|error| StorageError(format!("hashing {}: {error}", file.display())))?;
        if read == 0 {
            break;
        }
        length = length.checked_add(read as u64).ok_or_else(|| {
            StorageError(format!(
                "publication target {} is too large",
                file.display()
            ))
        })?;
        digest.update(&buffer[..read]);
    }
    Ok((digest.finish_hex(), length))
}

pub(crate) async fn verify_remote_target(
    store: &dyn ObjectStore,
    key: &object_store::path::Path,
    relative: &Path,
    expected_digest: &str,
    expected_length: u64,
) -> Result<(), StorageError> {
    let result = store.get(key).await.map_err(|error| {
        StorageError(format!(
            "content-addressed target {} is absent from the publication destination: {error}",
            relative.display()
        ))
    })?;
    if result.meta.size != expected_length {
        return Err(StorageError(format!(
            "target {} is {} bytes at the publication destination, but its signed/local length is {expected_length} bytes",
            relative.display(),
            result.meta.size
        )));
    }
    let mut digest = updated_contracts::digest::Sha256Hasher::new();
    let mut actual_length = 0_u64;
    let mut stream = result.into_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            StorageError(format!(
                "reading content-addressed target {}: {error}",
                relative.display()
            ))
        })?;
        actual_length = actual_length
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| StorageError(format!("target {} is too large", relative.display())))?;
        if actual_length > expected_length {
            return Err(StorageError(format!(
                "target {} streamed more than its {expected_length}-byte signed/local length",
                relative.display()
            )));
        }
        digest.update(&chunk);
    }
    let actual_digest = digest.finish_hex();
    if actual_length != expected_length || actual_digest != expected_digest {
        return Err(StorageError(format!(
            "target {} at the publication destination has SHA-256 {actual_digest} and length {actual_length}; expected {expected_digest} and {expected_length}",
            relative.display()
        )));
    }
    Ok(())
}

pub(crate) async fn publish_content_addressed_target(
    store: &dyn ObjectStore,
    key: &object_store::path::Path,
    relative: &Path,
    file: &Path,
    expected_digest: &str,
    expected_length: u64,
) -> Result<(), StorageError> {
    match store.head(key).await {
        Ok(_) => {
            return verify_remote_target(store, key, relative, expected_digest, expected_length)
                .await;
        }
        Err(object_store::Error::NotFound { .. }) => {}
        Err(error) => {
            return Err(StorageError(format!(
                "probing content-addressed target {}: {error}",
                relative.display()
            )));
        }
    }
    upload_repository_file(store, key, file).await?;
    verify_remote_target(store, key, relative, expected_digest, expected_length).await
}

/// Stream one repository object through a bounded multipart window.
///
/// Release targets are allowed to be hundreds of MiB; collecting one into a `Vec` made the
/// publisher's memory requirement equal to the largest artifact and could OOM between signing and
/// the final timestamp commit. Every non-commit repository file uses this one path; the bounded
/// timestamp uses a conditional single PUT because multipart completion cannot carry a fence.
pub(crate) async fn upload_repository_file(
    store: &dyn ObjectStore,
    key: &object_store::path::Path,
    file: &Path,
) -> Result<(), StorageError> {
    let path = file.to_path_buf();
    let opened = tokio::task::spawn_blocking(move || {
        foundation::file::open_regular(&path, foundation::file::FinalSymlink::Refuse)
    })
    .await
    .map_err(|error| StorageError(format!("opening {}: {error}", file.display())))?
    .map_err(|error| StorageError(format!("opening {}: {error}", file.display())))?;
    let mut source = tokio::fs::File::from_std(opened);
    let mut upload = store
        .put_multipart(key)
        .await
        .map_err(|error| StorageError(format!("starting upload of {}: {error}", file.display())))?;
    upload_repository_parts(&mut source, upload.as_mut(), file).await
}

pub(crate) async fn upload_repository_parts(
    source: &mut (impl tokio::io::AsyncRead + Unpin),
    upload: &mut dyn object_store::MultipartUpload,
    file: &Path,
) -> Result<(), StorageError> {
    // S3 requires every non-final part to be at least 5 MiB. Keep exactly one owned part in
    // memory and await it before reading the next: publication is not latency-sensitive, while
    // an explicit owner for the multipart session lets every failure path abort it reliably.
    const PART_BYTES: usize = 5 * 1024 * 1024;
    let mut uploaded_part = false;
    loop {
        let mut part = vec![0_u8; PART_BYTES];
        let mut filled = 0;
        let mut eof = false;
        while filled < part.len() {
            match source.read(&mut part[filled..]).await {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(read) => filled += read,
                Err(error) => {
                    return Err(
                        abort_failed_upload(upload, file, "reading during upload", &error).await,
                    );
                }
            }
        }
        if filled == 0 && uploaded_part {
            break;
        }
        // An empty repository file still gets one final, empty part; completing a zero-part S3
        // upload is not portable. For non-empty files this truncates only the final allocation.
        part.truncate(filled);
        if let Err(error) = upload.put_part(PutPayload::from(part)).await {
            return Err(abort_failed_upload(upload, file, "uploading a part", &error).await);
        }
        uploaded_part = true;
        if eof {
            break;
        }
    }
    if let Err(error) = upload.complete().await {
        return Err(abort_failed_upload(upload, file, "completing the upload", &error).await);
    }
    Ok(())
}

pub(crate) async fn abort_failed_upload(
    upload: &mut dyn object_store::MultipartUpload,
    file: &Path,
    operation: &str,
    error: &dyn std::fmt::Display,
) -> StorageError {
    let cleanup = upload.abort().await.err();
    StorageError(format!(
        "{operation} for {}: {error}{}",
        file.display(),
        cleanup.map_or_else(String::new, |cleanup| format!(
            "; aborting the multipart upload also failed: {cleanup}"
        ))
    ))
}

pub(crate) fn from_publish(error: PublishError) -> StorageError {
    StorageError(error.to_string())
}

/// The generation the object store is currently serving, read from the `version` of its published
/// `timestamp.json`. `None` when the store holds no generation at all.
///
/// The ONE question asked of the store about published state, for every guard that needs it: has
/// anything been published, and how far has it got? Both answers exist for the same reason — TUF
/// clients remember the highest version they accepted and refuse anything lower, so publishing
/// metadata numbered below what the store already serves wedges every node in the fleet
/// permanently.
///
/// Read unverified, deliberately. This is not a trust decision but a rollback guard on this
/// replica's own writes; anyone able to forge the number already holds write access to the prefix,
/// and the worst a forged one can do is make this publisher refuse to publish.
pub(crate) async fn store_published_version(
    store: &dyn ObjectStore,
    destination: &S3Destination,
) -> Result<Option<u64>, StorageError> {
    let key = crate::object_key(&destination.prefix, "metadata/timestamp.json");
    let bytes = match crate::read_object_bounded(store, &key, crate::OBJECT_BYTES_LIMIT).await {
        Ok(bytes) => bytes,
        Err(object_store::Error::NotFound { .. }) => return Ok(None),
        Err(e) => return Err(StorageError(format!("probing published metadata: {e}"))),
    };
    signed_version(&bytes)
        .ok_or_else(|| StorageError("published timestamp.json has no signed.version".into()))
        .map(Some)
}

/// The ONE rollback guard, asked before a pass signs anything: would the metadata this replica is
/// about to upload be numbered BELOW what the store already serves?
///
/// Clients enforce a rollback floor, so a lower generation is rejected by every node that saw the
/// higher one — forever, and with no self-healing path, because the replica that published it then
/// records its own publication marker and never republishes.
///
/// Both ways of being behind are the same question, so they are answered here together. An EMPTY
/// local state dir (a lost PVC, or a replica that never held the lease) would re-initialize at
/// version 1. A STALE one is worse because it looks healthy: a replica that led up to version 5,
/// lost the lease while another replica advanced the store to 40, and later reacquired it has
/// `root.json` on disk and a stale publication marker — and `replace_release` numbers the next
/// generation from LOCAL metadata, so it would upload version 6 over 40. Fail closed either way;
/// what must be restored is the state volume of the replica holding the newest metadata (or the
/// published prefix deleted to start over).
pub(crate) async fn refuse_generation_rollback(
    store: &dyn ObjectStore,
    destination: &S3Destination,
    repo_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(published) = store_published_version(store, destination).await? else {
        return Ok(()); // nothing is served, so nothing can be rolled back.
    };
    if !foundation::file::path_entry_exists(&repo_dir.join("metadata/root.json"))? {
        return Err(Box::new(StorageError(
            "local publisher state is empty but the object store already holds a published \
             generation; refusing to re-initialize a v1 TUF repo (restore the state volume)"
                .into(),
        )));
    }
    let local = updated_tuf::repo::current_version(repo_dir).await?;
    if local < published {
        return Err(Box::new(StorageError(format!(
            "local publisher state is at TUF generation {local} but the object store already \
             serves {published}; refusing to publish a lower generation every node would reject as \
             a rollback (restore the state volume of the replica that published {published})"
        ))));
    }
    Ok(())
}

/// The generation a signed TUF role document declares, or `None` if the bytes are not a role
/// document with a `signed.version`.
///
/// The one extractor. Two guards ask this question of the same objects in the same bucket for the
/// same reason — never publish below what the store already serves: this module's rollback guard,
/// and `updatectl`'s republish guard. They differ only in what an unreadable document means to
/// them (a hard error here, a zero there), which is the caller's decision to make, not a reason
/// for a second parser.
pub fn signed_version(bytes: &[u8]) -> Option<u64> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()?
        .pointer("/signed/version")?
        .as_u64()
}

/// How long every metadata document this control plane signs stays valid.
pub(crate) const METADATA_EXPIRY_DAYS: i64 = 365;

/// How little of that validity window may remain before the document is signed again.
///
/// A quarter of the window: long enough that renewal is never urgent (a control plane that is down
/// for two months still comes back to a live fleet), short enough that renewal happens roughly
/// three times per validity period, so a single failed attempt is not the failure.
pub(crate) const METADATA_RENEWAL_DAYS: i64 = 90;

/// The metadata this control plane is responsible for keeping fresh.
///
/// Two entries because they are re-signed by two different ceremonies: `sign_plan` re-signs the
/// online roles on every publication and never touches the root, while the root is renewed on its
/// own. They are checked together so freshness is decided in exactly one place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TufRole {
    Root,
    /// targets, snapshot, and timestamp — one `sign_plan` re-signs all three with one expiry, so
    /// `timestamp.json` speaks for the set.
    Online,
}

/// Which of this repository's signed metadata documents are inside their renewal window at `now`.
///
/// A document that is missing or unreadable is deliberately NOT a renewal: nothing has been signed
/// here yet (the initialization path handles that, with its own rollback guard), and metadata that
/// cannot be parsed must not be re-signed on top of.
pub(crate) async fn expiring_metadata(
    repo_dir: &Path,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<TufRole> {
    let horizon = now + chrono::Duration::days(METADATA_RENEWAL_DAYS);
    let metadata = repo_dir.join("metadata");
    let mut expiring = Vec::new();
    for (role, file) in [
        (TufRole::Root, "root.json"),
        (TufRole::Online, "timestamp.json"),
    ] {
        if metadata_expiry(&metadata.join(file))
            .await
            .is_some_and(|expires| expires <= horizon)
        {
            expiring.push(role);
        }
    }
    expiring
}

/// Whether this pass must sign and publish a generation.
///
/// FRESHNESS is a trigger in its own right, alongside changed content. The publication digest
/// covers the content and deliberately not time, so a fleet at steady state matched it forever and
/// never re-signed — walking straight into the hard expiry of its own metadata, at which point TUF
/// refresh and every signed-assignment authorization fail fleet-wide. Nothing recovers from inside
/// the loop.
pub(crate) fn publication_required(content_unchanged: bool, renewals: &[TufRole]) -> bool {
    !content_unchanged || !renewals.is_empty()
}

/// What "this repository is already published" means on disk: the content digest AND the digests of
/// the SIGNED METADATA that content is served under — the local `root.json` and, for the online
/// roles, `timestamp.json`.
///
/// The metadata must be part of it because every re-sign rewrites those documents in place BEFORE
/// this pass uploads anything. If the upload then fails — a lost lease, a transient object-store
/// error, the reconcile future dropped mid-upload — the store keeps serving the OLD documents while
/// the local ones have already moved on, and a marker keyed on CONTENT alone matches again on the
/// next pass, so nothing ever republishes:
///
/// * ROOT: `status.routingRootSha256` (read from the local root) then pins enrollment and node
///   capability authorization against a root the store does not serve — fleet-wide failure until
///   some unrelated content change happens to heal it.
/// * ONLINE roles: `sign_plan` re-signs targets/snapshot/timestamp with a fresh expiry, so the
///   freshness trigger CLEARS ITSELF — `expiring_metadata` reads the freshly signed LOCAL
///   `timestamp.json` and reports nothing expiring — and the store is left serving online metadata
///   that hard-expires ~90 days later, at which point every agent's TUF refresh fails at once.
///
/// With both digests in the marker, a local re-sign that never reached the store IS the mismatch,
/// and it demands the republication that heals it on the very next pass.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicationMarker {
    pub(crate) plan_sha256: String,
    pub(crate) root_sha256: String,
    pub(crate) timestamp_sha256: String,
}

impl PublicationMarker {
    pub(crate) fn validate(&self) -> Result<(), StorageError> {
        if [
            self.plan_sha256.as_str(),
            self.root_sha256.as_str(),
            self.timestamp_sha256.as_str(),
        ]
        .into_iter()
        .all(updated_contracts::is_canonical_sha256)
        {
            Ok(())
        } else {
            Err(StorageError(
                "publication marker contains a non-canonical SHA-256 identity".into(),
            ))
        }
    }

    pub(crate) fn to_bounded_json(&self) -> Result<Vec<u8>, StorageError> {
        self.validate()?;
        let encoded = serde_json::to_vec(self)
            .map_err(|error| StorageError(format!("encoding publication marker: {error}")))?;
        if encoded.len() > PUBLICATION_MARKER_MAX_BYTES {
            return Err(StorageError(
                "publication marker exceeds its fixed bound".into(),
            ));
        }
        Ok(encoded)
    }
}

pub(crate) async fn optional_marker_file_sha256(
    path: &Path,
) -> Result<Option<String>, StorageError> {
    match read_local_bounded(path, LOCAL_TUF_METADATA_MAX_BYTES).await {
        Ok(bytes) => Ok(Some(updated_contracts::digest::sha256_bytes(&bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StorageError(format!(
            "cannot read publication metadata {}: {error}",
            path.display()
        ))),
    }
}

/// Resolve the exact local signed generation. A completely absent repository is the one valid
/// `None` (first initialization); a partial or unreadable repository is corruption and fails
/// closed instead of manufacturing an identity with missing hashes.
pub(crate) async fn publication_marker(
    state_dir: &Path,
    digest: &str,
) -> Result<Option<PublicationMarker>, StorageError> {
    if !updated_contracts::is_canonical_sha256(digest) {
        return Err(StorageError(
            "publication plan digest is not canonical SHA-256".into(),
        ));
    }
    let metadata = state_dir.join("repository/metadata");
    let root = optional_marker_file_sha256(&metadata.join("root.json")).await?;
    let timestamp = optional_marker_file_sha256(&metadata.join("timestamp.json")).await?;
    match (root, timestamp) {
        (None, None) => Ok(None),
        (Some(root_sha256), Some(timestamp_sha256)) => {
            let marker = PublicationMarker {
                plan_sha256: digest.to_string(),
                root_sha256,
                timestamp_sha256,
            };
            marker.validate()?;
            Ok(Some(marker))
        }
        _ => Err(StorageError(
            "local signed repository is partial: root.json and timestamp.json must exist together"
                .into(),
        )),
    }
}

pub(crate) async fn read_publication_marker(
    path: &Path,
) -> Result<Option<PublicationMarker>, StorageError> {
    let bytes = match read_local_bounded(path, PUBLICATION_MARKER_MAX_BYTES).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(StorageError(format!(
                "cannot read publication marker {}: {error}",
                path.display()
            )));
        }
    };
    let marker: PublicationMarker = serde_json::from_slice(&bytes).map_err(|error| {
        StorageError(format!(
            "invalid publication marker {}: {error}",
            path.display()
        ))
    })?;
    marker.validate()?;
    Ok(Some(marker))
}

/// The SHA-256 of a file, or `None` when it cannot be read.
pub(crate) async fn file_sha256(path: &Path) -> Option<String> {
    let bytes = read_local_bounded(path, LOCAL_TUF_METADATA_MAX_BYTES)
        .await
        .ok()?;
    Some(updated_contracts::digest::sha256_bytes(&bytes))
}

/// Renew the TUF root in place when it is inside its renewal window — same key set, next version,
/// fresh expiry. Returns the operator-facing reason when it could not be renewed, having logged the
/// cause; `None` means there was nothing to do or it was done.
///
/// A renewal that fails is NOT a failed reconcile. The root that could not be re-signed is still
/// valid for up to [`METADATA_RENEWAL_DAYS`], and the ordinary cause — the signing Secret no longer
/// holds enough of the keys the current root lists, after a drifted or regenerated Secret — has
/// nothing to do with the content being published. Propagating it stopped every rollout, every
/// admission, and every durable write for the whole ninety-day window, over a condition the fleet
/// was not affected by.
///
/// The failed role is dropped from `renewals` for the same reason it must not abort: `root.json` is
/// unchanged, so it stays inside its window and would otherwise demand a freshly signed and
/// uploaded generation on every reconcile — one per second — until the operator noticed. The
/// operator is told by a status condition instead, and the next pass tries again.
///
/// Only ever called while holding the publisher lease, so two replicas cannot both bump the root.
/// Idempotent by construction: a renewed root is not expiring, so the next pass no longer asks.
pub(crate) async fn renew_expiring_root(
    repo_dir: &Path,
    keys_dir: &Path,
    repository: &str,
    renewals: &mut Vec<TufRole>,
) -> Option<String> {
    if !renewals.contains(&TufRole::Root) {
        return None;
    }
    tracing::info!(
        repository,
        "renewing the TUF root: it is inside its renewal window"
    );
    let outcome = match updated_tuf::repo::Keys::in_dir(keys_dir) {
        Ok(keys) => {
            updated_tuf::repo::renew_root(repo_dir, &keys.roots, METADATA_EXPIRY_DAYS).await
        }
        Err(error) => Err(error),
    };
    let error = outcome.err()?;
    tracing::error!(
        repository,
        %error,
        "could not renew the TUF root; it is inside its renewal window and will HARD EXPIRE, after \
         which every agent's metadata refresh fails at once. Content publication continues. Check \
         that the signing Secret still holds the root keys the current root.json lists."
    );
    renewals.retain(|role| *role != TufRole::Root);
    Some(format!(
        "The TUF root is inside its renewal window and could not be re-signed: {error}"
    ))
}

/// The `expires` instant a signed TUF metadata document declares, or `None` when it cannot be read.
pub(crate) async fn metadata_expiry(path: &Path) -> Option<chrono::DateTime<chrono::Utc>> {
    let bytes = read_local_bounded(path, LOCAL_TUF_METADATA_MAX_BYTES)
        .await
        .ok()?;
    let document: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let expires = document.pointer("/signed/expires")?.as_str()?;
    chrono::DateTime::parse_from_rfc3339(expires)
        .ok()
        .map(|instant| instant.with_timezone(&chrono::Utc))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn repository_object_keys_have_one_platform_independent_spelling() {
        assert_eq!(
            repository_object_key("releases", Path::new("metadata/timestamp.json"))
                .unwrap()
                .as_ref(),
            "releases/metadata/timestamp.json"
        );
        assert!(repository_object_key("releases", Path::new("../root.json")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn repository_object_keys_never_rewrite_invalid_path_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;

        let path = Path::new(OsStr::from_bytes(b"targets/invalid-\xff"));
        let error = repository_object_key("releases", path).unwrap_err();

        assert!(error.0.contains("not UTF-8"));
    }
}
