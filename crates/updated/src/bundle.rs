//! The sole application artifact format: an immutable, manifested tar.zst release.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use crate::hash::sha256_file;

pub const MANIFEST_FILE: &str = "manifest.json";
pub const MANIFEST_SCHEMA: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseId {
    pub version: String,
    pub manifest_sha256: String,
}

impl ReleaseId {
    pub fn directory_name(&self) -> String {
        format!("{}-{}", self.version, self.manifest_sha256)
    }

    fn validate(&self) -> io::Result<()> {
        semver::Version::parse(&self.version).map_err(invalid)?;
        validate_digest(&self.manifest_sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema: u32,
    pub product: String,
    pub version: String,
    pub platform: String,
    pub entrypoint: String,
    pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub executable: bool,
}

#[derive(Debug, Clone)]
pub struct BundleLimits {
    pub archive_bytes: u64,
    pub expanded_bytes: u64,
    pub file_bytes: u64,
    pub files: usize,
    pub path_bytes: usize,
}

impl Default for BundleLimits {
    fn default() -> Self {
        Self {
            archive_bytes: 512 << 20,
            expanded_bytes: 1 << 30,
            file_bytes: 512 << 20,
            files: 16_384,
            path_bytes: 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExpectedBundle<'a> {
    pub product: &'a str,
    pub version: &'a str,
    pub platform: &'a str,
}

#[derive(Debug)]
pub struct StagedRelease {
    pub id: ReleaseId,
    pub archive_sha256: String,
    pub directory: PathBuf,
    pub entrypoint: PathBuf,
}

/// Build the canonical deterministic application archive from a prepared release tree.
/// `source` must not itself contain `manifest.json`; the publisher generates it from the
/// exact files that will be archived.
pub fn create_bundle(
    source: &Path,
    archive: &Path,
    product: &str,
    version: &str,
    platform: &str,
    entrypoint: &str,
) -> io::Result<BundleManifest> {
    semver::Version::parse(version).map_err(invalid)?;
    validate_relative(entrypoint, 1024)?;
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("bundle source is not a regular directory"));
    }
    let mut paths = Vec::new();
    collect_files(source, source, &mut paths)?;
    paths.sort();
    let mut files = Vec::with_capacity(paths.len());
    for relative in &paths {
        let path = source.join(relative);
        let metadata = fs::symlink_metadata(&path)?;
        let executable = relative == entrypoint || is_executable(&metadata);
        files.push(ManifestFile {
            path: relative.clone(),
            sha256: sha256_file(&path)?,
            size: metadata.len(),
            executable,
        });
    }
    let manifest = BundleManifest {
        schema: MANIFEST_SCHEMA,
        product: product.to_string(),
        version: version.to_string(),
        platform: platform.to_string(),
        entrypoint: entrypoint.to_string(),
        files,
    };
    let expected = ExpectedBundle {
        product,
        version,
        platform,
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(invalid)?;
    BundleManifest::parse(&manifest_bytes, &expected)?;

    if let Some(parent) = archive.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let output = File::create(archive)?;
    let encoder = zstd::stream::write::Encoder::new(output, 9)?;
    let mut tar = tar::Builder::new(encoder);
    tar.mode(tar::HeaderMode::Deterministic);
    append_bytes(&mut tar, MANIFEST_FILE, &manifest_bytes, false)?;
    for file in &manifest.files {
        append_file(&mut tar, source, file)?;
    }
    let encoder = tar.into_inner()?;
    encoder.finish()?.sync_all()?;
    Ok(manifest)
}

impl BundleManifest {
    pub fn parse(bytes: &[u8], expected: &ExpectedBundle<'_>) -> io::Result<Self> {
        let manifest: Self = serde_json::from_slice(bytes).map_err(invalid)?;
        if manifest.schema != MANIFEST_SCHEMA {
            return Err(invalid("unsupported bundle manifest schema"));
        }
        if manifest.product != expected.product
            || manifest.version != expected.version
            || manifest.platform != expected.platform
        {
            return Err(invalid(
                "bundle manifest disagrees with authenticated metadata",
            ));
        }
        manifest.validate_shape()?;
        Ok(manifest)
    }

    fn validate_shape(&self) -> io::Result<()> {
        if self.schema != MANIFEST_SCHEMA {
            return Err(invalid("unsupported bundle manifest schema"));
        }
        semver::Version::parse(&self.version).map_err(invalid)?;
        validate_relative(&self.entrypoint, 1024)?;
        let mut exact = BTreeSet::new();
        let mut folded = BTreeSet::new();
        for file in &self.files {
            validate_relative(&file.path, 1024)?;
            validate_digest(&file.sha256)?;
            if !exact.insert(file.path.clone()) || !folded.insert(file.path.to_lowercase()) {
                return Err(invalid("duplicate or case-colliding manifest path"));
            }
        }
        let entry = self
            .files
            .iter()
            .find(|file| file.path == self.entrypoint)
            .ok_or_else(|| invalid("bundle entrypoint is not declared"))?;
        if !entry.executable {
            return Err(invalid("bundle entrypoint is not executable"));
        }
        Ok(())
    }

    pub fn id(&self, bytes: &[u8]) -> io::Result<ReleaseId> {
        Ok(ReleaseId {
            version: self.version.clone(),
            manifest_sha256: sha256_bytes(bytes)?,
        })
    }
}

pub fn read_release(root: &Path, id: &ReleaseId) -> io::Result<(BundleManifest, PathBuf)> {
    id.validate()?;
    let directory = root.join(id.directory_name());
    let directory_meta = fs::symlink_metadata(&directory)?;
    if !directory_meta.is_dir() || directory_meta.file_type().is_symlink() {
        return Err(invalid("release identity does not name a real directory"));
    }
    let bytes = fs::read(directory.join(MANIFEST_FILE))?;
    let manifest: BundleManifest = serde_json::from_slice(&bytes).map_err(invalid)?;
    manifest.validate_shape()?;
    if manifest.schema != MANIFEST_SCHEMA
        || manifest.version != id.version
        || !sha256_bytes(&bytes)?.eq_ignore_ascii_case(&id.manifest_sha256)
    {
        return Err(invalid("release identity does not match its manifest"));
    }
    verify_tree(&directory, &manifest)?;
    let entrypoint = directory.join(&manifest.entrypoint);
    Ok((manifest, entrypoint))
}

pub fn read_active(path: &Path) -> io::Result<Option<ReleaseId>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(invalid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn write_active(path: &Path, release: &ReleaseId) -> io::Result<()> {
    crate::apply::atomic_write(path, &serde_json::to_vec(release).map_err(invalid)?)
}

pub fn stage_bundle(
    archive: &Path,
    staging_root: &Path,
    versions_root: &Path,
    expected: &ExpectedBundle<'_>,
    limits: &BundleLimits,
) -> io::Result<StagedRelease> {
    let archive_meta = fs::symlink_metadata(archive)?;
    if !archive_meta.is_file() || archive_meta.len() > limits.archive_bytes {
        return Err(invalid("bundle archive is not a bounded regular file"));
    }
    ensure_real_directory(staging_root)?;
    ensure_real_directory(versions_root)?;
    let archive_sha256 = sha256_file(archive)?;
    let stage = staging_root.join(format!("stage-{}", crate::rand::token()?));
    fs::create_dir(&stage)?;
    let result = extract(archive, &stage, expected, limits).and_then(|(manifest, bytes)| {
        let id = manifest.id(&bytes)?;
        let destination = versions_root.join(id.directory_name());
        if destination.exists() {
            let (_, entrypoint) = read_release(versions_root, &id)?;
            fs::remove_dir_all(&stage)?;
            return Ok(StagedRelease {
                id,
                archive_sha256,
                directory: destination,
                entrypoint,
            });
        }
        foundation::durable::sync_dir(&stage)?;
        fs::rename(&stage, &destination)?;
        foundation::durable::sync_dir(versions_root)?;
        let (_, entrypoint) = read_release(versions_root, &id)?;
        Ok(StagedRelease {
            id,
            archive_sha256,
            directory: destination,
            entrypoint,
        })
    });
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

fn ensure_real_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("bundle storage root is not a real directory"));
    }
    Ok(())
}

fn extract(
    archive: &Path,
    stage: &Path,
    expected: &ExpectedBundle<'_>,
    limits: &BundleLimits,
) -> io::Result<(BundleManifest, Vec<u8>)> {
    let decoder = zstd::stream::read::Decoder::new(File::open(archive)?)?;
    let mut tar = tar::Archive::new(decoder);
    let mut manifest_bytes = None;
    let mut extracted = BTreeMap::<String, (u64, String)>::new();
    let mut expanded = 0u64;
    for entry in tar.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            return Err(invalid("bundle contains a non-regular archive entry"));
        }
        let path = entry.path()?.to_string_lossy().into_owned();
        validate_relative(&path, limits.path_bytes)?;
        if extracted.len() >= limits.files {
            return Err(invalid("bundle exceeds file-count limit"));
        }
        let size = entry.size();
        if size > limits.file_bytes {
            return Err(invalid("bundle member exceeds file-size limit"));
        }
        expanded = expanded
            .checked_add(size)
            .ok_or_else(|| invalid("bundle size overflow"))?;
        if expanded > limits.expanded_bytes {
            return Err(invalid("bundle exceeds expanded-size limit"));
        }
        let destination = stage.join(&path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)?;
        let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
        entry.read_to_end(&mut bytes)?;
        if bytes.len() as u64 != size {
            return Err(invalid("truncated bundle member"));
        }
        file.write_all(&bytes)?;
        file.sync_all()?;
        let digest = sha256_bytes(&bytes)?;
        if path == MANIFEST_FILE {
            manifest_bytes = Some(bytes);
        } else if extracted.insert(path, (size, digest)).is_some() {
            return Err(invalid("duplicate bundle member"));
        }
    }
    let bytes = manifest_bytes.ok_or_else(|| invalid("bundle manifest is missing"))?;
    let manifest = BundleManifest::parse(&bytes, expected)?;
    if extracted.len() != manifest.files.len() {
        return Err(invalid("bundle files do not exactly match the manifest"));
    }
    for declared in &manifest.files {
        match extracted.get(&declared.path) {
            Some((size, digest))
                if *size == declared.size && digest.eq_ignore_ascii_case(&declared.sha256) => {}
            _ => return Err(invalid("bundle member does not match its manifest")),
        }
        set_executable(&stage.join(&declared.path), declared.executable)?;
    }
    Ok((manifest, bytes))
}

fn collect_files(root: &Path, directory: &Path, out: &mut Vec<String>) -> io::Result<()> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("bundle source contains a symlink"));
        }
        if metadata.is_dir() {
            collect_files(root, &path, out)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(invalid)?
                .to_str()
                .ok_or_else(|| invalid("bundle path is not UTF-8"))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if relative == MANIFEST_FILE {
                return Err(invalid("bundle source must not contain manifest.json"));
            }
            validate_relative(&relative, 1024)?;
            out.push(relative);
        } else {
            return Err(invalid("bundle source contains a non-regular file"));
        }
    }
    Ok(())
}

fn append_file(
    builder: &mut tar::Builder<zstd::stream::write::Encoder<'_, File>>,
    root: &Path,
    file: &ManifestFile,
) -> io::Result<()> {
    let mut input = File::open(root.join(&file.path))?;
    let mut header = deterministic_header(file.size, file.executable)?;
    builder.append_data(&mut header, &file.path, &mut input)
}

fn append_bytes(
    builder: &mut tar::Builder<zstd::stream::write::Encoder<'_, File>>,
    path: &str,
    bytes: &[u8],
    executable: bool,
) -> io::Result<()> {
    let mut header = deterministic_header(bytes.len() as u64, executable)?;
    builder.append_data(&mut header, path, bytes)
}

fn deterministic_header(size: u64, executable: bool) -> io::Result<tar::Header> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(size);
    header.set_mode(if executable { 0o555 } else { 0o444 });
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    Ok(header)
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

pub fn verify_tree(directory: &Path, manifest: &BundleManifest) -> io::Result<()> {
    let mut actual = Vec::new();
    collect_release_files(directory, directory, &mut actual)?;
    actual.sort();
    let mut expected = manifest
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    expected.push(MANIFEST_FILE.into());
    expected.sort();
    if actual != expected {
        return Err(invalid("release tree contains missing or unexpected files"));
    }
    for file in &manifest.files {
        let path = directory.join(&file.path);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.len() != file.size {
            return Err(invalid("release file type or size drifted"));
        }
        if !sha256_file(&path)?.eq_ignore_ascii_case(&file.sha256) {
            return Err(invalid("release file digest drifted"));
        }
        verify_executable(&metadata, file.executable)?;
    }
    Ok(())
}

#[cfg(unix)]
fn verify_executable(metadata: &fs::Metadata, expected: bool) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let actual = metadata.permissions().mode() & 0o111 != 0;
    if actual != expected {
        return Err(invalid("release executable permission drifted"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_executable(_metadata: &fs::Metadata, _expected: bool) -> io::Result<()> {
    Ok(())
}

fn collect_release_files(root: &Path, directory: &Path, out: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("release tree contains a symlink"));
        }
        if metadata.is_dir() {
            collect_release_files(root, &path, out)?;
        } else if metadata.is_file() {
            out.push(
                path.strip_prefix(root)
                    .map_err(invalid)?
                    .to_str()
                    .ok_or_else(|| invalid("release path is not UTF-8"))?
                    .replace(std::path::MAIN_SEPARATOR, "/"),
            );
        } else {
            return Err(invalid("release tree contains a non-regular file"));
        }
    }
    Ok(())
}

fn validate_relative(path: &str, max: usize) -> io::Result<()> {
    if path.is_empty() || path.len() > max || path.contains('\\') {
        return Err(invalid("invalid bundle path"));
    }
    let parsed = Path::new(path);
    if parsed.is_absolute()
        || parsed
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid("bundle path is not a confined relative path"));
    }
    Ok(())
}

fn validate_digest(value: &str) -> io::Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("invalid SHA-256 digest"));
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> io::Result<String> {
    use aws_lc_rs::digest::{digest, SHA256};
    Ok(hex::encode(digest(&SHA256, bytes).as_ref()))
}

#[cfg(unix)]
fn set_executable(path: &Path, executable: bool) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if executable { 0o555 } else { 0o444 }),
    )
}

#[cfg(not(unix))]
fn set_executable(path: &Path, _executable: bool) -> io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("bundle-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn deterministic_bundle_round_trips_to_an_immutable_release() {
        let root = root("roundtrip");
        let source = root.join("source");
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::create_dir_all(source.join("config")).unwrap();
        fs::write(source.join("bin/app"), b"same executable").unwrap();
        fs::write(source.join("config/release.toml"), b"version = \"2.0.0\"\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(source.join("bin/app"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let archive = root.join("bundle.tar.zst");
        create_bundle(
            &source,
            &archive,
            "app",
            "2.0.0",
            "test-platform",
            "bin/app",
        )
        .unwrap();
        let staged = stage_bundle(
            &archive,
            &root.join("staging"),
            &root.join("versions"),
            &ExpectedBundle {
                product: "app",
                version: "2.0.0",
                platform: "test-platform",
            },
            &BundleLimits::default(),
        )
        .unwrap();
        assert_eq!(
            fs::read(staged.directory.join("config/release.toml")).unwrap(),
            b"version = \"2.0.0\"\n"
        );
        assert_eq!(staged.entrypoint, staged.directory.join("bin/app"));
        read_release(&root.join("versions"), &staged.id).unwrap();

        fs::write(staged.directory.join("undeclared"), b"drift").unwrap();
        assert!(read_release(&root.join("versions"), &staged.id).is_err());
    }

    #[test]
    fn manifest_rejects_unknown_fields_and_escaping_paths() {
        let expected = ExpectedBundle {
            product: "app",
            version: "1.0.0",
            platform: "test",
        };
        let unknown = br#"{"schema":1,"product":"app","version":"1.0.0","platform":"test","entrypoint":"bin/app","files":[],"legacy":true}"#;
        assert!(BundleManifest::parse(unknown, &expected).is_err());
        let escaping = br#"{"schema":1,"product":"app","version":"1.0.0","platform":"test","entrypoint":"../app","files":[]}"#;
        assert!(BundleManifest::parse(escaping, &expected).is_err());
    }
}
