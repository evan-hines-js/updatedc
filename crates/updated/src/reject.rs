//! Persistent suppression of content-addressed releases that proved unsafe.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Rejections {
    path: PathBuf,
    hashes: HashSet<String>,
    overrides: HashSet<String>,
}

impl Rejections {
    /// Load the record from `path`. Only a missing file is an empty set; unreadable or
    /// malformed state fails closed so rejected bytes cannot silently become eligible.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let hashes = load_keys(path, "rejection")?;
        let overrides = load_keys(&override_path(path), "rejection override")?;
        Ok(Rejections {
            path: path.to_owned(),
            hashes,
            overrides,
        })
    }

    /// Path of the deliberately local break-glass allowlist. Adding an exact rejection
    /// key here and restarting the runtime permits those same bytes to be tried again.
    /// Normal remediation publishes corrected bytes, whose new digest needs no override.
    pub fn override_path(path: &Path) -> PathBuf {
        override_path(path)
    }

    /// Whether these exact bytes were rejected. Rejections do not expire: retrying an
    /// unchanged, proven-bad artifact only creates an availability loop. Publishing
    /// corrected bytes produces a new digest and is immediately eligible. An exact key
    /// in the startup-loaded break-glass file overrides the rejection.
    pub fn is_rejected(&self, hash: &str) -> bool {
        digest_key(hash)
            .is_ok_and(|hash| self.hashes.contains(&hash) && !self.overrides.contains(&hash))
    }

    /// Record `hash` as rejected (persisted immediately). Validated on the way in with the
    /// same rule [`Rejections::load`] enforces on the way out: a key that `save` accepts
    /// but `load` refuses would fail every subsequent start, and the rejection record is
    /// read before anything else the supervisor does.
    pub fn reject(&mut self, hash: &str) -> std::io::Result<()> {
        let hash = digest_key(hash)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        self.hashes.insert(hash);
        self.save()
    }

    /// Drop any rejection for `hash` (e.g. once it later commits cleanly).
    pub fn clear(&mut self, hash: &str) -> std::io::Result<()> {
        let hash = digest_key(hash)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        if self.hashes.remove(&hash) {
            self.save()
        } else {
            Ok(())
        }
    }

    fn save(&self) -> std::io::Result<()> {
        let mut out = String::new();
        for hash in &self.hashes {
            out.push_str(hash);
            out.push('\n');
        }
        foundation::durable::atomic_write(&self.path, ".rejections-", out.as_bytes())
    }
}

fn load_keys(path: &Path, record: &str) -> std::io::Result<HashSet<String>> {
    let mut hashes = HashSet::new();
    let text = match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    if let Some(text) = text {
        for (line_no, line) in text.lines().enumerate() {
            let hash = digest_key(line).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("malformed {record}: {e} at line {}", line_no + 1),
                )
            })?;
            hashes.insert(hash);
        }
    }
    Ok(hashes)
}

fn override_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".allow");
    PathBuf::from(name)
}

/// Canonical rejection key. Supervisor candidates use their plain digest; application
/// candidates use `repository-lineage:digest`, preventing a rejection in one metadata
/// lineage from poisoning a different lineage that happens to reuse the same bytes.
fn digest_key(hash: &str) -> Result<String, String> {
    let valid = updated_contracts::is_sha256_hex(hash)
        || hash.split_once(':').is_some_and(|(lineage, digest)| {
            updated_contracts::is_sha256_hex(lineage) && updated_contracts::is_sha256_hex(digest)
        });
    if !valid {
        return Err(format!(
            "invalid rejection key (expected a SHA-256 digest or lineage:digest, got {} characters)",
            hash.len()
        ));
    }
    Ok(hash.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("reject-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("rejected")
    }

    #[test]
    fn rejects_then_survives_reload() {
        let path = tmp("persist");
        let digest = hash('2');
        let mut r = Rejections::load(&path).unwrap();
        assert!(!r.is_rejected(&digest));
        r.reject(&digest).unwrap();
        assert!(r.is_rejected(&digest));

        // A fresh load (as after a restart) still remembers it.
        let r2 = Rejections::load(&path).unwrap();
        assert!(r2.is_rejected(&digest), "rejection survives a restart");
        assert!(!r2.is_rejected(&hash('3')));
    }

    #[test]
    fn application_rejections_are_scoped_to_repository_lineage() {
        let path = tmp("lineage");
        let digest = hash('2');
        let x = format!("{}:{digest}", hash('a'));
        let y = format!("{}:{digest}", hash('b'));
        let mut rejections = Rejections::load(&path).unwrap();
        rejections.reject(&x).unwrap();
        assert!(rejections.is_rejected(&x));
        assert!(!rejections.is_rejected(&y));
    }

    #[test]
    fn rejection_is_not_a_retry_timer() {
        let path = tmp("permanent");
        let digest = hash('2');
        let mut r = Rejections::load(&path).unwrap();
        r.reject(&digest).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(
            r.is_rejected(&digest),
            "unchanged rejected bytes remain suppressed"
        );
    }

    #[test]
    fn exact_break_glass_entry_allows_rejected_bytes_after_restart() {
        let path = tmp("break-glass");
        let rejected = format!("{}:{}", hash('a'), hash('2'));
        let other = format!("{}:{}", hash('a'), hash('3'));
        let mut first = Rejections::load(&path).unwrap();
        first.reject(&rejected).unwrap();
        first.reject(&other).unwrap();
        assert!(first.is_rejected(&rejected));

        std::fs::write(Rejections::override_path(&path), format!("{rejected}\n")).unwrap();
        let restarted = Rejections::load(&path).unwrap();
        assert!(
            !restarted.is_rejected(&rejected),
            "exact override permits a retry"
        );
        assert!(
            restarted.is_rejected(&other),
            "override cannot broaden to other bytes"
        );
    }

    #[test]
    fn malformed_break_glass_file_fails_closed() {
        let path = tmp("bad-break-glass");
        std::fs::write(Rejections::override_path(&path), "all\n").unwrap();
        assert_eq!(
            Rejections::load(&path).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn clear_removes_the_entry() {
        let path = tmp("clear");
        let digest = hash('2');
        let mut r = Rejections::load(&path).unwrap();
        r.reject(&digest).unwrap();
        r.clear(&digest).unwrap();
        assert!(!r.is_rejected(&digest));
        assert!(!Rejections::load(&path).unwrap().is_rejected(&digest));
    }

    #[test]
    fn corrupt_record_fails_closed() {
        let path = tmp("corrupt");
        std::fs::write(&path, "not-a-hash\tnope\n").unwrap();
        assert_eq!(
            Rejections::load(&path).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn reject_refuses_what_load_would_fail_closed_on() {
        // save() must never be able to write a record load() rejects: the record is read
        // before anything else the supervisor does, so one bad key would be a permanent,
        // un-restartable crash loop rather than one failed rejection.
        let path = tmp("write-contract");
        let mut r = Rejections::load(&path).unwrap();
        for bad in ["", "v2", "2.0.0", &hash('g'), &"a".repeat(63)] {
            assert_eq!(
                r.reject(bad).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput,
                "reject({bad:?}) must be refused at the call, not persisted"
            );
        }
        assert!(!path.exists(), "nothing malformed reached the record");
        assert!(Rejections::load(&path).is_ok());
    }

    #[test]
    fn a_digest_is_matched_case_insensitively() {
        let path = tmp("case");
        let mut r = Rejections::load(&path).unwrap();
        r.reject(&hash('A')).unwrap();
        assert!(r.is_rejected(&hash('a')), "one digest, one entry");
        r.clear(&hash('a')).unwrap();
        assert!(!r.is_rejected(&hash('A')));
    }
}
