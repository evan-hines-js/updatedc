//! Persistent suppression of content-addressed releases that proved unsafe.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const MAX_REJECTION_KEYS: usize = 4096;
const MAX_REJECTION_RECORD_BYTES: usize = 1 << 20;

#[derive(Debug)]
pub struct Rejections {
    path: PathBuf,
    hashes: BTreeSet<String>,
    overrides: BTreeSet<String>,
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
    /// read before anything else the agent does.
    pub fn reject(&mut self, hash: &str) -> std::io::Result<()> {
        let hash = digest_key(hash)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        if self.hashes.contains(&hash) {
            return Ok(());
        }
        if self.hashes.len() >= MAX_REJECTION_KEYS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rejection record has reached its key limit",
            ));
        }
        self.hashes.insert(hash.clone());
        if let Err(error) = self.save() {
            self.hashes.remove(&hash);
            return Err(error);
        }
        Ok(())
    }

    /// Drop any rejection for `hash` (e.g. once it later commits cleanly).
    pub fn clear(&mut self, hash: &str) -> std::io::Result<()> {
        let hash = digest_key(hash)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        if !self.hashes.remove(&hash) {
            return Ok(());
        }
        if let Err(error) = self.save() {
            self.hashes.insert(hash);
            return Err(error);
        }
        Ok(())
    }

    fn save(&self) -> std::io::Result<()> {
        let mut out = String::new();
        for hash in &self.hashes {
            out.push_str(hash);
            out.push('\n');
        }
        if out.len() > MAX_REJECTION_RECORD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rejection record exceeds its byte limit",
            ));
        }
        foundation::durable::atomic_write_managed(&self.path, ".rejections-", out.as_bytes())
    }
}

fn load_keys(path: &Path, record: &str) -> std::io::Result<BTreeSet<String>> {
    let mut hashes = BTreeSet::new();
    let text = match foundation::file::read_bounded_regular_string(
        path,
        MAX_REJECTION_RECORD_BYTES,
        foundation::file::FinalSymlink::Refuse,
    ) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    if let Some(text) = text {
        for (line_no, line) in text.lines().enumerate() {
            // Blank and whitespace-padded lines are skipped, not fatal: the break-glass file
            // (see `override_path`) is hand-edited by an operator during an incident, and a
            // stray blank line there must not turn emergency recovery into a boot failure.
            // A non-empty line that is not a key still fails closed.
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let hash = digest_key(line).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("malformed {record}: {e} at line {}", line_no + 1),
                )
            })?;
            hashes.insert(hash);
            if hashes.len() > MAX_REJECTION_KEYS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{record} exceeds its key limit"),
                ));
            }
        }
    }
    Ok(hashes)
}

/// Path of the deliberately local break-glass allowlist. Adding an exact rejection key here and
/// restarting the runtime permits those same bytes to be tried again. Normal remediation
/// publishes corrected bytes, whose new digest needs no override.
fn override_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".allow");
    PathBuf::from(name)
}

/// Whether `hash` is a well-formed rejection key: a plain SHA-256 digest (agent
/// candidates) or `repository-lineage:digest` (application candidates). The single
/// definition of that grammar — callers that must know in advance whether
/// [`Rejections::reject`] would accept a key ask here rather than restating it.
pub fn is_rejection_key(hash: &str) -> bool {
    updated_contracts::is_canonical_sha256(hash)
        || hash.split_once(':').is_some_and(|(lineage, digest)| {
            updated_contracts::is_canonical_sha256(lineage)
                && updated_contracts::is_canonical_sha256(digest)
        })
}

/// Validated rejection key. Agent candidates use their plain digest; application
/// candidates use `repository-lineage:digest`, preventing a rejection in one metadata
/// lineage from poisoning a different lineage that happens to reuse the same bytes.
fn digest_key(hash: &str) -> Result<String, String> {
    if !is_rejection_key(hash) {
        return Err(format!(
            "invalid rejection key (expected a SHA-256 digest or lineage:digest, got {} characters)",
            hash.len()
        ));
    }
    Ok(hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rejected");
        (dir, path)
    }

    #[test]
    fn rejects_then_survives_reload() {
        let (_dir, path) = tmp();
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
    fn the_durable_record_is_canonical_and_bounded() {
        let (_dir, path) = tmp();
        let mut rejections = Rejections::load(&path).unwrap();
        rejections.reject(&hash('b')).unwrap();
        rejections.reject(&hash('a')).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{}\n{}\n", hash('a'), hash('b'))
        );

        std::fs::write(&path, vec![b'x'; MAX_REJECTION_RECORD_BYTES + 1]).unwrap();
        assert_eq!(
            Rejections::load(&path).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn application_rejections_are_scoped_to_repository_lineage() {
        let (_dir, path) = tmp();
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
        let (_dir, path) = tmp();
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
        let (_dir, path) = tmp();
        let rejected = format!("{}:{}", hash('a'), hash('2'));
        let other = format!("{}:{}", hash('a'), hash('3'));
        let mut first = Rejections::load(&path).unwrap();
        first.reject(&rejected).unwrap();
        first.reject(&other).unwrap();
        assert!(first.is_rejected(&rejected));

        std::fs::write(override_path(&path), format!("{rejected}\n")).unwrap();
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
    fn hand_edited_break_glass_whitespace_still_loads() {
        // The break-glass file is typed by an operator mid-incident. A blank line or a
        // padded entry must still start the runtime: the record is read before anything
        // else the agent does, so a fatal parse here is a permanent boot failure on the
        // one path that exists to end an outage.
        let (_dir, path) = tmp();
        let rejected = format!("{}:{}", hash('a'), hash('2'));
        let mut first = Rejections::load(&path).unwrap();
        first.reject(&rejected).unwrap();

        std::fs::write(override_path(&path), format!("\n  {rejected}  \n\n")).unwrap();
        let restarted = Rejections::load(&path).unwrap();
        assert!(
            !restarted.is_rejected(&rejected),
            "a padded entry beside blank lines still overrides"
        );
    }

    #[test]
    fn malformed_break_glass_file_fails_closed() {
        let (_dir, path) = tmp();
        std::fs::write(override_path(&path), "all\n").unwrap();
        assert_eq!(
            Rejections::load(&path).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn clear_removes_the_entry() {
        let (_dir, path) = tmp();
        let digest = hash('2');
        let mut r = Rejections::load(&path).unwrap();
        r.reject(&digest).unwrap();
        r.clear(&digest).unwrap();
        assert!(!r.is_rejected(&digest));
        assert!(!Rejections::load(&path).unwrap().is_rejected(&digest));
    }

    #[test]
    fn corrupt_record_fails_closed() {
        let (_dir, path) = tmp();
        std::fs::write(&path, "not-a-hash\tnope\n").unwrap();
        assert_eq!(
            Rejections::load(&path).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn reject_refuses_what_load_would_fail_closed_on() {
        // save() must never be able to write a record load() rejects: the record is read
        // before anything else the agent does, so one bad key would be a permanent,
        // un-restartable crash loop rather than one failed rejection.
        let (_dir, path) = tmp();
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
    fn noncanonical_digest_aliases_are_refused() {
        let (_dir, path) = tmp();
        let mut r = Rejections::load(&path).unwrap();
        assert_eq!(
            r.reject(&hash('A')).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        r.reject(&hash('a')).unwrap();
        assert!(r.is_rejected(&hash('a')));
        assert!(!r.is_rejected(&hash('A')));
        r.clear(&hash('a')).unwrap();
        assert!(!r.is_rejected(&hash('a')));
    }
}
