//! Persistent suppression of content-addressed releases that proved unsafe.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const MAX_REJECTION_KEYS: usize = 4096;
const MAX_REJECTION_RECORD_BYTES: usize = 1 << 20;

#[derive(Debug)]
pub struct Rejections {
    path: PathBuf,
    hashes: BTreeSet<String>,
    dirty: bool,
}

impl Rejections {
    /// Load the record from `path`. Only a missing file is an empty set; unreadable or
    /// malformed state fails closed so rejected bytes cannot silently become eligible.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let hashes = load_record(path)?;
        Ok(Rejections {
            path: path.to_owned(),
            hashes,
            dirty: false,
        })
    }

    /// Whether these exact bytes were rejected. Rejections do not expire: retrying an
    /// unchanged, proven-bad artifact only creates an availability loop. Publishing
    /// corrected bytes produces a new digest and is immediately eligible. There is no
    /// deletion or override path for the same bytes: a durable safety verdict is monotone.
    pub fn is_rejected(&self, hash: &str) -> bool {
        digest_key(hash).is_ok_and(|hash| self.hashes.contains(&hash))
    }

    /// Evidence that may discharge a durable journal obligation. A failed whole-record write
    /// conservatively withholds this proof until a successful retry, while selection continues
    /// to suppress every rejection observed by the live process.
    pub fn is_durably_rejected(&self, hash: &str) -> bool {
        !self.dirty && self.is_rejected(hash)
    }

    /// Record `hash` as rejected (persisted immediately). Validated on the way in with the
    /// same rule [`Rejections::load`] enforces on the way out: a key that `save` accepts
    /// but `load` refuses would fail every subsequent start, and the rejection record is
    /// read before anything else the agent does.
    pub fn reject(&mut self, hash: &str) -> std::io::Result<()> {
        let hash = digest_key(hash)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        if self.hashes.contains(&hash) {
            return if self.dirty { self.persist() } else { Ok(()) };
        }
        if self.hashes.len() >= MAX_REJECTION_KEYS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rejection record has reached its key limit",
            ));
        }
        // The evidence already exists even if this machine cannot persist it. Keep the live
        // process fail-closed on every write failure. This is also required for the durable
        // primitive's post-rename error: the new record is already visible even though its
        // directory fsync failed, so rolling memory back would make this process disagree with
        // every fresh reader of the same path.
        self.hashes.insert(hash);
        self.persist()
    }

    fn persist(&mut self) -> std::io::Result<()> {
        match self.save() {
            Ok(()) => {
                self.dirty = false;
                Ok(())
            }
            Err(error) => {
                // A later call for this key must retry the whole-set atomic write rather than
                // mistaking in-memory suppression for a durable commit.
                self.dirty = true;
                Err(error)
            }
        }
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

fn load_record(path: &Path) -> std::io::Result<BTreeSet<String>> {
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
        let body = text.strip_suffix('\n').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed rejection record: missing final newline",
            )
        })?;
        if body.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed rejection record: empty files are not records",
            ));
        }
        for (line_no, line) in body.split('\n').enumerate() {
            let hash = digest_key(line).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("malformed rejection record: {e} at line {}", line_no + 1),
                )
            })?;
            if hashes.last().is_some_and(|previous| previous >= &hash) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "malformed rejection record: keys are duplicated or unsorted at line {}",
                        line_no + 1
                    ),
                ));
            }
            hashes.insert(hash);
            if hashes.len() > MAX_REJECTION_KEYS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "rejection record exceeds its key limit",
                ));
            }
        }
    }
    Ok(hashes)
}

/// Whether `hash` is a well-formed `repository-lineage:digest` rejection key. The single
/// definition of that grammar — callers that must know in advance whether
/// [`Rejections::reject`] would accept a key ask here rather than restating it.
pub fn is_rejection_key(hash: &str) -> bool {
    hash.split_once(':').is_some_and(|(lineage, digest)| {
        updated_contracts::is_canonical_sha256(lineage)
            && updated_contracts::is_canonical_sha256(digest)
    })
}

/// Validated rejection key. Every package uses `repository-lineage:digest`, preventing a rejection in one metadata
/// lineage from poisoning a different lineage that happens to reuse the same bytes.
fn digest_key(hash: &str) -> Result<String, String> {
    if !is_rejection_key(hash) {
        return Err(format!(
            "invalid rejection key (expected lineage:digest, got {} characters)",
            hash.len()
        ));
    }
    Ok(hash.to_string())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn hash(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn key(byte: char) -> String {
        format!("{}:{}", hash('f'), hash(byte))
    }

    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rejected");
        (dir, path)
    }

    #[test]
    fn rejects_then_survives_reload() {
        let (_dir, path) = tmp();
        let digest = key('2');
        let mut r = Rejections::load(&path).unwrap();
        assert!(!r.is_rejected(&digest));
        r.reject(&digest).unwrap();
        assert!(r.is_rejected(&digest));

        // A fresh load (as after a restart) still remembers it.
        let r2 = Rejections::load(&path).unwrap();
        assert!(r2.is_rejected(&digest), "rejection survives a restart");
        assert!(!r2.is_rejected(&key('3')));
    }

    #[test]
    fn the_durable_record_is_canonical_and_bounded() {
        let (_dir, path) = tmp();
        let mut rejections = Rejections::load(&path).unwrap();
        rejections.reject(&key('b')).unwrap();
        rejections.reject(&key('a')).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{}\n{}\n", key('a'), key('b'))
        );

        std::fs::write(&path, vec![b'x'; MAX_REJECTION_RECORD_BYTES + 1]).unwrap();
        assert_eq!(
            Rejections::load(&path).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn noncanonical_record_aliases_fail_closed() {
        let (_dir, path) = tmp();
        let a = key('a');
        let b = key('b');
        for body in [
            String::new(),
            a.clone(),
            format!(" {a}\n"),
            format!("{a} \n"),
            format!("{a}\n\n"),
            format!("{b}\n{a}\n"),
            format!("{a}\n{a}\n"),
        ] {
            std::fs::write(&path, body).unwrap();
            assert_eq!(
                Rejections::load(&path).unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
        }
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
        let digest = key('2');
        let mut r = Rejections::load(&path).unwrap();
        r.reject(&digest).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(
            r.is_rejected(&digest),
            "unchanged rejected bytes remain suppressed"
        );
    }

    #[test]
    fn persistence_failure_cannot_erase_live_rejection_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("missing-parent");
        let path = parent.join("rejected");
        let digest = key('2');
        let mut rejections = Rejections::load(&path).unwrap();

        assert!(rejections.reject(&digest).is_err());
        assert!(
            rejections.is_rejected(&digest),
            "the process that observed bad bytes must remain fail-closed even when persistence fails"
        );
        assert!(!path.exists());
        assert!(!rejections.is_durably_rejected(&digest));

        std::fs::create_dir(&parent).unwrap();
        rejections
            .reject(&digest)
            .expect("an idempotent retry must finish the failed durable write");
        assert!(Rejections::load(&path).unwrap().is_rejected(&digest));
        assert!(rejections.is_durably_rejected(&digest));
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
        for bad in ["", "v2", "2.0.0", &key('g'), &hash('a'), &"a".repeat(63)] {
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
            r.reject(&key('A')).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        r.reject(&key('a')).unwrap();
        assert!(r.is_rejected(&key('a')));
        assert!(!r.is_rejected(&key('A')));
    }
}
