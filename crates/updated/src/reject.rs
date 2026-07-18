//! Persistent, expiring suppression of releases that fail their health check.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long a rejected candidate hash stays suppressed. Effectively forever: the
/// remedy for a bad release is a corrected republish (new bytes ⇒ new hash), not the
/// passage of time. Used for supervisor self-update rejections so a candidate that the
/// guardian refused to commit is never re-staged.
pub const REJECT_TTL: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 100);

#[derive(Debug)]
pub struct Rejections {
    path: PathBuf,
    retry_after: Duration,
    map: HashMap<String, u64>,
}

impl Rejections {
    /// Load the record from `path`. Only a missing file is an empty set; unreadable or
    /// malformed state fails closed so rejected bytes cannot silently become eligible.
    pub fn load(path: &Path, retry_after: Duration) -> std::io::Result<Self> {
        let mut map = HashMap::new();
        let text = match std::fs::read_to_string(path) {
            Ok(text) => Some(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        if let Some(text) = text {
            for (line_no, line) in text.lines().enumerate() {
                let (hash, ts) = line.split_once('\t').ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("malformed rejection record at line {}", line_no + 1),
                    )
                })?;
                let hash = digest_key(hash).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("{e} at line {}", line_no + 1),
                    )
                })?;
                let ts = ts.trim().parse().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid rejection timestamp at line {}", line_no + 1),
                    )
                })?;
                map.insert(hash, ts);
            }
        }
        Ok(Rejections {
            path: path.to_owned(),
            retry_after,
            map,
        })
    }

    /// Whether `hash` was rejected and has not yet aged out. A malformed digest is never
    /// present (every stored key is validated on the way in and out), so it reads as
    /// not-rejected rather than erroring a read-only query.
    pub fn is_rejected(&self, hash: &str) -> bool {
        digest_key(hash).is_ok_and(|hash| {
            self.map
                .get(&hash)
                .is_some_and(|&ts| now().saturating_sub(ts) < self.retry_after.as_secs())
        })
    }

    /// Record `hash` as rejected (persisted immediately). Validated on the way in with the
    /// same rule [`Rejections::load`] enforces on the way out: a key that `save` accepts
    /// but `load` refuses would fail every subsequent start, and the rejection record is
    /// read before anything else the supervisor does.
    pub fn reject(&mut self, hash: &str) -> std::io::Result<()> {
        let hash = digest_key(hash)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        self.map.insert(hash, now());
        self.save()
    }

    /// Drop any rejection for `hash` (e.g. once it later commits cleanly).
    pub fn clear(&mut self, hash: &str) -> std::io::Result<()> {
        let hash = digest_key(hash)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        if self.map.remove(&hash).is_some() {
            self.save()
        } else {
            Ok(())
        }
    }

    fn save(&self) -> std::io::Result<()> {
        let mut out = String::new();
        for (hash, ts) in &self.map {
            out.push_str(hash);
            out.push('\t');
            out.push_str(&ts.to_string());
            out.push('\n');
        }
        crate::apply::atomic_write(&self.path, out.as_bytes())
    }
}

/// The canonical map key for a SHA-256 digest: exactly 64 hex characters, lowercased so
/// the same digest never occupies two entries. The single definition of what this record
/// may hold, applied identically on read and write.
fn digest_key(hash: &str) -> Result<String, String> {
    if !crate::hash::is_sha256_hex(hash) {
        return Err(format!(
            "invalid rejection hash (expected a 64-character hexadecimal SHA-256 digest, got {} characters)",
            hash.len()
        ));
    }
    Ok(hash.to_ascii_lowercase())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
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
        let mut r = Rejections::load(&path, Duration::from_secs(3600)).unwrap();
        assert!(!r.is_rejected(&digest));
        r.reject(&digest).unwrap();
        assert!(r.is_rejected(&digest));

        // A fresh load (as after a restart) still remembers it.
        let r2 = Rejections::load(&path, Duration::from_secs(3600)).unwrap();
        assert!(r2.is_rejected(&digest), "rejection survives a restart");
        assert!(!r2.is_rejected(&hash('3')));
    }

    #[test]
    fn entries_age_out_for_retry() {
        let path = tmp("expire");
        let digest = hash('2');
        let mut r = Rejections::load(&path, Duration::from_secs(0)).unwrap(); // immediate expiry
        r.reject(&digest).unwrap();
        assert!(!r.is_rejected(&digest), "an aged-out rejection is retried");
    }

    #[test]
    fn clear_removes_the_entry() {
        let path = tmp("clear");
        let digest = hash('2');
        let mut r = Rejections::load(&path, Duration::from_secs(3600)).unwrap();
        r.reject(&digest).unwrap();
        r.clear(&digest).unwrap();
        assert!(!r.is_rejected(&digest));
        assert!(!Rejections::load(&path, Duration::from_secs(3600))
            .unwrap()
            .is_rejected(&digest));
    }

    #[test]
    fn ttl_is_effectively_a_century() {
        // A century in seconds, spelled out so a dropped factor in the constant is caught.
        assert_eq!(REJECT_TTL.as_secs(), 3_153_600_000);
    }

    #[test]
    fn expiry_is_measured_against_the_real_clock() {
        // A rejection stamped at the epoch must be long expired under any real clock; this
        // fails if `now()` is stubbed to a small constant instead of reading the wall time.
        let path = tmp("stale");
        let digest = hash('2');
        std::fs::write(&path, format!("{digest}\t1000\n")).unwrap();
        let r = Rejections::load(&path, Duration::from_secs(3600)).unwrap();
        assert!(!r.is_rejected(&digest));
    }

    #[test]
    fn corrupt_record_fails_closed() {
        let path = tmp("corrupt");
        std::fs::write(&path, "not-a-hash\tnope\n").unwrap();
        assert_eq!(
            Rejections::load(&path, Duration::from_secs(3600))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn reject_refuses_what_load_would_fail_closed_on() {
        // save() must never be able to write a record load() rejects: the record is read
        // before anything else the supervisor does, so one bad key would be a permanent,
        // un-restartable crash loop rather than one failed rejection.
        let path = tmp("write-contract");
        let mut r = Rejections::load(&path, Duration::from_secs(3600)).unwrap();
        for bad in ["", "v2", "2.0.0", &hash('g'), &"a".repeat(63)] {
            assert_eq!(
                r.reject(bad).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput,
                "reject({bad:?}) must be refused at the call, not persisted"
            );
        }
        assert!(!path.exists(), "nothing malformed reached the record");
        assert!(Rejections::load(&path, Duration::from_secs(3600)).is_ok());
    }

    #[test]
    fn a_digest_is_matched_case_insensitively() {
        let path = tmp("case");
        let mut r = Rejections::load(&path, Duration::from_secs(3600)).unwrap();
        r.reject(&hash('A')).unwrap();
        assert!(r.is_rejected(&hash('a')), "one digest, one entry");
        r.clear(&hash('a')).unwrap();
        assert!(!r.is_rejected(&hash('A')));
    }
}
