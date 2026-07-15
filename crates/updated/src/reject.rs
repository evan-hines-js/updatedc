//! Persistent, expiring suppression of releases that fail their health check.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long a rejected candidate hash stays suppressed. Effectively forever: the
/// remedy for a bad release is a corrected republish (new bytes ⇒ new hash), not the
/// passage of time. Used for supervisor self-update rejections so a candidate that the
/// guardian refused to commit is never re-staged.
pub const REJECT_TTL: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 100);

pub struct Rejections {
    path: PathBuf,
    retry_after: Duration,
    map: HashMap<String, u64>,
}

impl Rejections {
    /// Load the record from `path` (missing/corrupt lines are ignored).
    pub fn load(path: &Path, retry_after: Duration) -> Self {
        let mut map = HashMap::new();
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                if let Some((version, ts)) = line.split_once('\t') {
                    if let Ok(ts) = ts.trim().parse() {
                        map.insert(version.to_string(), ts);
                    }
                }
            }
        }
        Rejections {
            path: path.to_owned(),
            retry_after,
            map,
        }
    }

    /// Whether `version` was rejected and has not yet aged out.
    pub fn is_rejected(&self, version: &str) -> bool {
        self.map
            .get(version)
            .is_some_and(|&ts| now().saturating_sub(ts) < self.retry_after.as_secs())
    }

    /// Record `version` as rejected (persisted immediately).
    pub fn reject(&mut self, version: &str) -> std::io::Result<()> {
        self.map.insert(version.to_string(), now());
        self.save()
    }

    /// Drop any rejection for `version` (e.g. once it later commits cleanly).
    pub fn clear(&mut self, version: &str) -> std::io::Result<()> {
        if self.map.remove(version).is_some() {
            self.save()
        } else {
            Ok(())
        }
    }

    fn save(&self) -> std::io::Result<()> {
        let mut out = String::new();
        for (version, ts) in &self.map {
            out.push_str(version);
            out.push('\t');
            out.push_str(&ts.to_string());
            out.push('\n');
        }
        crate::apply::atomic_write(&self.path, out.as_bytes())
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("reject-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("rejected")
    }

    #[test]
    fn rejects_then_survives_reload() {
        let path = tmp("persist");
        let mut r = Rejections::load(&path, Duration::from_secs(3600));
        assert!(!r.is_rejected("2.0.0"));
        r.reject("2.0.0").unwrap();
        assert!(r.is_rejected("2.0.0"));

        // A fresh load (as after a restart) still remembers it.
        let r2 = Rejections::load(&path, Duration::from_secs(3600));
        assert!(r2.is_rejected("2.0.0"), "rejection survives a restart");
        assert!(!r2.is_rejected("3.0.0"));
    }

    #[test]
    fn entries_age_out_for_retry() {
        let path = tmp("expire");
        let mut r = Rejections::load(&path, Duration::from_secs(0)); // immediate expiry
        r.reject("2.0.0").unwrap();
        assert!(!r.is_rejected("2.0.0"), "an aged-out rejection is retried");
    }

    #[test]
    fn clear_removes_the_entry() {
        let path = tmp("clear");
        let mut r = Rejections::load(&path, Duration::from_secs(3600));
        r.reject("2.0.0").unwrap();
        r.clear("2.0.0").unwrap();
        assert!(!r.is_rejected("2.0.0"));
        assert!(!Rejections::load(&path, Duration::from_secs(3600)).is_rejected("2.0.0"));
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
        std::fs::write(&path, "2.0.0\t1000\n").unwrap();
        let r = Rejections::load(&path, Duration::from_secs(3600));
        assert!(!r.is_rejected("2.0.0"));
    }
}
