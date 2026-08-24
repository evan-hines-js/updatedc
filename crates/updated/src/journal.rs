//! The one durable-intent journal: read, write, clear.
//!
//! An update ([`crate::transaction`]) and a first install ([`crate::install`]) are different
//! transactions with different meanings — one has a predecessor to roll back to, the other does
//! not — but "write the intent atomically before acting, read it back on the next boot, delete it
//! when the transaction is over" is the same three operations over a different record. They were
//! written twice, byte for byte apart from the record type and the temp-file prefix, and the copies
//! had already drifted in what they were tested for: only one pinned that an unreadable journal is
//! an error rather than an absent one, so the other's `NotFound` branch could have swallowed every
//! read failure — a crashed node quietly deciding it had no transaction to recover.
//!
//! Both meanings that must not drift live here: a read error that is not `NotFound` is never
//! "absent", and a record is validated on the way out as well as on the way in, so a journal this
//! process would refuse to act on is one it never wrote.

use std::io;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;

/// Both durable transaction shapes carry exactly one bounded provider identity plus fixed-width
/// release/digest metadata. Keeping their disk ceiling here means adding a new journal cannot
/// accidentally return to an unbounded read path.
const JOURNAL_RECORD_MAX_BYTES: usize =
    crate::state::ProviderRelease::MAX_SERIALIZED_BYTES + 16 * 1024;

/// A durable transaction record. The prefix is the record's own, so the two journals' interrupted
/// temp files are distinguishable in a state directory an operator is looking at.
pub trait Journaled: DeserializeOwned + Serialize {
    /// Temp-file prefix for the atomic write that publishes this record.
    const STAGING_PREFIX: &'static str;

    /// Whether this record is one the node may act on.
    fn validate(&self) -> io::Result<()>;
}

/// The journal at `path`, or `None` when there is none.
///
/// Only `NotFound` is "no journal". Any other read failure propagates: a node that mistook an
/// unreadable journal for an absent one would resume as if the interrupted transaction had never
/// happened.
pub fn read<T: Journaled>(path: &Path) -> io::Result<Option<T>> {
    match foundation::file::read_bounded_regular(
        path,
        JOURNAL_RECORD_MAX_BYTES,
        foundation::file::FinalSymlink::Refuse,
    ) {
        Ok(raw) => {
            let record: T = serde_json::from_slice(&raw)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            record.validate()?;
            Ok(Some(record))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Publish `record` as the durable intent at `path`, atomically — an interrupted write leaves the
/// previous journal, never a truncated one.
pub fn write<T: Journaled>(path: &Path, record: &T) -> io::Result<()> {
    record.validate()?;
    let bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
    if bytes.len() > JOURNAL_RECORD_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal record exceeds its byte limit",
        ));
    }
    foundation::durable::atomic_write_managed(path, T::STAGING_PREFIX, &bytes)
}

/// Drop the journal: the transaction it recorded is over.
pub fn clear(path: &Path) -> io::Result<()> {
    foundation::durable::remove_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One journal's whole life, asserted for whichever record it carries: absent reads as none,
    /// a written record reads back exactly, and a cleared journal is absent again.
    fn round_trips<T: Journaled + PartialEq + std::fmt::Debug>(record: T) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.json");
        assert_eq!(read::<T>(&path).unwrap(), None, "absent journal reads None");

        write(&path, &record).unwrap();
        assert_eq!(
            read::<T>(&path).unwrap(),
            Some(record),
            "written journal reads back"
        );

        clear(&path).unwrap();
        assert_eq!(
            read::<T>(&path).unwrap(),
            None,
            "cleared journal reads None"
        );
    }

    #[test]
    fn a_journal_round_trips_and_an_absent_one_reads_as_none() {
        round_trips(crate::testing::update_transaction());
        round_trips(crate::testing::install_transaction());
    }

    /// A read error that is *not* NotFound (here, the path is a directory) must propagate. Mistaken
    /// for an absent journal it would tell a crashed node it had no transaction to recover — and
    /// this used to be pinned for the update journal only, so the install copy could have grown the
    /// bug undetected.
    #[test]
    fn an_unreadable_journal_is_an_error_not_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read::<crate::transaction::Transaction>(dir.path()).is_err());
        assert!(read::<crate::install::InstallTransaction>(dir.path()).is_err());
    }

    /// The prefixes are what an operator sees in a state directory after an interrupted write, and
    /// what tells the two journals' leftovers apart.
    #[test]
    fn the_two_journals_stage_under_distinct_prefixes() {
        assert_ne!(
            <crate::transaction::Transaction as Journaled>::STAGING_PREFIX,
            <crate::install::InstallTransaction as Journaled>::STAGING_PREFIX
        );
    }
}
