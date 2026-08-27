//! The request grammar for a served TUF repository object, plus the byte-range grammar used by the
//! development object-store fixture.
//!
//! The production gateway and the development repository fixture both accept the path layout. The
//! gateway never serves payload bytes: it validates the path and mints an exact S3 capability.
//! The fixture is the only in-process byte server, so it also uses [`ByteRange`] to emulate the
//! range behavior a direct object store provides. Authentication and capability policy remain
//! explicit responsibilities of their respective listeners.

/// A request path that names a repository object: its namespace (`metadata`, `targets`, …) and the
/// object's path within that namespace. Which namespaces a given server publishes is the server's
/// own business, so the caller matches `namespace` against the set it serves.
#[derive(Debug, PartialEq, Eq)]
pub struct ObjectRequest<'a> {
    /// The first path segment.
    pub namespace: &'a str,
    /// The remaining segments, joined with `/`. Never empty, never dot-leading, always confined.
    pub relative: String,
}

impl ObjectRequest<'_> {
    /// The object's key relative to the repository root, `<namespace>/<relative>`.
    pub fn key(&self) -> String {
        format!("{}/{}", self.namespace, self.relative)
    }
}

/// Parse a request path into the repository object it names, or `None` if it names none.
///
/// A path must be absolute, carry no query, fragment, percent-escape or backslash (the repository
/// layout has no use for any of them, and each is a way to smuggle a second reading of the path
/// past a validator), and split into a namespace plus at least one further segment. Every segment
/// is confined ([`updated_contracts::path::is_safe_component`]) and additionally may not lead with
/// a dot — no `.`/`..` climb, no empty segment, no hidden keys or files.
pub fn repository_object(request_path: &str) -> Option<ObjectRequest<'_>> {
    if request_path.contains(['?', '#', '%', '\\']) || !request_path.starts_with('/') {
        return None;
    }
    let mut parts = request_path[1..].split('/');
    let namespace = parts.next()?;
    let tail: Vec<_> = parts.collect();
    if tail.is_empty()
        || !tail
            .iter()
            .all(|part| updated_contracts::path::is_safe_component(part) && !part.starts_with('.'))
    {
        return None;
    }
    Some(ObjectRequest {
        namespace,
        relative: tail.join("/"),
    })
}

/// One HTTP byte range over a served object, in the three shapes RFC 9110 defines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteRange {
    /// `bytes=100-`: everything from the offset onward. What a resumed download sends.
    Offset(u64),
    /// `bytes=0-99`: the closed interval `start..=end`.
    Bounded { start: u64, end: u64 },
    /// `bytes=-500`: the last N bytes.
    Suffix(u64),
}

impl ByteRange {
    /// Place the range over an object of `length` bytes: `Some((start, count))`, or `None` if the
    /// range is unsatisfiable (a 416). A bounded end past the last byte and a suffix longer than
    /// the object are clamped, as the RFC requires; a start at or past the end is not satisfiable,
    /// and nothing is satisfiable over an empty object.
    ///
    /// The directory fixture asks this before it writes its status line. Production payloads go
    /// directly to S3, whose range implementation is outside this process.
    pub fn resolve(self, length: u64) -> Option<(u64, u64)> {
        match self {
            Self::Offset(start) if start < length => Some((start, length - start)),
            Self::Bounded { start, end } if start < length => {
                Some((start, end.min(length - 1) - start + 1))
            }
            Self::Suffix(n) if length > 0 => Some((length.saturating_sub(n), n.min(length))),
            _ => None,
        }
    }
}

/// Parse a single HTTP byte range: open-ended (`bytes=100-`), bounded (`bytes=0-99`, end
/// inclusive), or suffix (`bytes=-500`, the last N bytes). Multi-range requests and any malformed
/// value are refused (`None`), matching the read path's conservative framing — a server answers
/// that with a 400 rather than quietly serving the whole object.
pub fn parse_range_value(value: &str) -> Option<ByteRange> {
    let spec = value.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (start, end) = spec.split_once('-')?;
    let range = match (start.trim(), end.trim()) {
        ("", "") => return None,
        // Suffix: the last N bytes. A zero-length suffix is unsatisfiable.
        ("", suffix) => {
            let n: u64 = suffix.parse().ok()?;
            if n == 0 {
                return None;
            }
            ByteRange::Suffix(n)
        }
        // Open-ended: everything from `start` onward.
        (start, "") => ByteRange::Offset(start.parse().ok()?),
        // Bounded: `start`..=`end`.
        (start, end) => {
            let start: u64 = start.parse().ok()?;
            let end: u64 = end.parse().ok()?;
            if end < start {
                return None;
            }
            ByteRange::Bounded { start, end }
        }
    };
    Some(range)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn a_repository_object_is_a_namespace_plus_confined_segments() {
        let parsed = repository_object("/targets/nested/app.tar.gz").unwrap();
        assert_eq!(parsed.namespace, "targets");
        assert_eq!(parsed.relative, "nested/app.tar.gz");
        assert_eq!(parsed.key(), "targets/nested/app.tar.gz");
    }

    #[test]
    fn no_second_reading_of_a_path_is_admitted() {
        // Every one of these was served by one of the two implementations and refused by the
        // other while the grammar was written twice.
        for path in [
            "/metadata//root.json",
            "/metadata/./root.json",
            "/metadata/../root.json",
            "/targets/app?resume=1",
            "/targets/app#frag",
            "/targets/%2e%2e/root.json",
            "/targets/a\\b",
            "/targets/.hidden",
            "targets/app",
            "/targets/",
            "/targets",
            "/",
        ] {
            assert!(repository_object(path).is_none(), "{path} must not resolve");
        }
    }

    #[test]
    fn all_three_range_shapes_parse() {
        assert_eq!(
            parse_range_value("bytes=100-"),
            Some(ByteRange::Offset(100))
        );
        assert_eq!(
            parse_range_value("bytes=0-99"),
            Some(ByteRange::Bounded { start: 0, end: 99 })
        );
        assert_eq!(
            parse_range_value("bytes=-500"),
            Some(ByteRange::Suffix(500))
        );
        for value in ["bytes=wat", "bytes=-", "bytes=-0", "bytes=9-4", "100-", ""] {
            assert!(
                parse_range_value(value).is_none(),
                "{value} must be refused"
            );
        }
        assert!(
            parse_range_value("bytes=0-9,20-29").is_none(),
            "multi-range is refused rather than partially honoured"
        );
    }

    #[test]
    fn ranges_are_placed_over_the_object_the_way_the_rfc_says() {
        assert_eq!(ByteRange::Offset(4).resolve(10), Some((4, 6)));
        assert_eq!(ByteRange::Offset(10).resolve(10), None);
        assert_eq!(
            ByteRange::Bounded { start: 0, end: 3 }.resolve(10),
            Some((0, 4))
        );
        // A bounded end past the last byte clamps; a start past it does not satisfy.
        assert_eq!(
            ByteRange::Bounded { start: 8, end: 99 }.resolve(10),
            Some((8, 2))
        );
        assert_eq!(ByteRange::Bounded { start: 10, end: 99 }.resolve(10), None);
        assert_eq!(ByteRange::Suffix(4).resolve(10), Some((6, 4)));
        // A suffix longer than the object is the whole object; over an empty one, nothing is.
        assert_eq!(ByteRange::Suffix(99).resolve(10), Some((0, 10)));
        assert_eq!(ByteRange::Suffix(4).resolve(0), None);
    }
}
