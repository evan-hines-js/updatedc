//! The one bounded read of an HTTP response body.
//!
//! Every control-plane response the agent consumes — the enrollment/renewal bundle, the assigned
//! secret bundle — is small and arrives over a connection the agent authenticated but does not
//! control. A hostile or broken gateway must not be able to stream an unbounded body into the
//! agent's memory, so each read is capped. The cap is enforced in two places for one reason:
//! `Content-Length` is a cheap early reject, but it is only a *claim*, so the running total is
//! re-checked on every chunk. Both callers share this so the two halves can never drift apart —
//! a declared-length-only check would be trivially bypassed by omitting the header.

use std::io;

use futures::StreamExt;

/// Read `response`'s body, failing if it is (or claims to be) larger than `limit`. A non-2xx status
/// is an error naming the `what` operation, so callers get one consistent failure surface.
pub async fn read_bounded(
    response: reqwest::Response,
    what: &str,
    limit: usize,
) -> io::Result<Vec<u8>> {
    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "{what} returned HTTP {}",
            response.status()
        )));
    }
    // The declared length is only a hint — reject an obviously oversized body before reading a
    // single byte, then keep checking the real total below.
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(too_large(what));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(io::Error::other)?;
        append_chunk(&mut bytes, &chunk, what, limit)?;
    }
    Ok(bytes)
}

/// Append one streamed chunk, enforcing `limit` against the running total (not the declared
/// length), so a response that under-reports or omits `Content-Length` is still bounded.
fn append_chunk(bytes: &mut Vec<u8>, chunk: &[u8], what: &str, limit: usize) -> io::Result<()> {
    if bytes.len().saturating_add(chunk.len()) > limit {
        return Err(too_large(what));
    }
    bytes.extend_from_slice(chunk);
    Ok(())
}

fn too_large(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{what} response is too large"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limit_applies_across_streamed_chunks() {
        // The declared length can lie or be absent, so the running total is what actually bounds
        // the read: a body assembled one byte at a time must still stop at the limit.
        let mut body = vec![0; 15];
        append_chunk(&mut body, &[1], "enrollment", 16).unwrap();
        let error = append_chunk(&mut body, &[2], "enrollment", 16).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("enrollment"));
        assert_eq!(body.len(), 16, "the rejected chunk is never appended");
    }
}
