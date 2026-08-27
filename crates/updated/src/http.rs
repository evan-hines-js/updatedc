//! The one bounded read of an HTTP response body.
//!
//! Every control-plane response the agent consumes — enrollment, renewal, and capability
//! documents — is small and arrives over a connection the agent authenticated but does not
//! control. A hostile or broken gateway must not be able to stream an unbounded body into the
//! agent's memory, so each read is capped. The cap is enforced in two places for one reason:
//! `Content-Length` is a cheap early reject, but it is only a *claim*, so the running total is
//! re-checked on every chunk. Both callers share this so the two halves can never drift apart —
//! a declared-length-only check would be trivially bypassed by omitting the header.

use std::io;

use futures::StreamExt;

pub use updated_contracts::endpoint::EndpointTransport;

/// Where an outbound request's total deadline is enforced. Most controller integrations put it on
/// their shared client; the health proxy owns a separate per-fetch `tokio::time::timeout` that also
/// covers streaming the response body. Making the exceptional case explicit keeps "no timeout"
/// from being an accidental builder default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboundDeadline {
    Total(std::time::Duration),
    ExternallyEnforced,
}

/// Parse the one network-endpoint grammar used by the agent and controller.
///
/// Paths are allowed because a gateway or webhook may live below an ingress prefix. Userinfo,
/// query material, and fragments are not: credentials belong in mounted files and headers, while
/// reqwest errors and Kubernetes status may retain the configured URL. Keeping secrets out of the
/// URL makes those diagnostic paths safe by construction.
pub fn network_endpoint(
    value: &str,
    transport: EndpointTransport,
    what: &str,
) -> io::Result<reqwest::Url> {
    updated_contracts::endpoint::network_endpoint(value, transport)
        .map_err(|_| invalid_endpoint(what, transport))
}

fn invalid_endpoint(what: &str, transport: EndpointTransport) -> io::Error {
    let schemes = match transport {
        EndpointTransport::HttpsOnly => "HTTPS",
        EndpointTransport::HttpOrHttps => "HTTP(S)",
    };
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "{what} must be an absolute {schemes} URL with a host and without credentials, query material, or a fragment"
        ),
    )
}

/// Build the one client policy for operator-configured outbound endpoints. Redirects are refused
/// so a signed body, bearer header, or trusted health origin never escapes from the configured
/// authority to another host. Every caller must also name where its total deadline lives.
pub fn outbound_client(deadline: OutboundDeadline) -> io::Result<reqwest::Client> {
    finish_outbound_client(reqwest::Client::builder(), deadline)
}

/// Apply the shared redirect/deadline invariant to a caller-supplied builder (for example, one
/// carrying an explicit rustls mTLS config). This is the only place an outbound reqwest client is
/// finalized, so specialized TLS cannot drift from the ordinary webhook/health policy.
pub fn finish_outbound_client(
    mut builder: reqwest::ClientBuilder,
    deadline: OutboundDeadline,
) -> io::Result<reqwest::Client> {
    builder = builder.redirect(reqwest::redirect::Policy::none());
    if let OutboundDeadline::Total(timeout) = deadline {
        builder = builder.timeout(timeout);
    }
    builder.build().map_err(io::Error::other)
}

/// Read one exact HTTPS redirect capability without following it on the mTLS connection.
pub fn redirect_capability(response: &reqwest::Response, what: &str) -> io::Result<reqwest::Url> {
    if response.status() != reqwest::StatusCode::TEMPORARY_REDIRECT {
        return Err(io::Error::other(format!(
            "{what} returned HTTP {} instead of an object capability",
            response.status()
        )));
    }
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| io::Error::other(format!("{what} omitted its capability location")))?;
    updated_contracts::dataflow::capability_url(location).map_err(io::Error::other)
}

/// Classify a reqwest failure without formatting its URL. Capability URLs are bearer secrets and
/// reqwest errors may retain the request URL, including its signing query.
pub fn redacted_reqwest_error(what: &str, error: &reqwest::Error) -> io::Error {
    let kind = if error.is_timeout() {
        "timed out"
    } else if error.is_connect() {
        "could not connect"
    } else if error.is_body() {
        "body transfer failed"
    } else if error.is_decode() {
        "response decoding failed"
    } else if error.is_redirect() {
        "redirect was refused"
    } else if error.is_request() {
        "request failed"
    } else {
        "transport failed"
    };
    io::Error::other(format!("{what} {kind}"))
}

/// Authenticate bytes received through an anonymous exact-object capability.
///
/// The bearer URL grants access but does not make its object store a trust boundary. Enrollment
/// bundles and assigned runtime inputs both pass through this one check before either parser sees
/// the bytes; errors deliberately omit the URL and both digests.
pub fn authenticate_download_bytes(
    capability: &updated_contracts::dataflow::DownloadCapability,
    bytes: &[u8],
    what: &str,
) -> io::Result<()> {
    capability
        .validate()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if updated_contracts::digest::sha256_bytes(bytes) != capability.sha256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} does not match the control-plane SHA-256"),
        ));
    }
    Ok(())
}

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
        let chunk = chunk.map_err(|error| redacted_reqwest_error(what, &error))?;
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

    #[test]
    fn exact_downloads_are_authenticated_before_parsing() {
        let bytes = b"exact object";
        let capability = updated_contracts::dataflow::DownloadCapability {
            schema: updated_contracts::dataflow::DownloadCapability::SCHEMA,
            url: "https://objects.example/exact?X-Amz-Signature=secret".into(),
            sha256: updated_contracts::digest::sha256_bytes(bytes),
        };
        authenticate_download_bytes(&capability, bytes, "object").unwrap();
        assert_eq!(
            authenticate_download_bytes(&capability, b"substituted", "object")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn every_configured_network_endpoint_uses_one_safe_grammar() {
        network_endpoint(
            "https://gateway.example/fleet",
            EndpointTransport::HttpsOnly,
            "gateway",
        )
        .unwrap();
        network_endpoint(
            "http://health-proxy.updated-system.svc/ready",
            EndpointTransport::HttpOrHttps,
            "health endpoint",
        )
        .unwrap();

        for invalid in [
            "http://gateway.example",
            "https://user@gateway.example",
            "https://gateway.example?token=secret",
            "https://gateway.example#fragment",
            "gateway.example",
            "file:///gateway",
        ] {
            assert!(
                network_endpoint(invalid, EndpointTransport::HttpsOnly, "gateway").is_err(),
                "accepted {invalid}"
            );
        }
    }
}
