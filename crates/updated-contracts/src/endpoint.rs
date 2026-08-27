//! The one URL authority grammar shared by every wire contract and network consumer.
//!
//! Profiles differ in whether they allow internal HTTP, require bearer query material, or require
//! an origin rather than a path. They do not differ in how credentials and fragments are treated.
//! Keeping that common gate here prevents a new endpoint-shaped contract from quietly admitting
//! userinfo or client-local fragments that another consumer rejects (or logs).

/// The transport policy for an operator-configured network endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointTransport {
    HttpsOnly,
    HttpOrHttps,
}

/// An endpoint does not satisfy the selected wire-contract profile.
///
/// The parser deliberately exposes one opaque classification rather than a parse-library error:
/// callers own the field-specific message, and must never accidentally echo a bearer URL while
/// reporting why it was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointError;

impl std::fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid network endpoint")
    }
}

impl std::error::Error for EndpointError {}

#[derive(Clone, Copy)]
pub(crate) enum QueryPolicy {
    Forbidden,
    Required,
}

/// Parse the network-endpoint profile used by operator configuration.
///
/// Paths are allowed. Credentials, query material, and fragments are not.
pub fn network_endpoint(
    value: &str,
    transport: EndpointTransport,
) -> Result<url::Url, EndpointError> {
    let parsed = url::Url::parse(value).map_err(|_| EndpointError)?;
    let scheme_allowed = match transport {
        EndpointTransport::HttpsOnly => parsed.scheme() == "https",
        EndpointTransport::HttpOrHttps => matches!(parsed.scheme(), "http" | "https"),
    };
    if !scheme_allowed
        || parsed.host_str().is_none()
        || !has_unambiguous_shape(&parsed, QueryPolicy::Forbidden)
    {
        return Err(EndpointError);
    }
    Ok(parsed)
}

/// Parse an HTTPS origin: the root authority from which absolute capability URLs are minted.
pub fn https_origin(value: &str) -> Result<url::Url, EndpointError> {
    let parsed = network_endpoint(value, EndpointTransport::HttpsOnly)?;
    if parsed.cannot_be_a_base() || parsed.path() != "/" {
        return Err(EndpointError);
    }
    Ok(parsed)
}

pub(crate) fn https_url(value: &str, query: QueryPolicy) -> Result<url::Url, EndpointError> {
    let parsed = url::Url::parse(value).map_err(|_| EndpointError)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !has_unambiguous_shape(&parsed, query)
    {
        return Err(EndpointError);
    }
    Ok(parsed)
}

pub(crate) fn has_unambiguous_shape(url: &url::Url, query: QueryPolicy) -> bool {
    let query_allowed = match query {
        QueryPolicy::Forbidden => url.query().is_none(),
        QueryPolicy::Required => url.query().is_some_and(|value| !value.is_empty()),
    };
    url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && query_allowed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_endpoints_and_origins_share_one_unambiguous_authority_gate() {
        network_endpoint(
            "https://gateway.example/fleet",
            EndpointTransport::HttpsOnly,
        )
        .unwrap();
        network_endpoint(
            "http://health-proxy.updated-system.svc/ready",
            EndpointTransport::HttpOrHttps,
        )
        .unwrap();
        assert_eq!(
            https_origin("https://EXAMPLE.com:443").unwrap().as_str(),
            "https://example.com/"
        );

        for invalid in [
            "http://gateway.example",
            "https://user@gateway.example",
            "https://gateway.example?token=secret",
            "https://gateway.example#fragment",
            "gateway.example",
            "file:///gateway",
        ] {
            assert!(
                network_endpoint(invalid, EndpointTransport::HttpsOnly).is_err(),
                "accepted {invalid}"
            );
        }
        for invalid in [
            "http://objects.example",
            "https://user@objects.example",
            "https://objects.example/path",
            "https://objects.example?secret=value",
            "https://objects.example#fragment",
        ] {
            assert!(https_origin(invalid).is_err(), "accepted {invalid}");
        }
    }
}
