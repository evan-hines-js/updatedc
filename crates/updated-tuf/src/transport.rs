//! The agent's TUF transport to the externally-exposed gateway.
//!
//! Every routing and release fetch goes to the same gateway, which requires a client
//! certificate, so those fetches always present the agent's mTLS [`Identity`]. mTLS is
//! mandatory — there is no plaintext transport. The crypto is `aws-lc-rs`: the identity builds
//! an aws_lc_rs rustls client config.

use async_trait::async_trait;
use futures::TryStreamExt;
use tough::{FilesystemTransport, Transport, TransportError, TransportErrorKind};
use updated::tls::Identity;
use url::Url;

/// The mTLS transport for a repository fetch. An identity that fails to build is carried to the
/// first fetch as a transport error (never a panic), so the update loop fails closed and retries.
pub(crate) fn transport(mtls: &Identity) -> AgentTransport {
    match mtls.reqwest_client() {
        Ok(client) => AgentTransport::Mtls { client },
        Err(error) => AgentTransport::Broken {
            error: error.to_string(),
        },
    }
}

/// A concrete `tough` transport so it can be handed to `RepositoryLoader::transport`, which
/// requires a sized type. Every fetch is mTLS; a broken identity is a deferred fetch error.
#[derive(Clone, Debug)]
pub(crate) enum AgentTransport {
    Mtls { client: reqwest::Client },
    Broken { error: String },
}

#[async_trait]
impl Transport for AgentTransport {
    async fn fetch(&self, url: Url) -> Result<tough::TransportStream, TransportError> {
        // A `file://` repository is a local, offline signed-repair source — no network, so no
        // gateway and no mTLS. It is served straight from the filesystem, independent of the
        // mTLS identity: an offline source has no CA on disk, so building the identity would fail,
        // and that failure must not break the offline fetch. Mandatory mTLS governs the network
        // transport only, so this precedes the identity state.
        if url.scheme() == "file" {
            return FilesystemTransport.fetch(url).await;
        }
        match self {
            AgentTransport::Broken { error } => Err(TransportError::new_with_cause(
                TransportErrorKind::Other,
                &url,
                std::io::Error::other(error.clone()),
            )),
            AgentTransport::Mtls { client } => {
                let response = client.get(url.clone()).send().await.map_err(|error| {
                    TransportError::new_with_cause(TransportErrorKind::Other, &url, error)
                })?;
                if response.status() == reqwest::StatusCode::NOT_FOUND {
                    return Err(TransportError::new(TransportErrorKind::FileNotFound, &url));
                }
                let response = response.error_for_status().map_err(|error| {
                    TransportError::new_with_cause(TransportErrorKind::Other, &url, error)
                })?;
                let error_url = url.to_string();
                let stream = response.bytes_stream().map_err(move |error| {
                    TransportError::new_with_cause(TransportErrorKind::Other, &error_url, error)
                });
                Ok(Box::pin(stream) as tough::TransportStream)
            }
        }
    }
}
