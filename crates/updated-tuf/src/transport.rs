//! The agent's TUF transport.
//!
//! Routing objects use two explicit hops: mTLS to the control plane for a 307 exact-object
//! capability, then anonymous HTTPS to S3. Release repositories are already direct and never see
//! the node identity. Local `file:` repositories bypass both.

use async_trait::async_trait;
use futures::TryStreamExt;
use tough::{FilesystemTransport, Transport, TransportError, TransportErrorKind};
use updated::config::RepositoryAccess;
use updated::tls::Identity;
use url::Url;

pub(crate) fn transport(mtls: Option<&Identity>, access: RepositoryAccess) -> AgentTransport {
    let object = match access {
        RepositoryAccess::Direct => mtls.map_or_else(
            updated::tls::anonymous_object_client,
            Identity::reqwest_direct_object_client,
        ),
        RepositoryAccess::GatewayCapability => mtls
            .ok_or_else(|| std::io::Error::other("routing repository requires mTLS identity"))
            .and_then(Identity::reqwest_capability_client),
    };
    let object = match object {
        Ok(client) => client,
        Err(error) => {
            return AgentTransport::Broken {
                error: error.to_string(),
            };
        }
    };
    let control = match access {
        RepositoryAccess::Direct => None,
        RepositoryAccess::GatewayCapability => match mtls
            .ok_or_else(|| std::io::Error::other("routing repository requires mTLS identity"))
            .and_then(Identity::reqwest_control_client)
        {
            Ok(client) => Some(client),
            Err(error) => {
                return AgentTransport::Broken {
                    error: error.to_string(),
                };
            }
        },
    };
    AgentTransport::Network { control, object }
}

#[derive(Clone, Debug)]
pub(crate) enum AgentTransport {
    Network {
        /// Present only for the routing gateway. This client refuses redirects and carries mTLS.
        control: Option<reqwest::Client>,
        /// Carries no client identity and refuses redirects, so one bearer cannot widen itself.
        object: reqwest::Client,
    },
    Broken {
        error: String,
    },
}

fn transport_error(url: &Url, message: impl Into<String>) -> TransportError {
    TransportError::new_with_cause(
        TransportErrorKind::Other,
        url,
        std::io::Error::other(message.into()),
    )
}

#[async_trait]
impl Transport for AgentTransport {
    async fn fetch(&self, url: Url) -> Result<tough::TransportStream, TransportError> {
        if url.scheme() == "file" {
            return FilesystemTransport.fetch(url).await;
        }
        let AgentTransport::Network { control, object } = self else {
            let Self::Broken { error } = self else {
                unreachable!()
            };
            return Err(transport_error(&url, error.clone()));
        };

        let object_url = if let Some(control) = control {
            let response = control.get(url.clone()).send().await.map_err(|error| {
                TransportError::new_with_cause(
                    TransportErrorKind::Other,
                    &url,
                    updated::http::redacted_reqwest_error(
                        "requesting an S3 read capability",
                        &error,
                    ),
                )
            })?;
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Err(TransportError::new(TransportErrorKind::FileNotFound, &url));
            }
            updated::http::redirect_capability(&response, "repository capability").map_err(
                |error| TransportError::new_with_cause(TransportErrorKind::Other, &url, error),
            )?
        } else {
            if url.scheme() != "https" {
                return Err(transport_error(
                    &url,
                    "network release repositories must use HTTPS",
                ));
            }
            url.clone()
        };

        let response = object.get(object_url).send().await.map_err(|error| {
            TransportError::new_with_cause(
                TransportErrorKind::Other,
                &url,
                updated::http::redacted_reqwest_error("fetching a repository object", &error),
            )
        })?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(TransportError::new(TransportErrorKind::FileNotFound, &url));
        }
        if !response.status().is_success() {
            return Err(transport_error(
                &url,
                format!("repository object returned HTTP {}", response.status()),
            ));
        }
        let error_url = url.clone();
        let stream = response.bytes_stream().map_err(move |error| {
            TransportError::new_with_cause(
                TransportErrorKind::Other,
                &error_url,
                updated::http::redacted_reqwest_error("reading a repository object", &error),
            )
        });
        Ok(Box::pin(stream) as tough::TransportStream)
    }
}
