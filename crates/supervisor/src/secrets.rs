use std::collections::{BTreeMap, BTreeSet};

use updated::config::Routing;
use updated_contracts::assignment::SecretReference;

const MAX_BUNDLE_BYTES: usize = 1024 * 1024;
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Startup retry schedule for the first bundle fetch: doubling from [`INITIAL_RETRY`] up to
/// [`MAX_RETRY`], forever. The supervisor cannot launch the application without its secrets, and
/// giving up means an installed app stays down for as long as the control plane is unwell.
const INITIAL_RETRY: std::time::Duration = std::time::Duration::from_secs(1);
const MAX_RETRY: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Default, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SecretBundle {
    deployment: String,
    generation: String,
    values: BTreeMap<String, String>,
}

/// The supervisor's only secrets owner. It holds the one authenticated client, validates every
/// bundle against the signed assignment, and publishes a new environment only after the whole
/// bundle has arrived and passed validation.
pub(crate) struct SecretManager {
    endpoint: Option<String>,
    client: Option<reqwest::Client>,
    current: SecretBundle,
}

impl SecretManager {
    pub(crate) async fn initialize(
        routing: &Routing,
        deployment: &str,
        references: &[SecretReference],
    ) -> Result<Self, String> {
        let (endpoint, client) = if routing.is_local() {
            (None, None)
        } else {
            (
                Some(format!(
                    "{}/v1/node/secrets",
                    routing.base_url.trim_end_matches('/')
                )),
                Some(
                    routing
                        .mtls
                        .reqwest_client()
                        .map_err(|error| format!("building secrets mTLS client: {error}"))?,
                ),
            )
        };
        let mut manager = Self {
            endpoint,
            client,
            current: SecretBundle::default(),
        };
        // Retry rather than fail. This runs during argument parsing, before the supervisor exists,
        // and the caller's only response to an error is to print usage and exit — so one refused
        // connection to the control plane during a reboot would leave an already-installed,
        // already-verified application down until a human noticed. The bundle is required (the app
        // launches with these in its environment), so the honest behaviour is to keep asking.
        // A local routing repository has no control-plane endpoint to fetch from, so declared
        // secrets can never be resolved on this node. That is a configuration error, not an
        // outage: retrying it would spin forever instead of telling the operator.
        if manager.endpoint.is_none() && !references.is_empty() {
            return Err(
                "this deployment declares secrets, but a local routing repository has no \
                 control-plane endpoint to fetch them from"
                    .into(),
            );
        }
        let mut backoff = INITIAL_RETRY;
        loop {
            match manager.reconcile(deployment, references).await {
                Ok(_) => return Ok(manager),
                Err(error) => {
                    crate::warn(&format!(
                        "fetching the assigned secrets failed ({error}); retrying in {}s",
                        backoff.as_secs()
                    ));
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_RETRY);
                }
            }
        }
    }

    pub(crate) fn values(&self) -> &BTreeMap<String, String> {
        &self.current.values
    }

    /// Fetch and atomically adopt the bundle for `references`. Returns true only when the child
    /// environment changed; the server's generation is metadata, never trusted as the sole change
    /// detector.
    pub(crate) async fn reconcile(
        &mut self,
        deployment: &str,
        references: &[SecretReference],
    ) -> Result<bool, String> {
        let next = if references.is_empty() {
            SecretBundle::default()
        } else {
            self.fetch(deployment, references).await?
        };
        let changed = self.current.values != next.values;
        self.current = next;
        Ok(changed)
    }

    async fn fetch(
        &self,
        deployment: &str,
        references: &[SecretReference],
    ) -> Result<SecretBundle, String> {
        self.fetch_with_timeout(deployment, references, FETCH_TIMEOUT)
            .await
    }

    async fn fetch_with_timeout(
        &self,
        deployment: &str,
        references: &[SecretReference],
        timeout: std::time::Duration,
    ) -> Result<SecretBundle, String> {
        with_fetch_timeout(timeout, self.fetch_unbounded(deployment, references)).await
    }

    async fn fetch_unbounded(
        &self,
        deployment: &str,
        references: &[SecretReference],
    ) -> Result<SecretBundle, String> {
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or("assigned secrets require an HTTPS control-plane endpoint")?;
        let client = self
            .client
            .as_ref()
            .expect("endpoint and client are paired");
        let response = client
            .get(endpoint)
            .send()
            .await
            .map_err(|error| format!("fetching assigned secrets: {error}"))?;
        // The one bounded read every control-plane response goes through: status, declared length,
        // and running total are all checked there, so this path cannot drift from enrollment's.
        let bytes = updated::http::read_bounded(response, "assigned secrets", MAX_BUNDLE_BYTES)
            .await
            .map_err(|error| error.to_string())?;
        let bundle: SecretBundle = serde_json::from_slice(&bytes)
            .map_err(|error| format!("decoding assigned secrets: {error}"))?;
        validate_bundle(bundle, deployment, references)
    }
}

async fn with_fetch_timeout<T>(
    timeout: std::time::Duration,
    fetch: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    tokio::time::timeout(timeout, fetch).await.map_err(|_| {
        format!(
            "fetching assigned secrets exceeded its {}s timeout",
            timeout.as_secs_f64()
        )
    })?
}

fn validate_bundle(
    bundle: SecretBundle,
    deployment: &str,
    references: &[SecretReference],
) -> Result<SecretBundle, String> {
    let expected: BTreeSet<&str> = references
        .iter()
        .map(|item| item.environment.as_str())
        .collect();
    let actual: BTreeSet<&str> = bundle.values.keys().map(String::as_str).collect();
    if bundle.deployment != deployment
        || bundle.generation.is_empty()
        || bundle.generation.len() > 256
        || expected != actual
    {
        return Err(
            "control plane returned a secret bundle that does not match the assignment".into(),
        );
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(name: &str) -> SecretReference {
        SecretReference {
            environment: name.into(),
            secret: "secret".into(),
            key: "key".into(),
        }
    }

    #[test]
    fn bundle_requires_exact_names_and_a_bounded_generation() {
        let references = [reference("TOKEN")];
        assert!(validate_bundle(
            SecretBundle {
                deployment: "deployment".into(),
                generation: "one".into(),
                values: BTreeMap::from([("TOKEN".into(), "value".into())]),
            },
            "deployment",
            &references,
        )
        .is_ok());
        assert!(validate_bundle(
            SecretBundle {
                deployment: "deployment".into(),
                generation: "one".into(),
                values: BTreeMap::from([("OTHER".into(), "value".into())]),
            },
            "deployment",
            &references,
        )
        .is_err());
        assert!(validate_bundle(
            SecretBundle {
                deployment: "deployment".into(),
                generation: String::new(),
                values: BTreeMap::from([("TOKEN".into(), "value".into())]),
            },
            "deployment",
            &references,
        )
        .is_err());
    }

    #[tokio::test]
    async fn a_stalled_secret_response_is_bounded() {
        let result = with_fetch_timeout(
            std::time::Duration::from_millis(1),
            std::future::pending::<Result<(), String>>(),
        )
        .await;
        let Err(error) = result else {
            panic!("a stalled response must time out");
        };
        assert!(error.contains("timeout"));
    }
}
