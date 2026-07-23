use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use updated::config::{Routing, SecretReference};

const MAX_BUNDLE_BYTES: usize = 1024 * 1024;

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
        let local =
            routing.base_url.starts_with("file:") || Path::new(&routing.base_url).is_absolute();
        let (endpoint, client) = if local {
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
        manager.reconcile(deployment, references).await?;
        Ok(manager)
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
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or("assigned secrets require an HTTPS control-plane endpoint")?;
        let client = self
            .client
            .as_ref()
            .expect("endpoint and client are paired");
        let mut response = client
            .get(endpoint)
            .send()
            .await
            .map_err(|error| format!("fetching assigned secrets: {error}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "fetching assigned secrets returned HTTP {}",
                response.status()
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BUNDLE_BYTES as u64)
        {
            return Err("assigned secret bundle exceeds the response limit".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| format!("reading assigned secrets: {error}"))?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_BUNDLE_BYTES {
                return Err("assigned secret bundle exceeds the response limit".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let bundle: SecretBundle = serde_json::from_slice(&bytes)
            .map_err(|error| format!("decoding assigned secrets: {error}"))?;
        validate_bundle(bundle, deployment, references)
    }
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
}
