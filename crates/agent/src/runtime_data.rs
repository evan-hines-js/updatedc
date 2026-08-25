use std::sync::atomic::AtomicBool;

use updated::config::Routing;
use updated_contracts::dataflow::{
    DownloadCapability, FileSnapshot, InputPublication, InputSelection, MAX_CAPABILITY_BODY_BYTES,
    MAX_DATAFLOW_BODY_BYTES,
};
use updated_contracts::telemetry::REPORT_CADENCE_JITTER_PERCENT;

use crate::launcher::ReadySignalled;

const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const RETRY_BASE: std::time::Duration = std::time::Duration::from_secs(1);

/// The node's only assigned-input owner.
///
/// The mTLS gateway authorizes the current signed selection and returns a 60-second exact-object
/// S3 capability plus the control-plane-authenticated byte digest. The manager authenticates the
/// anonymous download before parsing it. Every request names the exact assignment this agent
/// verified, so a cached predecessor authorization cannot return stale values; the manager then
/// validates the snapshot against the signed selection before making it visible to a reconciler
/// invocation.
pub(crate) struct RuntimeDataManager {
    gateway_base_url: Option<String>,
    control_client: Option<reqwest::Client>,
    object_client: Option<reqwest::Client>,
    current: FileSnapshot,
    current_selection: InputSelection,
}

impl RuntimeDataManager {
    pub(crate) fn new(routing: &Routing, inputs: &InputSelection) -> Result<Self, String> {
        let (gateway_base_url, control_client, object_client) =
            if routing.is_local()? {
                (None, None, None)
            } else {
                (
                    Some(routing.base_url.clone()),
                    Some(routing.mtls.reqwest_control_client().map_err(|error| {
                        format!("building assigned-input mTLS client: {error}")
                    })?),
                    Some(routing.mtls.reqwest_capability_client().map_err(|error| {
                        format!("building assigned-input HTTPS client: {error}")
                    })?),
                )
            };
        if gateway_base_url.is_none() && !inputs.is_empty() {
            return Err(
                "this deployment declares assigned inputs, but a local routing repository has no \
                 capability endpoint"
                    .into(),
            );
        }
        Ok(Self {
            gateway_base_url,
            control_client,
            object_client,
            current: FileSnapshot::default(),
            current_selection: InputSelection::default(),
        })
    }

    pub(crate) async fn acquire(
        &mut self,
        assignment_sha256: &str,
        inputs: &InputSelection,
        shutdown: &AtomicBool,
        _ready: ReadySignalled,
    ) -> bool {
        let mut failures = 0u32;
        while let Err(error) = self.reconcile(assignment_sha256, inputs).await {
            let backoff = crate::schedule::jitter(
                crate::schedule::network_backoff(RETRY_BASE, failures),
                REPORT_CADENCE_JITTER_PERCENT,
            );
            failures = failures.saturating_add(1);
            crate::warn(&format!(
                "fetching assigned inputs failed ({error}); retrying in {}s",
                backoff.as_secs()
            ));
            if crate::schedule::sleep_interruptible(backoff, shutdown).await {
                return false;
            }
        }
        true
    }

    pub(crate) fn inputs(&self) -> &FileSnapshot {
        &self.current
    }

    pub(crate) async fn reconcile(
        &mut self,
        assignment_sha256: &str,
        inputs: &InputSelection,
    ) -> Result<(), String> {
        inputs.validate()?;
        if inputs == &self.current_selection {
            self.current.validate_selection(inputs)?;
            return Ok(());
        }
        let next = if inputs.is_empty() {
            FileSnapshot::default()
        } else {
            self.fetch(assignment_sha256, inputs).await?
        };
        next.validate_selection(inputs)?;
        self.current = next;
        self.current_selection = inputs.clone();
        Ok(())
    }

    async fn fetch(
        &self,
        assignment_sha256: &str,
        inputs: &InputSelection,
    ) -> Result<FileSnapshot, String> {
        tokio::time::timeout(
            FETCH_TIMEOUT,
            self.fetch_unbounded(assignment_sha256, inputs),
        )
        .await
        .map_err(|_| {
            format!(
                "fetching assigned inputs exceeded its {}s timeout",
                FETCH_TIMEOUT.as_secs_f64()
            )
        })?
    }

    async fn fetch_unbounded(
        &self,
        assignment_sha256: &str,
        inputs: &InputSelection,
    ) -> Result<FileSnapshot, String> {
        let gateway_base_url = self
            .gateway_base_url
            .as_ref()
            .ok_or("assigned inputs require an HTTPS capability endpoint")?;
        let endpoint =
            updated_contracts::dataflow::inputs_url(gateway_base_url, assignment_sha256)?;
        let response = self
            .control_client
            .as_ref()
            .expect("endpoint and client are paired")
            .get(endpoint)
            .send()
            .await
            .map_err(|error| {
                updated::http::redacted_reqwest_error("requesting the input capability", &error)
                    .to_string()
            })?;
        let capability_body = updated::http::read_bounded(
            response,
            "assigned input capability",
            MAX_CAPABILITY_BODY_BYTES,
        )
        .await
        .map_err(|error| error.to_string())?;
        let capability = DownloadCapability::from_bounded_json(&capability_body)?;
        authenticate_input_capability(&capability, inputs)?;
        let response = self
            .object_client
            .as_ref()
            .expect("endpoint and object client are paired")
            .get(&capability.url)
            .send()
            .await
            .map_err(|error| {
                updated::http::redacted_reqwest_error("fetching assigned inputs", &error)
                    .to_string()
            })?;
        let bytes = updated::http::read_bounded(
            response,
            "assigned input snapshot",
            MAX_DATAFLOW_BODY_BYTES,
        )
        .await
        .map_err(|error| error.to_string())?;
        decode_snapshot(&capability, inputs, &bytes)
    }
}

fn decode_snapshot(
    capability: &DownloadCapability,
    inputs: &InputSelection,
    bytes: &[u8],
) -> Result<FileSnapshot, String> {
    authenticate_input_capability(capability, inputs)?;
    updated::http::authenticate_download_bytes(capability, bytes, "assigned input object")
        .map_err(|error| error.to_string())?;
    InputPublication::from_bounded_body(bytes, inputs).map(|publication| publication.snapshot)
}

fn authenticate_input_capability(
    capability: &DownloadCapability,
    inputs: &InputSelection,
) -> Result<(), String> {
    (capability.sha256 == inputs.object_sha256)
        .then_some(())
        .ok_or_else(|| {
            "input capability does not match the object committed by the signed assignment".into()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routing(base_url: &str) -> Routing {
        Routing {
            root: "/var/lib/updated/routing".into(),
            base_url: base_url.into(),
            assignment: "assignments/agents/node.json".into(),
            transport_timeout: std::time::Duration::from_secs(30),
            mtls: updated::tls::Identity::new("client.pem", "client.key", "ca.pem"),
        }
    }

    #[test]
    fn local_repositories_refuse_inputs_they_cannot_fetch() {
        let input = InputSelection {
            generation: "a".repeat(64),
            object_sha256: "b".repeat(64),
            files: ["host".to_string()].into_iter().collect(),
        };
        assert!(RuntimeDataManager::new(&routing("/srv/repository/"), &input).is_err());
        assert!(
            RuntimeDataManager::new(&routing("/srv/repository/"), &InputSelection::default())
                .is_ok()
        );
    }

    #[test]
    fn object_store_cannot_substitute_assigned_input_bytes() {
        let snapshot = FileSnapshot {
            files: [(
                "password".into(),
                updated_contracts::dataflow::FileValue::from_bytes(b"real").unwrap(),
            )]
            .into_iter()
            .collect(),
        };
        let publication = InputPublication::from_snapshot(snapshot.clone(), &[7u8; 32]).unwrap();
        let inputs = publication.selection().unwrap();
        let bytes = publication.to_bounded_body().unwrap();
        let capability = DownloadCapability {
            schema: DownloadCapability::SCHEMA,
            url: "https://objects.example/input?X-Amz-Signature=secret".into(),
            sha256: inputs.object_sha256.clone(),
        };
        assert_eq!(
            decode_snapshot(&capability, &inputs, &bytes).unwrap(),
            snapshot
        );

        let substituted = InputPublication::from_snapshot(
            FileSnapshot {
                files: [(
                    "password".into(),
                    updated_contracts::dataflow::FileValue::from_bytes(b"attacker").unwrap(),
                )]
                .into_iter()
                .collect(),
            },
            &[7u8; 32],
        )
        .unwrap()
        .to_bounded_body()
        .unwrap();
        assert!(decode_snapshot(&capability, &inputs, &substituted).is_err());

        let substituted_capability = DownloadCapability {
            sha256: updated_contracts::digest::sha256_bytes(&substituted),
            ..capability
        };
        assert!(
            decode_snapshot(&substituted_capability, &inputs, &substituted).is_err(),
            "even a capability matching attacker bytes cannot override the TUF-signed commitment"
        );
    }

    #[tokio::test]
    async fn an_unchanged_signed_selection_uses_the_last_authenticated_snapshot() {
        let snapshot = FileSnapshot {
            files: [(
                "password".into(),
                updated_contracts::dataflow::FileValue::from_bytes(b"already authenticated")
                    .unwrap(),
            )]
            .into_iter()
            .collect(),
        };
        let selection = InputPublication::from_snapshot(snapshot.clone(), &[7u8; 32])
            .unwrap()
            .selection()
            .unwrap();
        let mut manager =
            RuntimeDataManager::new(&routing("/srv/repository/"), &InputSelection::default())
                .unwrap();
        manager.current = snapshot.clone();
        manager.current_selection = selection.clone();

        manager
            .reconcile(&"a".repeat(64), &selection)
            .await
            .expect("no capability endpoint is needed for unchanged authenticated bytes");
        assert_eq!(manager.inputs(), &snapshot);
    }
}
