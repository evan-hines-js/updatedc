use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;

use updated::config::Routing;
use updated_contracts::assignment::SecretReference;

use crate::guardian::ReadySignalled;
use updated_contracts::telemetry::REPORT_CADENCE_JITTER_PERCENT;

const MAX_BUNDLE_BYTES: usize = 1024 * 1024;
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Base of the retry schedule for [`SecretManager::acquire`], grown by
/// [`crate::schedule::network_backoff`] and jittered like every other supervisor network retry, so
/// a control-plane outage does not bring the whole fleet back on the same boundary.
const RETRY_BASE: std::time::Duration = std::time::Duration::from_secs(1);

/// Where the digest of the launched bundle lives, beside the rest of the supervisor's state.
fn launched_path(state: &std::path::Path) -> std::path::PathBuf {
    state.join("secrets-launched")
}

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
    /// Build the client for `routing`. Deliberately synchronous, because this runs during argument
    /// parsing — before the supervisor has even connected to the guardian, which holds a candidate
    /// supervisor to a readiness deadline from the moment it launches it. A fetch here would make
    /// an unreachable control plane look like a candidate that cannot start, and a candidate that
    /// misses that deadline is rejected by content hash *permanently*. Acquiring the bundle is
    /// [`Self::acquire`], which the supervisor runs behind its readiness signal.
    pub(crate) fn new(routing: &Routing, references: &[SecretReference]) -> Result<Self, String> {
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
        // A local routing repository has no control-plane endpoint to fetch from, so declared
        // secrets can never be resolved on this node. That is a configuration error, not an
        // outage: retrying it would spin forever instead of telling the operator.
        if endpoint.is_none() && !references.is_empty() {
            return Err(
                "this deployment declares secrets, but a local routing repository has no \
                 control-plane endpoint to fetch them from"
                    .into(),
            );
        }
        Ok(Self {
            endpoint,
            client,
            current: SecretBundle::default(),
        })
    }

    /// Hold this boot until the assigned bundle is in hand, retrying rather than failing. The
    /// application launches with these values in its environment and must never start without
    /// them, so giving up would mean launching an application that cannot work; and returning an
    /// error would leave an already-installed, already-verified application down until a human
    /// noticed. So the honest behaviour is to keep asking — which is affordable only because
    /// [`ReadySignalled`] proves the guardian has already been told this supervisor started, so the
    /// wait is attributed to the control plane rather than to this supervisor's bytes.
    ///
    /// Returns false when a stop was requested instead: an unbounded wait must stay abandonable, or
    /// a SIGTERM arriving during a control-plane outage is answered by nothing at all until the
    /// guardian's stop grace expires and kills the tree.
    pub(crate) async fn acquire(
        &mut self,
        deployment: &str,
        references: &[SecretReference],
        shutdown: &AtomicBool,
        _ready: ReadySignalled,
    ) -> bool {
        let mut failures: u32 = 0;
        while let Err(error) = self.reconcile(deployment, references).await {
            let backoff = crate::schedule::jitter(
                crate::schedule::network_backoff(RETRY_BASE, failures),
                REPORT_CADENCE_JITTER_PERCENT,
            );
            failures = failures.saturating_add(1);
            crate::warn(&format!(
                "fetching the assigned secrets failed ({error}); retrying in {}s",
                backoff.as_secs()
            ));
            if crate::app::sleep_interruptible(backoff, shutdown).await {
                return false;
            }
        }
        true
    }

    /// The digest of the values currently held, as recorded beside the installed state when the
    /// application is launched with them.
    fn digest(&self) -> String {
        let mut hasher = updated::hash::Sha256Hasher::new();
        for (name, value) in &self.current.values {
            hasher.update(name.as_bytes());
            hasher.update(b"\0");
            hasher.update(value.as_bytes());
            hasher.update(b"\0");
        }
        hasher.finish_hex()
    }

    /// Record the values the application was just launched with. A later supervisor that adopts
    /// that still-running process compares against this: the process's environment was fixed at its
    /// launch, so a rotation that landed while this supervisor was down is otherwise invisible —
    /// [`Self::reconcile`] would compare the rotated bundle against itself and report no change,
    /// and the application would run on revoked credentials indefinitely.
    pub(crate) fn record_launched(&self, state: &std::path::Path) {
        let path = launched_path(state);
        if let Err(error) = foundation::durable::atomic_write_managed(
            &path,
            "secrets-launched",
            self.digest().as_bytes(),
        ) {
            crate::warn(&format!(
                "recording the launched secret generation failed ({error}); the next adoption \
                 relaunches the application to be sure it holds current values"
            ));
        }
    }

    /// Whether a process launched under the recorded digest still holds these values. An
    /// unreadable record answers false: relaunching is the safe direction.
    pub(crate) fn launched_with_current(&self, state: &std::path::Path) -> bool {
        std::fs::read_to_string(launched_path(state))
            .is_ok_and(|recorded| recorded == self.digest())
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
        with_fetch_timeout(FETCH_TIMEOUT, self.fetch_unbounded(deployment, references)).await
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

    fn routing(base_url: &str) -> Routing {
        Routing {
            root: "/var/lib/updated/routing".into(),
            base_url: base_url.into(),
            assignment: "assignments/agents/agent.json".into(),
            transport_timeout: std::time::Duration::from_secs(30),
            mtls: updated::tls::Identity::new("client.pem", "client.key", "ca.pem"),
        }
    }

    #[test]
    fn a_manager_is_built_without_reaching_the_control_plane() {
        // Construction is synchronous precisely so it CANNOT fetch. It used to, retrying forever,
        // in front of the guardian's readiness handshake — so an unreachable /v1/node/secrets held
        // a candidate supervisor past its ready deadline and got its bytes permanently rejected,
        // blaming an outage on a binary that was fine.
        let manager = SecretManager::new(&routing("/srv/local-repository"), &[]).unwrap();
        assert!(manager.values().is_empty());
        // A declared secret with no control-plane endpoint to fetch it from is a configuration
        // error, and the one thing construction still refuses.
        assert!(
            SecretManager::new(&routing("/srv/local-repository"), &[reference("TOKEN")]).is_err()
        );
    }

    #[test]
    fn the_fetch_backoff_grows_to_a_cap_and_never_gives_up() {
        let waits: Vec<u64> = (0..9)
            .map(|failures| crate::schedule::network_backoff(RETRY_BASE, failures).as_secs())
            .collect();
        assert_eq!(waits, vec![1, 2, 4, 8, 16, 32, 64, 64, 64]);
    }

    /// A manager aimed at an endpoint nothing is listening on: every fetch fails, immediately, for
    /// as long as the test needs it to — a control-plane outage the retry loop cannot ride out.
    fn unreachable_endpoint() -> SecretManager {
        updated::tls::install_crypto_provider();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let port = listener.local_addr().expect("bound").port();
        drop(listener);
        SecretManager {
            endpoint: Some(format!("http://127.0.0.1:{port}/v1/node/secrets")),
            client: Some(reqwest::Client::new()),
            current: SecretBundle::default(),
        }
    }

    #[tokio::test]
    async fn a_stop_during_a_secrets_outage_ends_the_wait() {
        // The loop retries forever by design, so it is the one wait in the boot path that can
        // outlive a stop request. Ignoring the flag meant a SIGTERM during an outage was answered
        // only by the guardian's grace-expiry kill_tree, minutes later — while every other wait in
        // `run` returns on it.
        let shutdown = std::sync::Arc::new(AtomicBool::new(false));
        tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let acquired = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            unreachable_endpoint().acquire(
                "deployment",
                &[reference("TOKEN")],
                &shutdown,
                ReadySignalled::for_test(),
            ),
        )
        .await
        .expect("the wait ends on shutdown instead of retrying forever");
        assert!(!acquired, "no bundle was acquired; the stop won");
    }

    /// Stand in for a control plane that is down and then comes back: the first connection is
    /// dropped mid-request, the second is answered with `bundle`.
    fn flaky_endpoint(bundle: &'static str) -> (SecretManager, std::thread::JoinHandle<()>) {
        updated::tls::install_crypto_provider();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let port = listener.local_addr().expect("bound").port();
        let server = std::thread::spawn(move || {
            let (down, _) = listener.accept().expect("the attempt during the outage");
            drop(down);
            let (mut back, _) = listener.accept().expect("the retry");
            let mut request = [0u8; 1024];
            let _ = std::io::Read::read(&mut back, &mut request);
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{bundle}",
                bundle.len()
            );
            std::io::Write::write_all(&mut back, response.as_bytes()).expect("one response");
        });
        (
            SecretManager {
                endpoint: Some(format!("http://127.0.0.1:{port}/v1/node/secrets")),
                client: Some(reqwest::Client::new()),
                current: SecretBundle::default(),
            },
            server,
        )
    }

    #[tokio::test]
    async fn the_wait_retries_until_the_control_plane_answers() {
        // The other half of the loop: a failed fetch is neither fatal nor final — the boot waits
        // the outage out and launches with the bundle it eventually gets, never without it.
        let shutdown = AtomicBool::new(false);
        let (mut manager, server) = flaky_endpoint(
            r#"{"deployment":"deployment","generation":"one","values":{"TOKEN":"value"}}"#,
        );
        assert!(
            manager
                .acquire(
                    "deployment",
                    &[reference("TOKEN")],
                    &shutdown,
                    ReadySignalled::for_test(),
                )
                .await
        );
        assert_eq!(
            manager.values().get("TOKEN").map(String::as_str),
            Some("value")
        );
        server.join().expect("the stand-in control plane");
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
