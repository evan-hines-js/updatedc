use k8s_openapi::api::core::v1::Pod;
use kube::api::{Patch, PatchParams};
use kube::{Api, Client};
use updatec::{UpdateAgent, UpdateGroup, UpdateGroupSet, UpdateRepository};

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReleaseRequest {
    pub(crate) application: String,
    pub(crate) version: String,
    pub(crate) artifact: String,
    pub(crate) lifecycle: String,
}

impl ReleaseRequest {
    pub(crate) fn green() -> Self {
        Self {
            application: "color-demo".into(),
            version: "2.0.0".into(),
            artifact: "green".into(),
            lifecycle: "enterprise-java".into(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct KubernetesPublisher {
    pub(crate) namespace: String,
    pub(crate) repository: String,
    pub(crate) patch: serde_json::Value,
    pub(crate) client: Client,
}

impl KubernetesPublisher {
    /// Typed handles onto the demo's namespace, so the rest of the crate stops repeating
    /// `Api::namespaced(self.publisher.client.clone(), &self.publisher.namespace)` at every call
    /// site — the resource type is chosen by which of these it calls.
    pub(crate) fn pods(&self) -> Api<Pod> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    pub(crate) fn agents(&self) -> Api<UpdateAgent> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    pub(crate) fn groups(&self) -> Api<UpdateGroup> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    pub(crate) fn sets(&self) -> Api<UpdateGroupSet> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    pub(crate) fn repositories(&self) -> Api<UpdateRepository> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }
}

/// Driven port: the application knows how to publish a release request, but not
/// whether the adapter is Kubernetes, a test double, or another control plane.
#[async_trait::async_trait]
pub(crate) trait ReleasePublisher {
    async fn publish(&self, release: &ReleaseRequest) -> Result<(), Box<dyn std::error::Error>>;
}

#[async_trait::async_trait]
impl ReleasePublisher for KubernetesPublisher {
    async fn publish(&self, _release: &ReleaseRequest) -> Result<(), Box<dyn std::error::Error>> {
        self.repositories()
            .patch(
                &self.repository,
                &PatchParams::default(),
                &Patch::Merge(&self.patch),
            )
            .await?;
        Ok(())
    }
}


