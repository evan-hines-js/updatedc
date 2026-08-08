use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client};
use updatec::{UpdateAgent, UpdateGroup, UpdateGroupSet};

#[derive(Clone)]
pub(crate) struct KubernetesPublisher {
    pub(crate) namespace: String,
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
}
