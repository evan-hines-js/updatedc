//! The Kubernetes [`LoadBalancer`] backend: program a selectorless Service's EndpointSlice
//! from health, and let kube-proxy do the forwarding. A node's report going unhealthy flips
//! its endpoint to not-ready, which drains it from the Service with no data-path hop of ours.
//!
//! This is the first backend; DNS and HAProxy are future implementations of the same
//! [`LoadBalancer`] trait, driven by the identical health→membership core.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointPort, EndpointSlice};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;

use crate::{LoadBalancer, Member};

/// Value we stamp as the EndpointSlice manager, and the field-manager for server-side apply.
pub const MANAGED_BY: &str = "updated-healthproxy";

/// The EndpointSlice backend for one Service. The Service must be selectorless (no pod
/// selector) so that we, not the Endpoints controller, own its membership.
pub struct EndpointSliceLb {
    api: Api<EndpointSlice>,
    service: String,
    port_name: String,
    port: u16,
}

impl EndpointSliceLb {
    pub fn new(
        client: Client,
        namespace: &str,
        service: String,
        port_name: String,
        port: u16,
    ) -> Self {
        Self {
            api: Api::namespaced(client, namespace),
            service,
            port_name,
            port,
        }
    }

    /// The single slice we manage for the Service. One slice suffices well past any fleet
    /// this fronts (EndpointSlices hold up to 1000 endpoints).
    fn slice_name(&self) -> String {
        format!("{}-updated", self.service)
    }
}

#[async_trait::async_trait]
impl LoadBalancer for EndpointSliceLb {
    async fn reconcile(&self, members: &[Member]) -> Result<(), String> {
        let name = self.slice_name();
        let members = resolve_addresses(members).await;
        let slice = build_slice(&self.service, &name, &self.port_name, self.port, &members);
        // A single slice is one address family; any member of another family was dropped from
        // it (fail closed). Surface that misconfiguration rather than silently under-routing.
        let kept = slice.endpoints.len();
        if kept < members.len() {
            eprintln!(
                "healthproxy: {} inventory mixes address families; slice typed {}, dropped {} member(s) of another family",
                self.service,
                slice.address_type,
                members.len() - kept
            );
        }
        match self.apply(&name, &slice).await {
            Ok(()) => Ok(()),
            // `addressType` is immutable, and `force()` resolves field-manager conflicts, not
            // validation: once the inventory's family flips (IPv4 → IPv6), every future apply is
            // rejected with a 422 that no retry can clear, and membership silently freezes at
            // whatever was last programmed. Replacing the slice is the only way through. It is
            // ours (we own the name and the field manager), so deleting it costs one reconcile
            // interval of the endpoints it held.
            Err(error) if is_immutable_rejection(&error) => {
                eprintln!(
                    "healthproxy: {} slice must change address type to {}; replacing it",
                    self.service, slice.address_type
                );
                if let Err(delete_error) = self.api.delete(&name, &Default::default()).await {
                    return Err(format!(
                        "replacing the {} slice for a new address type: {delete_error}",
                        self.service
                    ));
                }
                self.apply(&name, &slice)
                    .await
                    .map_err(|error| error.to_string())
            }
            Err(error) => Err(error.to_string()),
        }
    }
}

impl EndpointSliceLb {
    async fn apply(&self, name: &str, slice: &EndpointSlice) -> Result<(), kube::Error> {
        self.api
            .patch(
                name,
                &PatchParams::apply(MANAGED_BY).force(),
                &Patch::Apply(slice),
            )
            .await
            .map(|_| ())
    }
}

/// Whether the apiserver refused an apply because a field on the existing object cannot change.
/// Only 422 (Invalid) qualifies; a conflict, a permission error, or a transport failure must keep
/// retrying against the existing object rather than deleting it.
fn is_immutable_rejection(error: &kube::Error) -> bool {
    matches!(error, kube::Error::Api(response) if response.code == 422)
}

/// Replace every hostname member with a resolved IP literal, dropping any that does not resolve.
///
/// Kubernetes accepts an `FQDN` EndpointSlice but **kube-proxy does not implement that address
/// type**, so a hostname slice programs zero working endpoints while every apply succeeds and
/// every log line looks healthy — the worst failure shape there is. Members are documented as
/// bare hostnames for out-of-cluster VMs, so the names are resolved here, each cycle, and the
/// slice only ever carries addresses kube-proxy can actually route.
async fn resolve_addresses(members: &[Member]) -> Vec<Member> {
    let mut resolved = Vec::with_capacity(members.len());
    for member in members {
        if AddressType::of(&member.address) != AddressType::Fqdn {
            resolved.push(member.clone());
            continue;
        }
        // The port is irrelevant to the lookup; the Service owns it.
        match tokio::net::lookup_host((member.address.as_str(), 0)).await {
            Ok(mut addresses) => match addresses.next() {
                Some(address) => resolved.push(Member {
                    address: address.ip().to_string(),
                    ..member.clone()
                }),
                None => eprintln!(
                    "healthproxy: {} ({}) resolved to no address; leaving it out of rotation",
                    member.node, member.address
                ),
            },
            Err(error) => eprintln!(
                "healthproxy: resolving {} ({}) failed ({error}); leaving it out of rotation",
                member.node, member.address
            ),
        }
    }
    resolved
}

/// Build the desired EndpointSlice for a set of members. Pure, so the mapping from health to
/// endpoints (addresses, ready conditions, the service-name label kube-proxy keys on) is
/// tested without a cluster.
///
/// An EndpointSlice is single-address-typed, so a mixed inventory (IPv4 plus IPv6 members) cannot
/// go in one slice: it is partitioned to one family ([`slice_address_type`]) and any member of
/// another family is dropped, i.e. left out of rotation (fail closed). Such a mix is a
/// misconfiguration; the reconcile loop logs the drop.
///
/// Members reach here as IP literals — [`resolve_addresses`] has already turned any hostname into
/// one — because kube-proxy does not route `FQDN` slices.
pub fn build_slice(
    service: &str,
    slice_name: &str,
    port_name: &str,
    port: u16,
    members: &[Member],
) -> EndpointSlice {
    let address_type = slice_address_type(members);
    let endpoints = members
        .iter()
        .filter(|member| AddressType::of(&member.address) == address_type)
        .map(|member| Endpoint {
            addresses: vec![member.address.clone()],
            conditions: Some(EndpointConditions {
                // `ready` gates routing; `serving` mirrors it; nothing we manage is
                // "terminating" — a drained node is simply not ready.
                ready: Some(member.ready),
                serving: Some(member.ready),
                terminating: Some(false),
            }),
            ..Default::default()
        })
        .collect();
    let mut labels = BTreeMap::new();
    // The label kube-proxy/the EndpointSlice mirroring uses to attach this slice to its
    // Service, plus a manager marker so ownership is legible.
    labels.insert(
        "kubernetes.io/service-name".to_string(),
        service.to_string(),
    );
    labels.insert(
        "endpointslice.kubernetes.io/managed-by".to_string(),
        MANAGED_BY.to_string(),
    );
    EndpointSlice {
        metadata: ObjectMeta {
            name: Some(slice_name.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        address_type: address_type.label().to_string(),
        endpoints,
        ports: Some(vec![EndpointPort {
            name: Some(port_name.to_string()),
            port: Some(i32::from(port)),
            protocol: Some("TCP".to_string()),
            app_protocol: None,
        }]),
    }
}

/// The address family of one member address: a parseable IPv4 or IPv6 literal, else a hostname
/// (`FQDN`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum AddressType {
    Ipv4,
    Ipv6,
    Fqdn,
}

impl AddressType {
    fn of(address: &str) -> Self {
        if address.parse::<Ipv4Addr>().is_ok() {
            Self::Ipv4
        } else if address.parse::<Ipv6Addr>().is_ok() {
            Self::Ipv6
        } else {
            Self::Fqdn
        }
    }

    /// The Kubernetes `addressType` string for this family.
    fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Fqdn => "FQDN",
        }
    }
}

/// The one family the slice is typed as: the family the most members share, so a mixed inventory
/// keeps its largest partition and drops the rest rather than emitting a mismatched endpoint. Ties
/// break IPv4 → IPv6 for a deterministic slice. An empty inventory types as IPv4 (an empty slice,
/// draining everything — fail closed).
///
/// Only the two IP families are candidates: `resolve_addresses` has already turned every hostname
/// into a literal (kube-proxy does not route `FQDN` slices) or dropped it, so typing a slice FQDN
/// would produce a slice that is accepted and then silently routes nothing.
fn slice_address_type(members: &[Member]) -> AddressType {
    let ipv6 = members
        .iter()
        .filter(|member| AddressType::of(&member.address) == AddressType::Ipv6)
        .count();
    if ipv6 * 2 > members.len() {
        AddressType::Ipv6
    } else {
        AddressType::Ipv4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(node: &str, address: &str, ready: bool) -> Member {
        Member {
            node: node.to_string(),
            address: address.to_string(),
            ready,
        }
    }

    #[test]
    fn slice_reflects_member_readiness_and_attaches_to_its_service() {
        let members = vec![
            member("agent-0", "10.0.0.1", true),
            member("agent-1", "10.0.0.2", false),
        ];
        let slice = build_slice("vm-db", "vm-db-updated", "http", 5432, &members);

        assert_eq!(slice.address_type, "IPv4");
        let labels = slice.metadata.labels.unwrap();
        assert_eq!(labels.get("kubernetes.io/service-name").unwrap(), "vm-db");
        assert_eq!(
            labels
                .get("endpointslice.kubernetes.io/managed-by")
                .unwrap(),
            MANAGED_BY
        );

        assert_eq!(slice.endpoints.len(), 2);
        assert_eq!(slice.endpoints[0].addresses, vec!["10.0.0.1".to_string()]);
        assert_eq!(
            slice.endpoints[0].conditions.as_ref().unwrap().ready,
            Some(true)
        );
        assert_eq!(
            slice.endpoints[1].conditions.as_ref().unwrap().ready,
            Some(false)
        );

        let ports = slice.ports.unwrap();
        assert_eq!(ports[0].port, Some(5432));
        assert_eq!(ports[0].name.as_deref(), Some("http"));
    }

    #[test]
    fn a_hostname_never_reaches_a_slice_as_an_fqdn_endpoint() {
        // kube-proxy does not route `FQDN` slices, so an unresolvable hostname must leave the
        // member OUT of rotation rather than produce a slice that is accepted and routes nothing.
        let members = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(resolve_addresses(&[member(
                "db",
                "vm-db.invalid.example",
                true,
            )]));
        assert!(members.is_empty(), "an unresolvable member is dropped");

        let slice = build_slice("s", "s-updated", "http", 80, &members);
        assert_eq!(slice.address_type, "IPv4");
        assert!(slice.endpoints.is_empty());
    }
}
