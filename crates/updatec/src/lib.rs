//! Environment-neutral desired-state compiler for `updated`, hosted on Kubernetes.
//!
//! Custom `UpdatedNode` resources represent agents anywhere. Group selectors determine
//! which exact config bundle each minimal agent document references.

use std::collections::{BTreeMap, BTreeSet};

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use updated::config::{
    RepositoryAssignment as DesiredDeployment, TargetReference as ExactTarget,
};

pub mod gateway;
pub mod publisher;
pub mod runtime;

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "updated.dev",
    version = "v1alpha1",
    kind = "UpdatedGroup",
    plural = "updatedgroups",
    namespaced,
    shortname = "ug"
)]
pub struct UpdatedGroupSpec {
    /// All labels must match. Empty selectors are forbidden because the repository owns
    /// the explicit default group.
    pub match_labels: BTreeMap<String, String>,
    /// ConfigMap in the same namespace. Its `deployment.json` entry is the exact
    /// desired-deployment document defined by the node contract.
    pub deployment_config_map: String,
}

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "updated.dev",
    version = "v1alpha1",
    kind = "UpdatedNode",
    plural = "updatednodes",
    namespaced,
    shortname = "un"
)]
pub struct UpdatedNodeSpec {
    /// Control-plane labels for this agent. The represented agent may run anywhere and
    /// does not need to be a Kubernetes Node, Pod, or workload.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "updated.dev",
    version = "v1alpha1",
    kind = "UpdatedRepository",
    plural = "updatedrepositories",
    namespaced,
    shortname = "ur"
)]
pub struct UpdatedRepositorySpec {
    pub default_group: String,
    /// Secret in the same namespace containing root, targets, snapshot, and timestamp
    /// private keys. The controller never stores private keys in CRD status.
    pub signing_secret: String,
    pub s3: S3Destination,
    /// Prefix below the TUF targets namespace at which assignments are published.
    #[serde(default = "default_assignment_prefix")]
    pub assignment_prefix: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct S3Destination {
    pub bucket: String,
    #[serde(default)]
    pub prefix: String,
    pub region: String,
    /// Optional Secret containing standard AWS_ACCESS_KEY_ID and
    /// AWS_SECRET_ACCESS_KEY entries. When absent, workload identity is used.
    pub credentials_secret: Option<String>,
    pub endpoint: Option<String>,
}

fn default_assignment_prefix() -> String {
    "assignments".into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationTarget {
    pub path: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationPlan {
    /// Config documents contain desired deployments; agent documents contain exact config
    /// target references.
    pub targets: Vec<PublicationTarget>,
    pub node_groups: BTreeMap<String, String>,
    pub digest: String,
}

/// An `UpdatedGroup` after its ConfigMap has been fetched and strictly decoded.
#[derive(Clone, Debug)]
pub struct ResolvedGroup {
    pub name: String,
    pub match_labels: BTreeMap<String, String>,
    pub deployment: DesiredDeployment,
}

#[derive(Clone, Debug)]
pub struct ResolvedNode {
    pub name: String,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PlanError {
    MissingDefault(String),
    EmptySelector(String),
    DuplicateGroup(String),
    DuplicateNode(String),
    AmbiguousNode { node: String, groups: Vec<String> },
    InvalidNodeName,
    InvalidPrefix,
    InvalidDeployment(String),
    Serialize(String),
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PlanError {}

/// Compile a deterministic, all-or-nothing TUF target batch.
pub fn build_publication_plan(
    repository: &UpdatedRepositorySpec,
    groups: impl IntoIterator<Item = ResolvedGroup>,
    nodes: impl IntoIterator<Item = ResolvedNode>,
) -> Result<PublicationPlan, PlanError> {
    let prefix = repository.assignment_prefix.trim_matches('/');
    if prefix.is_empty()
        || prefix
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || prefix.contains(['\\', ':'])
        || prefix.chars().any(char::is_control)
    {
        return Err(PlanError::InvalidPrefix);
    }

    let mut indexed = BTreeMap::new();
    for group in groups {
        let name = group.name.clone();
        if group.match_labels.is_empty() {
            return Err(PlanError::EmptySelector(name));
        }
        if indexed.insert(name.clone(), group).is_some() {
            return Err(PlanError::DuplicateGroup(name));
        }
    }
    let default = indexed
        .get(&repository.default_group)
        .ok_or_else(|| PlanError::MissingDefault(repository.default_group.clone()))?;

    let mut group_bytes = BTreeMap::new();
    for (name, group) in &indexed {
        let bytes = canonical_json(&group.deployment)?;
        group_bytes.insert(name.clone(), bytes);
    }

    let mut node_groups = BTreeMap::new();
    for node in nodes {
        let name = node.name;
        if name.is_empty()
            || name.contains(['/', '\\', ':'])
            || name.chars().any(char::is_control)
            || node_groups.contains_key(&name)
        {
            return if node_groups.contains_key(&name) {
                Err(PlanError::DuplicateNode(name))
            } else {
                Err(PlanError::InvalidNodeName)
            };
        }
        let matches: Vec<_> = indexed
            .iter()
            .filter(|(group_name, group)| {
                group_name.as_str() != repository.default_group
                    && selector_matches(&group.match_labels, &node.labels)
            })
            .map(|(name, _)| name.clone())
            .collect();
        let selected = match matches.as_slice() {
            [] => repository.default_group.clone(),
            [only] => only.clone(),
            _ => {
                return Err(PlanError::AmbiguousNode {
                    node: name,
                    groups: matches,
                })
            }
        };
        node_groups.insert(name, selected);
    }

    let mut targets = Vec::new();
    let mut group_references = BTreeMap::new();
    for (name, bytes) in &group_bytes {
        let group = target(format!("{prefix}/configs/{name}.json"), bytes.clone());
        group_references.insert(
            name.clone(),
            ExactTarget {
                path: group.path.clone(),
                sha256: group.sha256.clone(),
            },
        );
        targets.push(group);
    }
    for (node, group) in &node_groups {
        let assignment = updated::config::AgentDocument {
            schema: 1,
            config: group_references[group].clone(),
        };
        let bytes = serde_json::to_vec(&assignment)
            .map_err(|error| PlanError::Serialize(error.to_string()))?;
        targets.push(target(format!("{prefix}/agents/{node}.json"), bytes));
    }
    targets.sort_by(|a, b| a.path.cmp(&b.path));
    let digest = publication_digest(&targets);
    let _ = default;
    Ok(PublicationPlan {
        targets,
        node_groups,
        digest,
    })
}

fn selector_matches(
    expected: &BTreeMap<String, String>,
    labels: &BTreeMap<String, String>,
) -> bool {
    expected
        .iter()
        .all(|(key, value)| labels.get(key) == Some(value))
}

fn canonical_json(value: &DesiredDeployment) -> Result<Vec<u8>, PlanError> {
    value.validate().map_err(PlanError::InvalidDeployment)?;
    serde_json::to_vec(value).map_err(|error| PlanError::Serialize(error.to_string()))
}

fn target(path: String, bytes: Vec<u8>) -> PublicationTarget {
    let sha256 = hex_digest(&bytes);
    PublicationTarget {
        path,
        bytes,
        sha256,
    }
}

fn publication_digest(targets: &[PublicationTarget]) -> String {
    let mut digest = Sha256::new();
    for target in targets {
        digest.update(target.path.as_bytes());
        digest.update([0]);
        digest.update(&target.bytes);
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn desired_group_names(groups: &[ResolvedGroup]) -> BTreeSet<String> {
    groups.iter().map(|group| group.name.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deployment(id: &str) -> DesiredDeployment {
        DesiredDeployment {
            schema: 2,
            deployment: id.into(),
            metadata_url: "https://cdn.example/tuf/metadata/".into(),
            targets_url: "https://cdn.example/tuf/targets/".into(),
            application: ExactTarget {
                path: "app".into(),
                sha256: "1".repeat(64),
            },
            provider_set: ExactTarget {
                path: "providers".into(),
                sha256: "2".repeat(64),
            },
        }
    }

    fn group(name: &str, labels: &[(&str, &str)]) -> ResolvedGroup {
        ResolvedGroup {
            name: name.into(),
            match_labels: labels
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            deployment: deployment(name),
        }
    }

    fn node(name: &str, labels: &[(&str, &str)]) -> ResolvedNode {
        ResolvedNode {
            name: name.into(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
        }
    }

    fn repository() -> UpdatedRepositorySpec {
        UpdatedRepositorySpec {
            default_group: "default".into(),
            signing_secret: "tuf-signing-keys".into(),
            s3: S3Destination {
                bucket: "updates".into(),
                prefix: String::new(),
                region: "us-east-1".into(),
                credentials_secret: None,
                endpoint: None,
            },
            assignment_prefix: "assignments".into(),
        }
    }

    #[test]
    fn agent_documents_point_to_the_exact_selected_config_bundle() {
        let plan = build_publication_plan(
            &repository(),
            [
                group("default", &[("updated.dev/default", "true")]),
                group("edge", &[("role", "edge")]),
            ],
            [node("a", &[("role", "edge")]), node("b", &[])],
        )
        .unwrap();
        assert_eq!(plan.node_groups["a"], "edge");
        assert_eq!(plan.node_groups["b"], "default");
        let config = plan
            .targets
            .iter()
            .find(|t| t.path == "assignments/configs/edge.json")
            .unwrap();
        let node = plan
            .targets
            .iter()
            .find(|t| t.path == "assignments/agents/a.json")
            .unwrap();
        let assignment: updated::config::AgentDocument =
            serde_json::from_slice(&node.bytes).unwrap();
        assert_eq!(assignment.config.path, config.path);
        assert_eq!(assignment.config.sha256, config.sha256);
        assert_ne!(node.bytes, config.bytes);
    }

    #[test]
    fn overlapping_non_default_groups_fail_closed() {
        let error = build_publication_plan(
            &repository(),
            [
                group("default", &[("updated.dev/default", "true")]),
                group("a", &[("role", "edge")]),
                group("b", &[("role", "edge")]),
            ],
            [node("node", &[("role", "edge")])],
        )
        .unwrap_err();
        assert_eq!(
            error,
            PlanError::AmbiguousNode {
                node: "node".into(),
                groups: vec!["a".into(), "b".into()]
            }
        );
    }

    #[test]
    fn output_is_deterministic_across_input_order() {
        let first = build_publication_plan(
            &repository(),
            [
                group("default", &[("default", "yes")]),
                group("edge", &[("role", "edge")]),
            ],
            [node("b", &[]), node("a", &[("role", "edge")])],
        )
        .unwrap();
        let second = build_publication_plan(
            &repository(),
            [
                group("edge", &[("role", "edge")]),
                group("default", &[("default", "yes")]),
            ],
            [node("a", &[("role", "edge")]), node("b", &[])],
        )
        .unwrap();
        assert_eq!(first, second);
    }
}
