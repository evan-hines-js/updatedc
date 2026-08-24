//! Controller-owned publication of private, assignment-bound input data.
//!
//! A reconciler's only configuration representation is a bounded set of named files. The
//! controller resolves producer dependencies, wraps them with stable keyed blinding, and writes one
//! immutable private S3 object keyed by the assignment digest before publishing the assignment's
//! exact-byte commitment.

use std::collections::BTreeMap;

use crate::dataflow::RepositoryDataflow;
use crate::PublicationPlan;
use updated_contracts::assignment::RepositoryAssignment;
use updated_contracts::dataflow::{FileSnapshot, InputPublication};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InputDataError {
    Invalid(String),
    Storage(String),
}

impl std::fmt::Display for InputDataError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(error) => write!(formatter, "assigned input data is invalid: {error}"),
            Self::Storage(error) => write!(formatter, "publishing assigned input data: {error}"),
        }
    }
}

impl std::error::Error for InputDataError {}

/// Materialize every distinct assignment before the TUF generation that references it is
/// published. A carried predecessor may no longer be derivable from current producer reports; its
/// immutable existing object is then the durable source.
pub(crate) async fn publish(
    dataflow: &RepositoryDataflow,
    plan: &PublicationPlan,
    assignment_prefix: &str,
    input_snapshots: &BTreeMap<String, FileSnapshot>,
    dataflow_key: &[u8],
) -> Result<(), InputDataError> {
    for (digest, assignment) in assignments(plan, assignment_prefix)? {
        if assignment.runtime.inputs.is_empty() {
            continue;
        }
        let publication =
            if let Some(snapshot) = input_snapshots.get(&assignment.runtime.inputs.generation) {
                InputPublication::from_snapshot(snapshot.clone(), dataflow_key)
                    .map_err(InputDataError::Invalid)?
            } else {
                dataflow
                    .inputs(&digest, &assignment.runtime.inputs)
                    .await
                    .map_err(|error| InputDataError::Storage(error.to_string()))?
            };
        publication
            .snapshot
            .validate_selection(&assignment.runtime.inputs)
            .map_err(InputDataError::Invalid)?;
        if publication.selection().map_err(InputDataError::Invalid)? != assignment.runtime.inputs {
            return Err(InputDataError::Invalid(
                "private input publication does not match its signed selection".into(),
            ));
        }
        dataflow
            .put_inputs(&digest, &publication, &assignment.runtime.inputs)
            .await
            .map_err(|error| InputDataError::Storage(error.to_string()))?;
    }
    Ok(())
}

fn assignments(
    plan: &PublicationPlan,
    assignment_prefix: &str,
) -> Result<BTreeMap<String, RepositoryAssignment>, InputDataError> {
    let mut assignments = BTreeMap::new();
    for digest in plan.node_assignments.values() {
        if assignments.contains_key(digest) {
            continue;
        }
        let path = updated_contracts::telemetry::config_object_key(assignment_prefix, digest);
        let target = plan
            .targets
            .iter()
            .find(|target| target.path == path && target.sha256 == *digest)
            .ok_or_else(|| {
                InputDataError::Invalid(format!(
                    "publication plan has no exact configuration target for {digest}"
                ))
            })?;
        let assignment = RepositoryAssignment::from_bounded_json(&target.bytes)
            .map_err(InputDataError::Invalid)?;
        assignments.insert(digest.clone(), assignment);
    }
    Ok(assignments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn snapshot() -> FileSnapshot {
        FileSnapshot {
            files: BTreeMap::from([(
                "database-password".into(),
                updated_contracts::dataflow::FileValue::from_bytes(b"correct horse battery staple")
                    .unwrap(),
            )]),
        }
    }

    fn assignment(snapshot: &FileSnapshot) -> RepositoryAssignment {
        let inputs = InputPublication::from_snapshot(snapshot.clone(), &[7u8; 32])
            .unwrap()
            .selection()
            .unwrap();
        RepositoryAssignment {
            schema: RepositoryAssignment::SCHEMA,
            deployment: "consumer".into(),
            metadata_url: "https://releases.example/metadata/".into(),
            targets_url: "https://releases.example/targets/".into(),
            application: updated_contracts::artifact::TargetReference {
                path: "application".into(),
                sha256: "a".repeat(64),
            },
            ordered_install_fallback: false,
            provider_set: updated_contracts::artifact::TargetReference {
                path: "provider".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({"signed": {}, "signatures": []}),
            runtime: updated_contracts::assignment::ManagedRuntime {
                inputs,
                ..crate::tests::managed_runtime()
            },
        }
    }

    fn plan(assignment: &RepositoryAssignment) -> (PublicationPlan, String) {
        let bytes = serde_json::to_vec(assignment).unwrap();
        let digest = updated_contracts::digest::sha256_bytes(&bytes);
        (
            PublicationPlan {
                targets: vec![crate::PublicationTarget {
                    path: updated_contracts::telemetry::config_object_key("assignments", &digest),
                    bytes,
                    sha256: digest.clone(),
                }],
                node_groups: BTreeMap::from([("node-0".into(), "consumer".into())]),
                node_assignments: BTreeMap::from([("node-0".into(), digest.clone())]),
                digest: "plan".into(),
            },
            digest,
        )
    }

    #[tokio::test]
    async fn snapshots_exist_and_match_before_an_assignment_can_publish() {
        let store: Arc<dyn object_store::ObjectStore> =
            Arc::new(object_store::memory::InMemory::new());
        let dataflow = RepositoryDataflow::new(store, "repository");
        let snapshot = snapshot();
        let assignment = assignment(&snapshot);
        let generation = assignment.runtime.inputs.generation.clone();
        let (plan, digest) = plan(&assignment);

        publish(
            &dataflow,
            &plan,
            "assignments",
            &BTreeMap::from([(generation, snapshot.clone())]),
            &[7u8; 32],
        )
        .await
        .unwrap();
        assert_eq!(
            dataflow
                .inputs(&digest, &assignment.runtime.inputs)
                .await
                .unwrap()
                .snapshot,
            snapshot
        );
    }

    #[tokio::test]
    async fn a_carried_assignment_uses_only_its_immutable_existing_snapshot() {
        let store: Arc<dyn object_store::ObjectStore> =
            Arc::new(object_store::memory::InMemory::new());
        let dataflow = RepositoryDataflow::new(store, "repository");
        let snapshot = snapshot();
        let assignment = assignment(&snapshot);
        let (plan, digest) = plan(&assignment);
        let publication = InputPublication::from_snapshot(snapshot.clone(), &[7u8; 32]).unwrap();
        dataflow
            .put_inputs(&digest, &publication, &assignment.runtime.inputs)
            .await
            .unwrap();

        publish(
            &dataflow,
            &plan,
            "assignments",
            &BTreeMap::new(),
            &[7u8; 32],
        )
        .await
        .unwrap();
        assert_eq!(
            dataflow
                .inputs(&digest, &assignment.runtime.inputs)
                .await
                .unwrap()
                .snapshot,
            snapshot
        );
    }

    #[tokio::test]
    async fn a_missing_carried_snapshot_fails_closed() {
        let store: Arc<dyn object_store::ObjectStore> =
            Arc::new(object_store::memory::InMemory::new());
        let dataflow = RepositoryDataflow::new(store, "repository");
        let (plan, _) = plan(&assignment(&snapshot()));
        assert!(matches!(
            publish(
                &dataflow,
                &plan,
                "assignments",
                &BTreeMap::new(),
                &[7u8; 32]
            )
            .await,
            Err(InputDataError::Storage(_))
        ));
    }
}
