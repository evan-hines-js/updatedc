//! The one place a CustomResourceDefinition for this control plane is produced.
//!
//! Two rules meet here and disagree, and the disagreement has to be resolved once rather than at
//! each generator.
//!
//! A contract type carries `serde(deny_unknown_fields)` because a *signed* document must be closed:
//! an unrecognized field is a document this build does not understand, and accepting it silently is
//! how a node acts on a meaning it was never taught. `schemars` faithfully renders that as
//! `additionalProperties: false` — and the Kubernetes API server refuses exactly that beside
//! `properties` in a structural schema. A custom resource gets its closedness from structural
//! pruning, which the server converges regardless, so the pair is not merely illegal but redundant.
//!
//! Stripping it at generation time is therefore correct, and doing it *here* is what makes it
//! reliable: the chart's `crdgen` and the test that enforces structural-ness now read from one
//! function, so the YAML an operator converges is the YAML that was checked.

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::CustomResourceExt;

use crate::{
    UpdateAdmissionPolicy, UpdateAgent, UpdateBackend, UpdateGroup, UpdateGroupSet,
    UpdateRepository, UpdateSubscription,
};

/// Every CRD this control plane owns, in the order the chart writes them, structural by
/// construction.
pub fn all() -> Vec<CustomResourceDefinition> {
    vec![
        structural::<UpdateAdmissionPolicy>(),
        structural::<UpdateBackend>(),
        structural::<UpdateGroup>(),
        structural::<UpdateGroupSet>(),
        structural::<UpdateAgent>(),
        structural::<UpdateRepository>(),
        structural::<UpdateSubscription>(),
    ]
}

/// One derived CRD, with every illegal `additionalProperties`/`properties` pair removed.
fn structural<T: CustomResourceExt>() -> CustomResourceDefinition {
    let mut value = serde_json::to_value(T::crd()).expect("a derived CRD serializes");
    make_structural(&mut value);
    if value["metadata"]["name"] == "updaterepositories.updated.dev" {
        make_repository_storage_coordinates_write_once(&mut value);
    }
    serde_json::from_value(value).expect("a CRD survives its own round trip")
}

/// The repository-state finalizer deletes the controller-derived namespace/name prefix from the
/// bucket and endpoint bound into status, so those operator-selected coordinates cannot move after
/// creation. It also owns the fixed-name admitted-state projection and local TUF epoch.
/// The credential Secret reference is also fixed because another identity may resolve the same
/// bucket name in another cloud account. Secret CONTENTS and the public-routing endpoint remain
/// mutable, so credentials can rotate without changing the bound identity selector.
fn make_repository_storage_coordinates_write_once(value: &mut serde_json::Value) {
    let s3 = value
        .pointer_mut("/spec/versions/0/schema/openAPIV3Schema/properties/spec/properties/s3")
        .and_then(serde_json::Value::as_object_mut)
        .expect("UpdateRepository has an s3 object schema");
    s3.insert(
        "x-kubernetes-validations".into(),
        serde_json::json!([{
            "rule": "self.bucket == oldSelf.bucket && self.region == oldSelf.region && has(self.endpoint) == has(oldSelf.endpoint) && (!has(self.endpoint) || self.endpoint == oldSelf.endpoint) && has(self.credentialsSecretRef) == has(oldSelf.credentialsSecretRef) && (!has(self.credentialsSecretRef) || self.credentialsSecretRef.name == oldSelf.credentialsSecretRef.name)",
            "message": "spec.s3 bucket, region, endpoint, and credentialsSecretRef are immutable because the deletion finalizer owns that storage destination"
        }]),
    );
}

/// Remove `additionalProperties` wherever it sits beside `properties`.
///
/// Only that exact pair: `additionalProperties` alone is how an open map (`BTreeMap<String, String>`
/// for labels, say) states its value type, and it is perfectly legal there.
fn make_structural(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            if object.contains_key("properties") {
                object.remove("additionalProperties");
            }
            for child in object.values_mut() {
                make_structural(child);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(make_structural),
        _ => {}
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// The API server's own rule, enforced against what this module actually emits — so the mistake
    /// fails `cargo test` instead of the first `kubectl apply`.
    #[test]
    fn every_generated_crd_is_structural() {
        fn assert_structural(value: &serde_json::Value, path: &str) {
            match value {
                serde_json::Value::Object(object) => {
                    assert!(
                        !(object.contains_key("properties")
                            && object.contains_key("additionalProperties")),
                        "{path}: additionalProperties beside properties is refused by the API server"
                    );
                    for (key, child) in object {
                        assert_structural(child, &format!("{path}.{key}"));
                    }
                }
                serde_json::Value::Array(items) => {
                    for (index, child) in items.iter().enumerate() {
                        assert_structural(child, &format!("{path}[{index}]"));
                    }
                }
                _ => {}
            }
        }

        let crds = all();
        assert_eq!(crds.len(), 7, "every custom resource is generated here");
        for crd in &crds {
            let name = crd.metadata.name.clone().unwrap_or_default();
            let value = serde_json::to_value(crd).expect("a CRD serializes");
            assert_structural(&value, &name);
        }
    }

    /// The stripping is targeted, not indiscriminate: an open map still declares its value type.
    ///
    /// Without this, a rule that deleted every `additionalProperties` would still pass the
    /// structural check above while quietly turning `matchLabels` into an untyped object.
    #[test]
    fn an_open_map_keeps_its_value_type() {
        let group_set = all()
            .into_iter()
            .find(|crd| crd.metadata.name.as_deref() == Some("updategroupsets.updated.dev"))
            .expect("the group-set CRD is generated");
        let value = serde_json::to_value(&group_set).expect("a CRD serializes");
        let labels = value["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]
            ["spec"]["properties"]["selector"]["properties"]["matchLabels"]
            .clone();
        assert_eq!(
            labels["additionalProperties"]["type"], "string",
            "matchLabels must keep its declared value type: {labels}"
        );
        assert!(
            labels.get("properties").is_none(),
            "an open map has no fixed properties, so nothing was stripped here"
        );
    }

    #[test]
    fn repository_storage_coordinates_are_write_once() {
        let repository = all()
            .into_iter()
            .find(|crd| crd.metadata.name.as_deref() == Some("updaterepositories.updated.dev"))
            .expect("the repository CRD is generated");
        let value = serde_json::to_value(repository).expect("a CRD serializes");
        let rules = value
            .pointer(
                "/spec/versions/0/schema/openAPIV3Schema/properties/spec/properties/s3/x-kubernetes-validations",
            )
            .and_then(serde_json::Value::as_array)
            .expect("the storage schema carries CEL validations");
        let expressions = rules
            .iter()
            .filter_map(|rule| rule["rule"].as_str())
            .collect::<Vec<_>>()
            .join("\n");
        for field in ["bucket", "region", "endpoint", "credentialsSecretRef"] {
            assert!(
                expressions.contains(field),
                "{field} is not protected: {expressions}"
            );
        }
        for removed in ["prefix", "storageIdentity"] {
            assert!(
                value
                    .pointer(&format!(
                        "/spec/versions/0/schema/openAPIV3Schema/properties/spec/properties/s3/properties/{removed}"
                    ))
                    .is_none(),
                "managed repository storage must not expose operator-selected {removed}"
            );
        }
        let s3 = "/spec/versions/0/schema/openAPIV3Schema/properties/spec/properties/s3/properties";
        for field in ["bucket", "region", "endpoint", "publicEndpoint"] {
            assert_eq!(
                value.pointer(&format!("{s3}/{field}/minLength")),
                Some(&serde_json::json!(1)),
                "spec.s3.{field} must reject the empty string"
            );
        }
        assert_eq!(
            value.pointer(&format!(
                "{s3}/credentialsSecretRef/properties/name/minLength"
            )),
            Some(&serde_json::json!(1)),
            "credentialsSecretRef.name must reject the empty string"
        );
    }
}
