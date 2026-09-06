//! Resolve a route through the signed release graph. No implicit head selection or history walk.
use std::collections::BTreeMap;

use updated_contracts::artifact::TargetReference;

use crate::{DefaultPolicy, TrustedRepository, VerifiedTarget};

pub fn target_sha(target: &VerifiedTarget) -> String {
    hex::encode(&target.sha256)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stance<'a> {
    Nothing,
    Installed {
        version: &'a str,
        sha256: &'a str,
    },
    /// Repair reconstructs already-committed bytes; it never selects a different graph node.
    Reacquire {
        version: &'a str,
        sha256: &'a str,
    },
}

impl<'a> Stance<'a> {
    fn installed_version(self) -> Option<&'a str> {
        match self {
            Self::Nothing => None,
            Self::Installed { version, .. } | Self::Reacquire { version, .. } => Some(version),
        }
    }
}

pub struct SelectedRelease {
    pub target: VerifiedTarget,
    pub version: String,
    pub sha256: String,
}

impl TrustedRepository {
    /// One pinned package verifier for fleet preflight, installation, upgrades, and exact repair.
    pub fn verify_release(
        &self,
        policy: &DefaultPolicy,
        version: &str,
        package: &TargetReference,
    ) -> Result<SelectedRelease, crate::Error> {
        let target = self.exact_target(package)?;
        let signed_version = policy
            .candidate_version(&target)
            .map_err(|error| crate::Error::Trust(error.to_string()))?;
        if signed_version.to_string() != version {
            return Err(crate::Error::Trust(format!(
                "release {version} disagrees with its signed package version {signed_version}"
            )));
        }
        Ok(SelectedRelease {
            sha256: target_sha(&target),
            target,
            version: version.into(),
        })
    }

    /// Resolve the complete route before acquisition or mutation. Every selected package is pinned
    /// by the assignment and authenticated by TUF and the shared product/channel/platform policy.
    pub fn assigned_application(
        &self,
        policy: &DefaultPolicy,
        stance: Stance<'_>,
        mut rejected: impl FnMut(&VerifiedTarget, &str) -> bool,
    ) -> Result<Vec<SelectedRelease>, crate::Error> {
        if let Stance::Reacquire { version, sha256 } = stance {
            let mut targets = self.all_targets();
            targets.sort_by(|a, b| a.path.cmp(&b.path));
            for target in targets {
                if target_sha(&target) != sha256 {
                    continue;
                }
                let package = TargetReference {
                    path: target.path,
                    sha256: sha256.into(),
                };
                if let Ok(candidate) = self.verify_release(policy, version, &package) {
                    if !rejected(&candidate.target, version) {
                        return Ok(vec![candidate]);
                    }
                }
            }
            return Ok(vec![]);
        }
        let graph = &self
            .assignment_context()
            .ok_or_else(|| {
                crate::Error::Trust("release repository has no desired deployment".into())
            })?
            .document()
            .application;
        graph.validate().map_err(crate::Error::Trust)?;
        if let Stance::Installed { version, sha256 } = stance {
            graph
                .check_source(version, sha256)
                .map_err(crate::Error::Trust)?;
        }

        let mut candidates = BTreeMap::new();
        let mut failures = Vec::new();
        for (version, release) in &graph.releases {
            let candidate = (|| {
                let candidate = self.verify_release(policy, version, &release.package)?;
                if rejected(&candidate.target, version) {
                    return Err(crate::Error::Trust(format!(
                        "release {version} was rejected"
                    )));
                }
                Ok(candidate)
            })();
            match candidate {
                Ok(candidate) => {
                    candidates.insert(version.as_str(), candidate);
                }
                Err(error) => {
                    failures.push(format!("{version}: {error}"));
                }
            }
        }
        if stance.installed_version() == Some(graph.target.as_str())
            && !candidates.contains_key(graph.target.as_str())
        {
            return Err(crate::Error::Trust(format!(
                "current target package is unavailable: {}",
                failures.join("; ")
            )));
        }
        let route = graph
            .route(stance.installed_version(), |version, _| {
                candidates.contains_key(version)
            })
            .map_err(|error| crate::Error::Trust(format!("{error}; {}", failures.join("; "))))?;
        Ok(route
            .into_iter()
            .map(|version| {
                candidates
                    .remove(version)
                    .expect("planner only returns authenticated available releases")
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo;
    use updated_contracts::{
        artifact::TargetReference,
        releases::{Release, ReleaseGraph},
    };

    async fn fixture() -> (tempfile::TempDir, TrustedRepository) {
        let tmp = tempfile::tempdir().unwrap();
        let directory = tmp.path().join("repo");
        let keys = repo::generate_keys(&tmp.path().join("keys")).await.unwrap();
        repo::init(&directory, &keys, 365).await.unwrap();
        let mut published = vec![];
        for v in [1, 2, 3, 4, 6] {
            let source = tmp.path().join(format!("payload-{v}"));
            std::fs::write(&source, format!("payload-{v}")).unwrap();
            published.push(repo::PublishTarget::application(
                "app",
                "stable",
                &format!("{v}.0.0"),
                std::env::consts::OS,
                std::env::consts::ARCH,
                "app",
                source,
            ));
        }
        repo::add_release(&directory, &keys, published, 365)
            .await
            .unwrap();
        let source = crate::testing::offline_source(&directory);
        let repository = TrustedRepository::load(&source, &tmp.path().join("initial"))
            .await
            .unwrap();
        let graph = ReleaseGraph {
            target: "6.0.0".into(),
            releases: [
                (1, vec![], true),
                (2, vec![], true),
                (3, vec![1], false),
                (4, vec![2], false),
                (6, vec![3], false),
            ]
            .into_iter()
            .map(|(v, from, installable)| {
                let version = format!("{v}.0.0");
                let path = format!(
                    "products/app/stable/{version}/{}-{}/app",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                );
                let target = repository.target(&path).unwrap();
                (
                    version,
                    Release {
                        package: TargetReference {
                            path,
                            sha256: target_sha(&target),
                        },
                        installable,
                        rollback_from: Default::default(),
                        upgrade_from: from.into_iter().map(|v| format!("{v}.0.0")).collect(),
                    },
                )
            })
            .collect(),
        };
        let assignment = updated_contracts::assignment::RepositoryAssignment {
            application: graph,
            metadata_url: source.metadata_url,
            targets_url: source.targets_url,
            release_root: serde_json::from_slice(&std::fs::read(source.root).unwrap()).unwrap(),
            ..crate::fixture::assignment("route")
        };
        let mut repository = TrustedRepository::load_release_repository(
            &assignment,
            &tmp.path().join("verified"),
            None,
        )
        .await
        .unwrap();
        repository.assignment = Some(crate::AssignmentContext {
            sha256: assignment.publication().unwrap().1,
            repository_lineage: updated::state::RepositoryLineage::from_metadata_url(
                &assignment.metadata_url,
            )
            .unwrap(),
            document: assignment,
        });
        (tmp, repository)
    }

    fn versions(
        repository: &TrustedRepository,
        stance: Stance<'_>,
    ) -> Result<Vec<String>, crate::Error> {
        repository
            .assigned_application(&DefaultPolicy::current("app", "stable"), stance, |_, _| {
                false
            })
            .map(|route| route.into_iter().map(|release| release.version).collect())
    }

    #[tokio::test]
    async fn authenticated_graph_chooses_a_complete_installation_and_refuses_stranded_nodes() {
        let (_tmp, repository) = fixture().await;
        assert_eq!(
            versions(&repository, Stance::Nothing).unwrap(),
            ["1.0.0", "3.0.0", "6.0.0"]
        );
        let graph = &repository
            .assignment_context()
            .unwrap()
            .document()
            .application;
        assert_eq!(
            versions(
                &repository,
                Stance::Installed {
                    version: "1.0.0",
                    sha256: &graph.releases["1.0.0"].package.sha256
                }
            )
            .unwrap(),
            ["3.0.0", "6.0.0"]
        );
        let error = versions(
            &repository,
            Stance::Installed {
                version: "2.0.0",
                sha256: &graph.releases["2.0.0"].package.sha256,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("2.0.0") && error.contains("6.0.0"),
            "{error}"
        );
        assert!(versions(
            &repository,
            Stance::Installed {
                version: "1.0.0",
                sha256: &"a".repeat(64)
            }
        )
        .is_err());
    }

    #[tokio::test]
    async fn missing_metadata_wrong_version_and_rejected_hops_cannot_start_an_install() {
        let (_tmp, mut repository) = fixture().await;
        let policy = DefaultPolicy::current("app", "stable");
        assert!(repository
            .assigned_application(&policy, Stance::Nothing, |_, version| version == "3.0.0")
            .is_err());
        let release = &mut repository
            .assignment
            .as_mut()
            .unwrap()
            .document
            .application
            .releases
            .get_mut("3.0.0")
            .unwrap()
            .package;
        release.path = "absent".into();
        assert!(versions(&repository, Stance::Nothing).is_err());
        let two = repository
            .assignment
            .as_ref()
            .unwrap()
            .document
            .application
            .releases["2.0.0"]
            .package
            .clone();
        let graph = &mut repository.assignment.as_mut().unwrap().document.application;
        graph.releases.remove("2.0.0");
        graph
            .releases
            .get_mut("4.0.0")
            .unwrap()
            .upgrade_from
            .clear();
        graph.releases.get_mut("3.0.0").unwrap().package = two;
        assert!(versions(&repository, Stance::Nothing)
            .unwrap_err()
            .to_string()
            .contains("signed package version"));
    }

    #[tokio::test]
    async fn repair_reacquires_only_the_committed_bytes() {
        let (_tmp, repository) = fixture().await;
        let hash = &repository
            .assignment_context()
            .unwrap()
            .document()
            .application
            .releases["2.0.0"]
            .package
            .sha256;
        assert_eq!(
            versions(
                &repository,
                Stance::Reacquire {
                    version: "2.0.0",
                    sha256: hash
                }
            )
            .unwrap(),
            ["2.0.0"]
        );
        assert!(versions(
            &repository,
            Stance::Reacquire {
                version: "2.0.0",
                sha256: &"a".repeat(64)
            }
        )
        .unwrap()
        .is_empty());
    }

    #[tokio::test]
    async fn availability_checks_read_no_bundle_and_full_download_still_checks_bytes() {
        let (tmp, repository) = fixture().await;
        let target = repository.all_targets().into_iter().next().unwrap();
        repository.check_target_available(&target).await.unwrap();
        // Find the repository's hash-prefixed object without duplicating TUF filename rules.
        fn replace(path: &std::path::Path) {
            for entry in std::fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    replace(&entry.path());
                } else {
                    std::fs::write(entry.path(), b"corrupt").unwrap();
                }
            }
        }
        replace(&tmp.path().join("repo/targets"));
        repository.check_target_available(&target).await.unwrap();
        assert!(repository
            .download_target(&target, &tmp.path().join("download"))
            .await
            .is_err());
        std::fs::remove_dir_all(tmp.path().join("repo/targets")).unwrap();
        assert!(repository.check_target_available(&target).await.is_err());
    }
}
