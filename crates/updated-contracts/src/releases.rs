//! One release graph, shared verbatim by Kubernetes and signed assignments.
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::artifact::TargetReference;

pub const MAX_RELEASES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Release {
    pub package: TargetReference,
    /// Exact predecessor versions accepted by this release. No ranges or inferred edges.
    #[serde(default)]
    pub upgrade_from: BTreeSet<String>,
    /// Exact higher versions this release can restore from. Upgrade edges never imply rollback.
    #[serde(default)]
    pub rollback_from: BTreeSet<String>,
    /// This release can establish a new installation. Absence must still be checked by its code.
    #[serde(default)]
    pub installable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseGraph {
    pub target: String,
    pub releases: BTreeMap<String, Release>,
}

#[derive(Clone, Copy)]
enum Direction {
    Upgrade,
    Rollback,
}

impl Direction {
    fn predecessors(self, release: &Release) -> &BTreeSet<String> {
        match self {
            Self::Upgrade => &release.upgrade_from,
            Self::Rollback => &release.rollback_from,
        }
    }

    fn permits(self, from: &semver::Version, to: &semver::Version) -> bool {
        match self {
            Self::Upgrade => from.cmp_precedence(to).is_lt(),
            Self::Rollback => from.cmp_precedence(to).is_gt(),
        }
    }
}

impl ReleaseGraph {
    pub fn validate(&self) -> Result<(), String> {
        if self.releases.is_empty() || self.releases.len() > MAX_RELEASES {
            return Err(format!(
                "application must declare 1..={MAX_RELEASES} releases"
            ));
        }
        self.target_reference()?;
        let mut packages = BTreeSet::new();
        for (version, release) in &self.releases {
            let parsed = crate::identity::parse_release_version(version)
                .filter(|parsed| parsed.to_string() == *version)
                .ok_or_else(|| format!("invalid exact release version {version:?}"))?;
            if !release.package.is_valid() || !packages.insert(&release.package.sha256) {
                return Err(format!(
                    "release {version} has an invalid or duplicate package identity"
                ));
            }
            for (direction, from) in [Direction::Upgrade, Direction::Rollback]
                .into_iter()
                .flat_map(|direction| {
                    direction
                        .predecessors(release)
                        .iter()
                        .map(move |from| (direction, from))
                })
            {
                let source = crate::identity::parse_release_version(from)
                    .filter(|_| self.releases.contains_key(from))
                    .ok_or_else(|| {
                        format!("release {version} names an undeclared predecessor {from}")
                    })?;
                if !direction.permits(&source, &parsed) {
                    return Err(format!(
                        "edge {from} -> {version} must advance for upgradeFrom or descend for rollbackFrom"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Bind a claimed starting version to its immutable package before using any upgrade edge.
    pub fn check_source(&self, version: &str, sha256: &str) -> Result<(), String> {
        let source = self.releases.get(version).ok_or_else(|| {
            format!(
                "no supported route from installed {version} to {}: source is not declared",
                self.target
            )
        })?;
        if !crate::digest::digests_match(&source.package.sha256, sha256) {
            return Err(format!(
                "no supported route from installed {version} to {}: source package bytes differ",
                self.target
            ));
        }
        Ok(())
    }

    pub fn target_reference(&self) -> Result<&TargetReference, String> {
        self.releases
            .get(&self.target)
            .map(|release| &release.package)
            .ok_or_else(|| format!("target release {} is not declared", self.target))
    }

    /// Every executable version on a complete route from this source. Fleet admission checks
    /// this set so an agent choosing an alternative route cannot bypass package policy. The
    /// installed source is an identity anchor, not an executable hop. Dead ends are excluded.
    pub fn route_versions(&self, installed: Option<&str>) -> Result<BTreeSet<&str>, String> {
        self.route(installed, |_, _| true)?;
        let direction = self.direction(installed);
        if installed == Some(self.target.as_str()) {
            return Ok(BTreeSet::new());
        }
        let mut reaches_target = BTreeSet::from([self.target.as_str()]);
        let mut queue = VecDeque::from([self.target.as_str()]);
        while let Some(version) = queue.pop_front() {
            for predecessor in direction.predecessors(&self.releases[version]) {
                if reaches_target.insert(predecessor.as_str()) {
                    queue.push_back(predecessor.as_str());
                }
            }
        }
        let starts: Vec<&str> = match installed {
            Some(version) => vec![self
                .releases
                .get_key_value(version)
                .expect("validated source")
                .0
                .as_str()],
            None => self
                .releases
                .iter()
                .filter_map(|(version, release)| release.installable.then_some(version.as_str()))
                .collect(),
        };
        let mut reachable: BTreeSet<&str> = starts.iter().copied().collect();
        let mut queue: VecDeque<&str> = starts.into();
        while let Some(version) = queue.pop_front() {
            for (next, release) in &self.releases {
                if direction.predecessors(release).contains(version)
                    && reachable.insert(next.as_str())
                {
                    queue.push_back(next);
                }
            }
        }
        Ok(reachable
            .intersection(&reaches_target)
            .copied()
            .filter(|version| Some(*version) != installed)
            .collect())
    }

    /// The shortest permitted route, excluding an installed starting release. Sorted neighbors
    /// make equal-length routes deterministic, independent of YAML declaration order.
    /// `available` excludes rejected or unavailable packages before a route is chosen.
    pub fn route<'a>(
        &'a self,
        installed: Option<&str>,
        mut available: impl FnMut(&str, &Release) -> bool,
    ) -> Result<Vec<&'a str>, String> {
        self.validate()?;
        if let Some(version) = installed {
            if !self.releases.contains_key(version) {
                return Err(format!(
                    "installed version {version} has no declared upgrade path"
                ));
            }
            if version == self.target {
                return Ok(vec![]);
            }
        }
        let direction = self.direction(installed);
        let allowed: BTreeSet<&str> = self
            .releases
            .iter()
            .filter(|(version, release)| available(version, release))
            .map(|(version, _)| version.as_str())
            .collect();
        let mut parents: BTreeMap<&str, Option<&str>> = BTreeMap::new();
        let mut queue = VecDeque::new();
        if let Some(version) = installed {
            let start = self
                .releases
                .get_key_value(version)
                .expect("validated start")
                .0
                .as_str();
            parents.insert(start, None);
            queue.push_back(start);
        } else {
            for (version, release) in &self.releases {
                if release.installable && allowed.contains(version.as_str()) {
                    parents.insert(version, None);
                    queue.push_back(version.as_str());
                }
            }
        }
        while let Some(version) = queue.pop_front() {
            if version == self.target {
                let mut route = vec![];
                let mut at = Some(version);
                while let Some(current) = at {
                    if Some(current) != installed {
                        route.push(current);
                    }
                    at = parents[current];
                }
                route.reverse();
                return Ok(route);
            }
            for (next, release) in &self.releases {
                if allowed.contains(next.as_str())
                    && !parents.contains_key(next.as_str())
                    && direction.predecessors(release).contains(version)
                {
                    parents.insert(next, Some(version));
                    queue.push_back(next);
                }
            }
        }
        Err(format!(
            "no supported route from {} to {}",
            installed.unwrap_or("a fresh installation"),
            self.target
        ))
    }

    /// Called only after validation has established canonical versions and source membership.
    fn direction(&self, installed: Option<&str>) -> Direction {
        match installed {
            Some(version)
                if Direction::Rollback.permits(
                    &crate::identity::parse_release_version(version).expect("validated source"),
                    &crate::identity::parse_release_version(&self.target)
                        .expect("validated target"),
                ) =>
            {
                Direction::Rollback
            }
            _ => Direction::Upgrade,
        }
    }
}

/// Shared fixtures for tests and the development-only repository server.
pub mod testing {
    use super::*;

    pub fn install(version: &str, package: TargetReference) -> ReleaseGraph {
        ReleaseGraph {
            target: version.into(),
            releases: BTreeMap::from([(
                version.into(),
                Release {
                    package,
                    installable: true,
                    rollback_from: Default::default(),
                    upgrade_from: BTreeSet::new(),
                },
            )]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph() -> ReleaseGraph {
        ReleaseGraph {
            target: "11.0.0".into(),
            releases: [
                (1, vec![], true),
                (5, vec![1], false),
                (8, vec![5], false),
                (11, vec![8], false),
            ]
            .into_iter()
            .map(|(v, from, installable)| {
                (
                    format!("{v}.0.0"),
                    Release {
                        package: TargetReference {
                            path: format!("releases/{v}"),
                            sha256: format!("{v:064x}"),
                        },
                        rollback_from: Default::default(),
                        upgrade_from: from.into_iter().map(|v| format!("{v}.0.0")).collect(),
                        installable,
                    },
                )
            })
            .collect(),
        }
    }

    #[test]
    fn disconnected_nodes_skip_only_explicitly_supported_versions() {
        let graph = graph();
        assert_eq!(
            graph.route(Some("1.0.0"), |_, _| true).unwrap(),
            ["5.0.0", "8.0.0", "11.0.0"]
        );
        assert_eq!(
            graph.route(Some("5.0.0"), |_, _| true).unwrap(),
            ["8.0.0", "11.0.0"]
        );
        assert!(graph.route(Some("11.0.0"), |_, _| true).unwrap().is_empty());
        assert!(graph.route(Some("2.0.0"), |_, _| true).is_err());
        assert!(graph.route(Some("1.0.0"), |v, _| v != "8.0.0").is_err());
    }

    #[test]
    fn installable_releases_are_roots_not_implicit_upgrade_edges() {
        let mut graph = graph();
        assert_eq!(
            graph.route(None, |_, _| true).unwrap(),
            ["1.0.0", "5.0.0", "8.0.0", "11.0.0"]
        );
        graph.releases.get_mut("8.0.0").unwrap().installable = true;
        assert_eq!(graph.route(None, |_, _| true).unwrap(), ["8.0.0", "11.0.0"]);
        assert_eq!(
            graph.route(Some("1.0.0"), |_, _| true).unwrap(),
            ["5.0.0", "8.0.0", "11.0.0"]
        );
        graph.releases.get_mut("11.0.0").unwrap().installable = true;
        assert_eq!(graph.route(None, |_, _| true).unwrap(), ["11.0.0"]);
        for release in graph.releases.values_mut() {
            release.installable = false;
        }
        assert!(graph.route(None, |_, _| true).is_err());
    }

    #[test]
    fn shortest_route_wins_and_ties_are_stable() {
        let mut graph = graph();
        graph
            .releases
            .get_mut("11.0.0")
            .unwrap()
            .upgrade_from
            .insert("5.0.0".into());
        graph
            .releases
            .get_mut("8.0.0")
            .unwrap()
            .upgrade_from
            .insert("1.0.0".into());
        assert_eq!(
            graph.route(Some("1.0.0"), |_, _| true).unwrap(),
            ["5.0.0", "11.0.0"]
        );
        assert_eq!(
            graph.route_versions(Some("1.0.0")).unwrap(),
            BTreeSet::from(["5.0.0", "8.0.0", "11.0.0"])
        );
        assert_eq!(
            graph.route(Some("1.0.0"), |v, _| v != "5.0.0").unwrap(),
            ["8.0.0", "11.0.0"]
        );
        graph
            .releases
            .get_mut("11.0.0")
            .unwrap()
            .upgrade_from
            .insert("1.0.0".into());
        assert_eq!(graph.route(Some("1.0.0"), |_, _| true).unwrap(), ["11.0.0"]);
    }

    #[test]
    fn an_installable_dead_end_never_wins_over_a_route_to_the_target() {
        let mut graph = ReleaseGraph {
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
                (
                    format!("{v}.0.0"),
                    Release {
                        package: TargetReference {
                            path: format!("releases/{v}"),
                            sha256: format!("{v:064x}"),
                        },
                        rollback_from: Default::default(),
                        upgrade_from: from.into_iter().map(|v| format!("{v}.0.0")).collect(),
                        installable,
                    },
                )
            })
            .collect(),
        };
        assert_eq!(
            graph.route(None, |_, _| true).unwrap(),
            ["1.0.0", "3.0.0", "6.0.0"]
        );
        assert_eq!(
            graph.route_versions(None).unwrap(),
            BTreeSet::from(["1.0.0", "3.0.0", "6.0.0"])
        );
        assert_eq!(
            graph.route_versions(Some("1.0.0")).unwrap(),
            BTreeSet::from(["3.0.0", "6.0.0"])
        );
        assert!(graph.route(Some("2.0.0"), |_, _| true).is_err());
        assert!(graph.route(None, |v, _| v != "3.0.0").is_err());
        graph
            .releases
            .get_mut("6.0.0")
            .unwrap()
            .upgrade_from
            .clear();
        assert!(graph.route(None, |_, _| true).is_err());
    }

    #[test]
    fn rollback_uses_only_explicit_return_edges_and_checks_the_complete_route() {
        let mut graph = graph();
        for (to, from) in [("1.0.0", "5.0.0"), ("5.0.0", "8.0.0"), ("8.0.0", "11.0.0")] {
            graph
                .releases
                .get_mut(to)
                .unwrap()
                .rollback_from
                .insert(from.into());
        }
        graph.target = "1.0.0".into();
        assert_eq!(
            graph.route(Some("11.0.0"), |_, _| true).unwrap(),
            ["8.0.0", "5.0.0", "1.0.0"]
        );
        assert_eq!(
            graph.route_versions(Some("11.0.0")).unwrap(),
            BTreeSet::from(["1.0.0", "5.0.0", "8.0.0"])
        );
        assert!(graph.route(Some("11.0.0"), |v, _| v != "5.0.0").is_err());
        graph.releases.get_mut("11.0.0").unwrap().installable = true;
        graph.releases.get_mut("1.0.0").unwrap().installable = false;
        assert!(
            graph.route(None, |_, _| true).is_err(),
            "installation cannot start above its target and roll back"
        );
        graph
            .releases
            .get_mut("5.0.0")
            .unwrap()
            .rollback_from
            .clear();
        assert!(
            graph.route(Some("11.0.0"), |_, _| true).is_err(),
            "an upgrade edge never grants its inverse"
        );
    }

    #[test]
    fn both_directions_use_semantic_precedence_not_build_metadata_order() {
        for rollback in [false, true] {
            let mut graph = testing::install(
                "1.0.0+first",
                crate::artifact::TargetReference {
                    path: "first".into(),
                    sha256: "1".repeat(64),
                },
            );
            let mut release = Release {
                package: crate::artifact::TargetReference {
                    path: "second".into(),
                    sha256: "2".repeat(64),
                },
                upgrade_from: BTreeSet::new(),
                rollback_from: BTreeSet::new(),
                installable: false,
            };
            if rollback {
                release.rollback_from.insert("1.0.0+first".into());
            } else {
                release.upgrade_from.insert("1.0.0+first".into());
            }
            graph.releases.insert("1.0.0+second".into(), release);
            assert!(graph.validate().is_err());
        }
    }

    #[test]
    fn malformed_graphs_fail_before_planning() {
        for from in ["12.0.0", "11.0.0"] {
            let mut graph = graph();
            graph
                .releases
                .get_mut("1.0.0")
                .unwrap()
                .upgrade_from
                .insert(from.into());
            assert!(graph
                .route(None, |_, _| panic!("validation must happen first"))
                .is_err());
        }
        let mut graph = graph();
        graph.releases.remove("8.0.0");
        assert!(graph.validate().is_err());
    }
}
