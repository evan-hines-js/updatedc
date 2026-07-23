//! Product policy applied *after* TUF authentication and *before* any target
//! bytes are installed. TUF proves a target is authentic; policy decides whether
//! this installation should accept it (right product/platform, upgrade-only).

use crate::VerifiedTarget;

/// A policy rejection. Distinct from a TUF trust failure: the target is authentic
/// but not one this installation should apply.
#[derive(Debug)]
pub struct PolicyError(String);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "policy rejected candidate: {}", self.0)
    }
}

impl std::error::Error for PolicyError {}

/// Requires the candidate's signed custom metadata to match the configured
/// product/channel/os/arch, and refuses versions below the installed one.
///
/// Deployed code builds this with [`DefaultPolicy::current`], which fills `os`/`arch`
/// from the running host — the only values a runnable target can carry. The fields
/// stay public so tests can pin a specific platform.
pub struct DefaultPolicy {
    pub product: String,
    pub channel: String,
    pub os: String,
    pub arch: String,
}

impl DefaultPolicy {
    /// A policy for the current host: `os`/`arch` come from the running target's
    /// consts. The one place platform identity enters release selection.
    pub fn current(product: impl Into<String>, channel: impl Into<String>) -> Self {
        DefaultPolicy {
            product: product.into(),
            channel: channel.into(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
        }
    }

    /// Parse and authorize the signed identity shared by discovery and final policy
    /// enforcement, so those paths cannot disagree about metadata fields.
    pub(crate) fn candidate_version(
        &self,
        candidate: &VerifiedTarget,
    ) -> Result<semver::Version, PolicyError> {
        let field = |k: &str| -> Result<&str, PolicyError> {
            candidate
                .custom
                .get(k)
                .and_then(|v| v.as_str())
                .ok_or_else(|| PolicyError(format!("candidate custom metadata missing `{k}`")))
        };
        for (k, want) in [
            ("product", self.product.as_str()),
            ("channel", self.channel.as_str()),
            ("os", self.os.as_str()),
            ("arch", self.arch.as_str()),
        ] {
            let got = field(k)?;
            if got != want {
                return Err(PolicyError(format!("{k} is `{got}`, expected `{want}`")));
            }
        }
        let version = field("version")?;
        // Cross-check the target path's version segment against the signed `custom.version`.
        // The canonical layout is `products/<product>/<channel>/<version>/<os>-<arch>/<file>`
        // (see `repo::PublishTarget::application`). Both segments are TUF-authentic, but if
        // they disagree the target is ambiguous: two authentic targets could then claim the
        // same `custom.version` while living at different paths, leaving the tie-break to
        // decorative path bytes. Requiring agreement makes `custom.version` the single
        // authority and rejects any candidate whose path says otherwise.
        let segments: Vec<&str> = candidate.path.split('/').collect();
        if segments.first().copied() == Some("products") {
            let path_version = segments.get(3).copied().ok_or_else(|| {
                PolicyError(format!(
                    "product target path `{}` omits its version segment",
                    candidate.path
                ))
            })?;
            if path_version != version {
                return Err(PolicyError(format!(
                    "path version segment `{path_version}` disagrees with signed version `{version}`"
                )));
            }
        }
        parse_semver(version)
    }

    /// Authorize an authenticated candidate for this installation, including
    /// identity/platform matching and upgrade-only version policy.
    pub fn authorize(
        &self,
        installed_version: Option<&str>,
        candidate: &VerifiedTarget,
    ) -> Result<(), PolicyError> {
        let candidate_sv = self.candidate_version(candidate)?;
        if let Some(installed_version) = installed_version {
            let installed_sv = parse_semver(installed_version)?;
            if candidate_sv < installed_sv {
                return Err(PolicyError(format!(
                    "refusing downgrade {installed_version} -> {candidate_sv}"
                )));
            }
        }
        Ok(())
    }
}

fn parse_semver(v: &str) -> Result<semver::Version, PolicyError> {
    semver::Version::parse(v).map_err(|e| PolicyError(format!("invalid version `{v}`: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const OS: &str = std::env::consts::OS;
    const ARCH: &str = std::env::consts::ARCH;

    fn target(path: &str, custom_version: &str) -> VerifiedTarget {
        let mut hashes = BTreeMap::new();
        hashes.insert("sha256".to_string(), vec![1u8; 32]);
        VerifiedTarget {
            path: path.to_string(),
            length: 1,
            hashes,
            custom: serde_json::json!({
                "product": "app",
                "channel": "stable",
                "version": custom_version,
                "os": OS,
                "arch": ARCH,
            }),
        }
    }

    fn policy() -> DefaultPolicy {
        DefaultPolicy::current("app", "stable")
    }

    #[test]
    fn path_version_segment_must_match_signed_version() {
        // The path's version segment agrees with `custom.version`: accepted.
        let good = target(
            &format!("products/app/stable/2.0.0/{OS}-{ARCH}/app"),
            "2.0.0",
        );
        assert_eq!(
            policy().candidate_version(&good).unwrap(),
            semver::Version::parse("2.0.0").unwrap()
        );

        // A target whose signed version claims 2.0.0 but whose path says 1.0.0 is ambiguous
        // and must be rejected, so decorative path bytes can never break a version tie.
        let mismatched = target(
            &format!("products/app/stable/1.0.0/{OS}-{ARCH}/app"),
            "2.0.0",
        );
        assert!(policy().candidate_version(&mismatched).is_err());
    }
}
