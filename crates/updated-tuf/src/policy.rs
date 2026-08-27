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
        // Every field above matched, so this target claims to be a runnable release for this
        // installation. Require it to live at the canonical layout AND for every identity segment
        // to agree with the signed metadata:
        //
        //     products/<product>/<channel>/<version>/<os>-<arch>/<file>
        //
        // (the one layout `repo::PublishTarget::application` publishes). Path and custom metadata
        // are both TUF-authentic, but if they can disagree the target is ambiguous: two authentic
        // targets could claim the same `custom.version` at different paths, leaving the tie-break
        // to decorative path bytes — exactly the ordering the selector treats as authoritative.
        // Checking only *some* segments, or only when the path happens to begin with `products`,
        // leaves that ambiguity open; requiring the whole layout closes it.
        let segments: Vec<&str> = candidate.path.split('/').collect();
        let expected = [
            ("products", "products"),
            (self.product.as_str(), "product"),
            (self.channel.as_str(), "channel"),
            (version, "version"),
            (&format!("{}-{}", self.os, self.arch), "os-arch"),
        ];
        if segments.len() != expected.len() + 1 {
            return Err(PolicyError(format!(
                "runnable target path `{}` is not the canonical \
                 products/<product>/<channel>/<version>/<os>-<arch>/<file> layout",
                candidate.path
            )));
        }
        for (index, (want, what)) in expected.iter().enumerate() {
            let got = segments[index];
            if got != *want {
                return Err(PolicyError(format!(
                    "path {what} segment `{got}` disagrees with signed `{want}` in `{}`",
                    candidate.path
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
    updated_contracts::identity::parse_release_version(v)
        .ok_or_else(|| PolicyError(format!("invalid or oversized version `{v}`")))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const OS: &str = std::env::consts::OS;
    const ARCH: &str = std::env::consts::ARCH;

    fn target(path: &str, custom_version: &str) -> VerifiedTarget {
        VerifiedTarget {
            path: path.to_string(),
            length: 1,
            sha256: vec![1u8; 32],
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

    #[test]
    fn every_identity_segment_of_the_canonical_layout_must_agree() {
        // A candidate whose signed metadata fully matches this installation must ALSO sit at the
        // canonical path with every identity segment agreeing. Otherwise two authentic targets
        // could claim one version at different paths and the selector's ordering would break the
        // tie on decorative bytes.
        for path in [
            // Not the canonical layout at all — the escape hatch that used to skip the check.
            "elsewhere/app-2.0.0".to_string(),
            format!("mirror/products/app/stable/2.0.0/{OS}-{ARCH}/app"),
            // Canonical shape, but an identity segment disagrees with the signed metadata.
            format!("products/other/stable/2.0.0/{OS}-{ARCH}/app"),
            format!("products/app/beta/2.0.0/{OS}-{ARCH}/app"),
            format!("products/app/stable/2.0.0/{OS}-someotherarch/app"),
            // Right prefix, wrong depth.
            format!("products/app/stable/2.0.0/{OS}-{ARCH}/nested/app"),
            "products/app/stable/2.0.0".to_string(),
        ] {
            assert!(
                policy().candidate_version(&target(&path, "2.0.0")).is_err(),
                "{path} must be rejected as ambiguous"
            );
        }
    }
}
