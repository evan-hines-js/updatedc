//! The node reconciler protocol vocabulary.
//!
//! Every release carries one signed node reconciler, invoked as ordinary argv.
//! The protocol has exactly four operations and three reserved
//! attempt identities, and this module is their single definition: the supervisor that
//! *invokes* a reconciler, and every reconciler implementation in this workspace that
//! *answers* one, name them from here. A second spelling of `healthcheck` — a reconciler
//! that answers `verify` while the supervisor asks for `healthcheck` — is exactly the
//! silent drift this module exists to make impossible.

use std::fmt;
use std::str::FromStr;

/// The four public reconciler operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Idempotently converge machine state to the candidate.
    Apply,
    /// Make one bounded readiness observation. This — and only this — is the readiness gate:
    /// exit zero means healthy.
    Healthcheck,
    /// Idempotently restore or compensate toward the predecessor.
    Rollback,
    /// Make one bounded steady-state observation for fingerprinting.
    Inspect,
}

impl Operation {
    /// The wire spelling passed as the reconciler's first argument.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Healthcheck => "healthcheck",
            Self::Rollback => "rollback",
            Self::Inspect => "inspect",
        }
    }
}

/// An argv operation that is not one of the four.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownOperation(pub String);

impl fmt::Display for UnknownOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown reconciler operation {:?}", self.0)
    }
}

impl std::error::Error for UnknownOperation {}

impl FromStr for Operation {
    type Err = UnknownOperation;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "apply" => Ok(Self::Apply),
            "healthcheck" => Ok(Self::Healthcheck),
            "rollback" => Ok(Self::Rollback),
            "inspect" => Ok(Self::Inspect),
            other => Err(UnknownOperation(other.to_string())),
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The reserved `--attempt-id` values. A deployment carries the transaction's own token, so
/// a reconciler can tell a transaction step from an observation made outside one; these three
/// name the observations that belong to no transaction.
pub mod attempt {
    /// A boot or restart: the per-boot converge and the boot readiness gate.
    pub const BOOT: &str = "boot";
    /// The supervisor's steady-state readiness/liveness observation.
    pub const PERIODIC: &str = "periodic";
    /// The steady-state fingerprint observation.
    pub const FINGERPRINT: &str = "fingerprint";

    /// Whether `id` is one of the reserved observation identities rather than a deployment
    /// transaction token.
    pub fn is_reserved(id: &str) -> bool {
        matches!(id, BOOT | PERIODIC | FINGERPRINT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire spellings are the published protocol: changing one silently breaks every
    /// reconciler in the field.
    #[test]
    fn the_four_operations_round_trip_their_published_spellings() {
        for (operation, spelling) in [
            (Operation::Apply, "apply"),
            (Operation::Healthcheck, "healthcheck"),
            (Operation::Rollback, "rollback"),
            (Operation::Inspect, "inspect"),
        ] {
            assert_eq!(operation.as_str(), spelling);
            assert_eq!(spelling.parse::<Operation>().unwrap(), operation);
        }
    }

    #[test]
    fn a_retired_spelling_is_rejected_rather_than_silently_ignored() {
        for retired in ["verify", "periodic", "pre-start", "finalize", "drain"] {
            assert!(retired.parse::<Operation>().is_err());
        }
    }

    #[test]
    fn only_the_three_observation_identities_are_reserved() {
        assert!(attempt::is_reserved(attempt::BOOT));
        assert!(attempt::is_reserved(attempt::PERIODIC));
        assert!(attempt::is_reserved(attempt::FINGERPRINT));
        assert!(!attempt::is_reserved("a1b2c3"));
    }
}
