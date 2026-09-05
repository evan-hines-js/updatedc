//! Versioned, language-independent reconciler helper compatibility.
use serde::{Deserialize, Serialize};

pub const API: u32 = 1;
pub const MAX_COMMAND_SECONDS: u64 = 3600;
pub const MAX_SEQUENCE_STEPS: usize = 128;
/// Literal process arguments and deadlines share one bound across package and step execution.
pub fn validate_command(argv: &[String], timeout_seconds: u64) -> Result<(), String> {
    if argv.is_empty()
        || argv[0].is_empty()
        || argv.len() > 256
        || argv
            .iter()
            .any(|value| value.len() > 16384 || value.contains('\0'))
        || !(1..=MAX_COMMAND_SECONDS).contains(&timeout_seconds)
    {
        return Err("invalid command arguments or timeout".into());
    }
    Ok(())
}
pub const SUBCOMMAND: &str = "reconciler-helper";
pub const EXECUTABLE_ENV: &str = "UPDATED_RECONCILER_HELPER";
pub const CONTEXT_ENV: &str = "UPDATED_RECONCILER_CONTEXT";
pub const CAPABILITIES: &[&str] = &[
    "command-adapter",
    "attention",
    "context",
    "boot-id",
    "result",
    "output",
    "file",
    "sequence",
];

fn valid_capabilities(values: &[String]) -> bool {
    values.len() <= 32
        && values
            .iter()
            .all(|value| value.len() <= 64 && crate::identity::is_segment(value))
        && values
            .iter()
            .enumerate()
            .all(|(i, value)| !values[..i].contains(value))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Support {
    pub apis: Vec<u32>,
    pub capabilities: Vec<String>,
}

impl Support {
    pub fn current() -> Self {
        Self {
            apis: vec![API],
            capabilities: CAPABILITIES.iter().map(|s| (*s).into()).collect(),
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.apis.is_empty()
            && self.apis.len() <= 16
            && self
                .apis
                .iter()
                .enumerate()
                .all(|(i, api)| *api != 0 && !self.apis[..i].contains(api))
            && valid_capabilities(&self.capabilities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn advertised_support_is_valid_and_rejects_duplicate_capabilities() {
        let mut support = Support::current();
        assert!(support.is_valid());
        support.capabilities.push(support.capabilities[0].clone());
        assert!(!support.is_valid());
    }
}
