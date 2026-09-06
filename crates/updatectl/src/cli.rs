//! The command line: every subcommand, its arguments, and the shared release-repository
//! backend they are all parameterised by.

use crate::*;

/// Validate and publish custom software from CI. Rollouts are configured in Kubernetes YAML.
#[derive(Parser, Debug)]
#[command(name = "updatectl", about, long_about = None, disable_version_flag = true)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Build, sign, and publish a package; print its immutable reference for deployment YAML.
    Publish(Box<PublishArgs>),
    /// Validate a package and entrypoint; optionally run against an isolated predecessor fixture.
    Check(Box<crate::package::CheckArgs>),
}

/// The release repository backend, shared by every subcommand. AWS credentials come from
/// the standard `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` environment.
#[derive(Args, Debug)]
pub(crate) struct Backend {
    /// Mounted online signing keys: targets.pk8, snapshot.pk8, and timestamp.pk8.
    /// Repository provisioning and root-key management are separate from the release pipeline.
    #[arg(long, env = "UPDATECTL_KEYS_DIR")]
    pub(crate) keys_dir: PathBuf,

    /// Release-repository S3 bucket.
    #[arg(long, env = "UPDATECTL_BUCKET")]
    pub(crate) bucket: String,

    /// Release-repository S3 region.
    #[arg(long, env = "UPDATECTL_REGION")]
    pub(crate) region: String,

    /// Key prefix within the bucket. Empty means the bucket root.
    #[arg(long, env = "UPDATECTL_PREFIX", default_value = "")]
    pub(crate) prefix: String,

    /// Optional S3 endpoint override (e.g. MinIO). Omit for real AWS.
    #[arg(long, env = "UPDATECTL_ENDPOINT")]
    pub(crate) endpoint: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct PublishArgs {
    #[command(flatten)]
    pub(crate) procedure: crate::package::ProcedureArgs,
    #[command(flatten)]
    pub(crate) backend: Backend,

    /// Product name; also the bundle target's component segment.
    #[arg(long, env = "UPDATECTL_PRODUCT")]
    pub(crate) product: String,

    /// Release channel.
    #[arg(long, env = "UPDATECTL_CHANNEL", default_value = "stable")]
    pub(crate) channel: String,

    /// Semantic version of this release.
    #[arg(long, env = "UPDATECTL_VERSION")]
    pub(crate) version: String,

    /// Package directory containing the entrypoint and its files.
    #[arg(long, env = "UPDATECTL_SOURCE")]
    pub(crate) source: PathBuf,

    /// Target platform `<os>-<arch>`. Defaults to the host platform.
    #[arg(long, env = "UPDATECTL_PLATFORM")]
    pub(crate) platform: Option<String>,

    /// Days until the re-signed TUF metadata expires.
    #[arg(long, env = "UPDATECTL_EXPIRY_DAYS", default_value_t = 365)]
    pub(crate) expiry_days: i64,

    /// Result format written to stdout. Diagnostics always go to stderr, so `json` yields a
    /// single clean object a pipeline can capture and parse.
    #[arg(long, value_enum, env = "UPDATECTL_OUTPUT", default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum OutputFormat {
    Text,
    Json,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_public_cli_only_validates_and_publishes_packages() {
        let command = Cli::command();
        command.clone().debug_assert();
        let names: Vec<_> = command
            .get_subcommands()
            .map(|command| command.get_name())
            .collect();
        assert_eq!(names, ["publish", "check"]);
        let publish = command.find_subcommand("publish").unwrap();
        for argument in ["group", "namespace", "emergency"] {
            assert!(!publish.get_arguments().any(|arg| arg.get_id() == argument));
        }
    }

    #[test]
    fn publication_needs_no_kubernetes_target_or_credentials() {
        let arguments = [
            "updatectl",
            "publish",
            "--source",
            ".",
            "--entrypoint",
            "install.sh",
            "--product",
            "app",
            "--version",
            "1.0.0",
            "--keys-dir",
            "keys",
            "--bucket",
            "releases",
            "--region",
            "us-east-1",
        ];
        assert!(Cli::try_parse_from(arguments).is_ok());
        for flag in ["--group", "--namespace", "--emergency"] {
            let mut rejected = arguments.to_vec();
            rejected.push(flag);
            rejected.push("unexpected");
            assert!(Cli::try_parse_from(rejected).is_err());
        }
    }
}
