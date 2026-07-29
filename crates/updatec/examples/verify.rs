use updated::config::RepositorySource;
use updated_tuf::TrustedRepository;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [root, base, target] = args.as_slice() else {
        return Err("usage: verify <root.json> <base-url> <target-path>".into());
    };
    let state = tempfile::tempdir()?;
    let repository = TrustedRepository::load(
        &RepositorySource {
            root: root.into(),
            metadata_url: format!("{}/metadata/", base.trim_end_matches('/')),
            targets_url: format!("{}/targets/", base.trim_end_matches('/')),
            metadata_limit: 1024 * 1024,
            target_limit: 1024 * 1024,
            transport_timeout: std::time::Duration::from_secs(30),
            mtls: updated::tls::Identity::new("client.crt", "client.key", "ca.crt"),
        },
        &state.path().join("datastore"),
    )
    .await?;
    let verified = repository
        .all_targets()
        .into_iter()
        .find(|candidate| candidate.path == *target)
        .ok_or("target missing from verified TUF metadata")?;
    repository
        .download_target(&verified, &state.path().join("assignment.json"))
        .await?;
    let node: updated_contracts::artifact::AgentDocument =
        serde_json::from_slice(&std::fs::read(state.path().join("assignment.json"))?)?;
    node.validate()?;
    let config = repository.exact_target(&node.config)?;
    repository
        .download_target(&config, &state.path().join("config.json"))
        .await?;
    let config: updated_contracts::assignment::RepositoryAssignment =
        serde_json::from_slice(&std::fs::read(state.path().join("config.json"))?)?;
    config.validate()?;
    println!("{}", config.deployment);
    Ok(())
}
