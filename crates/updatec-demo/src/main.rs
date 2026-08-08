//! Presentation-only UI for the real `updatec` operator path.
//!
//! The service observes the fleet and drives releases through the real `updatectl deploy` — it
//! signs nothing itself and holds no key: `updatectl` signs a complete routing generation, uploads
//! it, and the managed agent consumes it. What this binary serves is the view of that happening.

use std::env;
use std::net::SocketAddr;

use tokio::net::TcpListener;

mod background;
mod demo;
mod golden;
mod haproxy;
mod layout;
mod page;
mod publisher;
mod server;
mod setup;
mod state;
pub(crate) use background::*;
pub(crate) use demo::*;
pub(crate) use golden::*;
pub(crate) use haproxy::*;
pub(crate) use layout::*;
pub(crate) use page::*;
pub(crate) use publisher::*;
pub(crate) use server::*;
pub(crate) use setup::*;
pub(crate) use state::*;

#[tokio::main]
pub(crate) async fn main() -> Result<(), Box<dyn std::error::Error>> {
    updated::tls::install_crypto_provider();
    match env::args().nth(1).as_deref() {
        Some("start") => return start_demo(false, false).await,
        Some("e2e") => {
            let exit_after = env::args().any(|argument| argument == "--exit");
            return start_demo(true, exit_after).await;
        }
        Some("setup") => return setup_demo().await,
        Some("exercise") => {
            let passes = env::args()
                .nth(2)
                .and_then(|arg| arg.parse().ok())
                .unwrap_or(1);
            return exercise_existing_cluster(passes).await;
        }
        Some("reset") => return reset_demo(),
        // The one place anything — Rust, shell, or Ansible — learns the enrollment name a host
        // asserts. `resource_name` is the single definition; this prints it so nothing outside
        // this binary re-implements the derivation.
        Some("agent-name") => {
            let hostname = env::args()
                .nth(2)
                .ok_or("agent-name needs a hostname: `updatec-demo agent-name <hostname>`")?;
            println!("{}", resource_name(&hostname));
            return Ok(());
        }
        Some("serve") | None => {}
        Some(command) => {
            return Err(format!(
                "unknown command {command:?}; use start, setup, e2e [--exit], \
                 exercise [passes], serve, agent-name <hostname>, or reset"
            )
            .into())
        }
    }
    let demo = Demo::new().await?;
    let address: SocketAddr = env::var("DEMO_ADDRESS")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()?;
    let listener = TcpListener::bind(address).await?;
    eprintln!("updatec demo listening on http://{address}");
    spawn_pod_set_labeler(demo.clone());
    spawn_load_generator(demo.clone());
    spawn_readiness_watcher(demo.clone());
    loop {
        let (stream, _) = listener.accept().await?;
        let demo = demo.clone();
        tokio::spawn(async move {
            if let Err(error) = serve(stream, demo).await {
                eprintln!("demo request failed: {error}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::agent_resource_name;

    /// Golden vectors for the derivation every consumer now reads out of this binary
    /// (`updatec-demo agent-name`). Changing it renames every node in the demo and the kind
    /// e2e at once, so it must be a deliberate edit, not a refactoring accident.
    #[test]
    fn demo_agent_names_match_dynamic_enrollment_names() {
        assert_eq!(agent_resource_name(0), "agent-53fa7c16911537893c54970e");
        assert_eq!(agent_resource_name(4), "agent-9f815b3ffd9a32a533b577d9");
    }
}
