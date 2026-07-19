use kube::CustomResourceExt;
use updatec::{UpdateAgent, UpdateGroup, UpdateGroupSet, UpdateRepository};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print!(
        "{}---\n{}---\n{}---\n{}",
        serde_yaml::to_string(&UpdateGroup::crd())?,
        serde_yaml::to_string(&UpdateGroupSet::crd())?,
        serde_yaml::to_string(&UpdateAgent::crd())?,
        serde_yaml::to_string(&UpdateRepository::crd())?
    );
    Ok(())
}
