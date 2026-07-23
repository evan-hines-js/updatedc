use kube::CustomResourceExt;
use updatec::{UpdateAgent, UpdateGroup, UpdateGroupSet, UpdateRepository, UpdateSubscription};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print!(
        "{}---\n{}---\n{}---\n{}---\n{}",
        serde_yaml::to_string(&UpdateGroup::crd())?,
        serde_yaml::to_string(&UpdateGroupSet::crd())?,
        serde_yaml::to_string(&UpdateAgent::crd())?,
        serde_yaml::to_string(&UpdateRepository::crd())?,
        serde_yaml::to_string(&UpdateSubscription::crd())?
    );
    Ok(())
}
