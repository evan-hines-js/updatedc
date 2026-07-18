use kube::CustomResourceExt;
use updatec::{UpdatedGroup, UpdatedNode, UpdatedRepository};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print!(
        "{}---\n{}---\n{}",
        serde_yaml::to_string(&UpdatedGroup::crd())?,
        serde_yaml::to_string(&UpdatedNode::crd())?,
        serde_yaml::to_string(&UpdatedRepository::crd())?
    );
    Ok(())
}
