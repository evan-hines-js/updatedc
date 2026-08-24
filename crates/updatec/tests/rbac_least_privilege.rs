//! Minting a node identity is the gateway's alone.
//!
//! An `UpdateAgent` carries the labels that decide which `UpdateGroup` selects a node, and therefore
//! which deployment reaches it. Creating or rewriting one is the most consequential write in this
//! system, which is why `/enroll` — the only thing that does it — runs under its own ServiceAccount,
//! with a Role scoped to that transaction, behind a `ValidatingAdmissionPolicy` that constrains the
//! shape of what it may write (see `gateway_write_boundary`).
//!
//! The controller's Role granted `create` on `updateagents` too, alongside four sibling resources it
//! only ever reads. Nothing used it: the reconciling half observes this inventory and writes only
//! `/status` subresources and one `UpdateRepository` finalizer patch. It was unconstrained in a way
//! the gateway's identical authority deliberately is not — the controller's admission policy covers
//! ConfigMaps and EndpointSlices, and nothing else. So the grant is gone, and this test is what
//! keeps it gone: a verb re-added to the read-only rule fails the build rather than quietly
//! restoring identity-minting authority to the half that never needed it.
//!
//! Scoped to the invariant, not to the file. This does not assert what the Role DOES grant — that
//! would be a test that mirrors the YAML and fails on every legitimate edit. It asserts the one
//! thing that must never become true again.

/// The controller half of the chart's RBAC template, as written.
///
/// The template's two Roles are separated by a banner comment; the gateway's rules are supposed to
/// contain agent writes, so mixing the halves would make this check vacuous.
fn controller_rules() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/charts/updatec/templates/rbac.yaml");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));

    let start = source
        .find("── Controller")
        .expect("the RBAC template marks its controller section");
    let end = source
        .find("── Gateway")
        .expect("the RBAC template marks its gateway section");
    assert!(
        start < end,
        "the controller section must precede the gateway section"
    );
    source[start..end].to_string()
}

/// One `- apiGroups:` rule block, as the lines belonging to it.
fn rules(section: &str) -> Vec<Vec<&str>> {
    let mut blocks: Vec<Vec<&str>> = Vec::new();
    for line in section.lines() {
        if line.trim_start().starts_with("- apiGroups:") {
            blocks.push(Vec::new());
        }
        if let Some(block) = blocks.last_mut() {
            block.push(line);
        }
    }
    blocks
}

/// The controller may read node inventory. It may not create or rewrite it.
///
/// `updateagents/status` is a different resource and is deliberately untouched here: publishing a
/// node's observed condition is exactly the reconciling half's job.
#[test]
fn the_controller_may_not_mint_or_rewrite_a_node_identity() {
    let section = controller_rules();
    let blocks = rules(&section);
    assert!(
        !blocks.is_empty(),
        "parsed no rules out of the controller Role; this test is not checking anything"
    );

    let mut checked = 0;
    for block in blocks {
        let text = block.join("\n");
        // The bare resource, never the `/status` subresource.
        if !text.contains("\"updateagents\"") {
            continue;
        }
        checked += 1;
        for forbidden in [
            "create",
            "update",
            "patch",
            "delete",
            "deletecollection",
            "*",
        ] {
            assert!(
                !text.contains(&format!("\"{forbidden}\"")),
                "the controller Role grants {forbidden:?} on updateagents:\n{text}\n\nMinting or \
                 rewriting a node identity is the gateway's alone — it is the write the gateway's \
                 ValidatingAdmissionPolicy exists to fence, and the controller has no such policy \
                 over updated.dev objects. If the controller genuinely needs this, it needs an \
                 admission boundary first."
            );
        }
    }
    assert_eq!(
        checked, 1,
        "expected exactly one controller rule naming updateagents (the read-only one); found \
         {checked}. A second rule is how a write verb gets in without touching the first."
    );
}

/// The gateway, which does mint identities, is still the one that holds that authority.
///
/// The mirror of the assertion above: if this ever fails, the capability did not get tightened, it
/// got moved somewhere without the fence.
#[test]
fn the_gateway_is_the_identity_minting_half() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/charts/updatec/templates/rbac.yaml");
    let source = std::fs::read_to_string(&path).expect("the RBAC template is readable");
    let gateway = &source[source.find("── Gateway").expect("a gateway section")..];

    let mints = rules(gateway).into_iter().any(|block| {
        let text = block.join("\n");
        text.contains("\"updateagents\"") && text.contains("\"create\"")
    });
    assert!(
        mints,
        "the gateway Role no longer grants create on updateagents — /enroll cannot complete, and \
         if that authority moved to another identity it moved out from behind the write boundary"
    );
}
