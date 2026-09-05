//! A durable hold is a request for an operator decision, never a successful reconciliation.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Attention {
    pub product: String,
    pub receipt: String,
    pub operation: crate::reconciler::MutationOperation,
    pub attempt: String,
    pub version: String,
    pub message: String,
}
impl Attention {
    pub fn validate(&self) -> Result<(), String> {
        if !crate::identity::is_segment(&self.product)
            || !crate::is_canonical_sha256(&self.receipt)
            || !crate::identity::is_release_version(&self.version)
            || !(crate::reconciler::attempt::is_reserved(&self.attempt)
                || crate::reconciler::attempt::is_transaction_invocation(&self.attempt))
            || self.message.is_empty()
            || self.message.len() > crate::reconciler::MAX_RESULT_MESSAGE_BYTES
            || self.message.chars().any(char::is_control)
        {
            return Err("invalid operator attention record".into());
        }
        Ok(())
    }
}
