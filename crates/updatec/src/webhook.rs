//! Shared outbound-webhook authentication.
//!
//! Subscription delivery and release admission sign their REQUESTS the same way. Keeping the
//! implementation here prevents the two outbound paths from acquiring subtly different key lookup,
//! header, or encoding rules.
//!
//! Only requests. This is caller authentication over a shared secret, which is the right shape for
//! "which caller is asking" and the wrong shape for an authoritative answer: both ends hold the
//! key, so neither can prove to anyone what the other said. Release admission therefore verifies
//! its RESPONSE against a pinned public key instead (see [`crate::admission`]), and nothing in this
//! module is involved in that direction.

use k8s_openapi::api::core::v1::Secret;
use kube::Api;

pub(crate) const SIGNATURE_HEADER: &str = "x-updated-signature";
const MIN_HMAC_KEY_BYTES: usize = 32;
const MAX_HMAC_KEY_BYTES: usize = 1024;

/// HMAC-SHA256 of `body` under `key`, encoded exactly as the webhook header value.
pub(crate) fn signature(key: &[u8], body: &[u8]) -> String {
    use aws_lc_rs::hmac;

    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    format!("sha256={}", hex::encode(hmac::sign(&key, body).as_ref()))
}

/// Load the signing key from the namespace-local Secret entry named `key`.
pub(crate) async fn hmac_key(
    secrets: &Api<Secret>,
    name: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let secret = secrets.get(name).await?;
    let bytes = secret
        .data
        .as_ref()
        .and_then(|data| data.get("key"))
        .ok_or_else(|| format!("webhook Secret {name} is missing entry 'key'"))?;
    if !(MIN_HMAC_KEY_BYTES..=MAX_HMAC_KEY_BYTES).contains(&bytes.0.len()) {
        return Err(format!(
            "webhook Secret {name} entry 'key' must be {MIN_HMAC_KEY_BYTES}..={MAX_HMAC_KEY_BYTES} bytes"
        )
        .into());
    }
    Ok(bytes.0.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_stable_and_binds_key_and_body() {
        let value = signature(b"secret-key", b"event");
        assert_eq!(value.len(), "sha256=".len() + 64);
        assert_eq!(value, signature(b"secret-key", b"event"));
        assert_ne!(value, signature(b"other-key", b"event"));
        assert_ne!(value, signature(b"secret-key", b"tampered"));
    }

    #[tokio::test]
    async fn secret_key_material_has_exact_shared_bounds() {
        use k8s_openapi::ByteString;

        for (length, accepted) in [
            (MIN_HMAC_KEY_BYTES - 1, false),
            (MIN_HMAC_KEY_BYTES, true),
            (MAX_HMAC_KEY_BYTES, true),
            (MAX_HMAC_KEY_BYTES + 1, false),
        ] {
            let secret = Secret {
                metadata: kube::api::ObjectMeta {
                    name: Some("webhook-key".into()),
                    ..Default::default()
                },
                data: Some(std::collections::BTreeMap::from([(
                    "key".into(),
                    ByteString(vec![7; length]),
                )])),
                ..Default::default()
            };
            let encoded = serde_json::to_value(secret).unwrap();
            let client = crate::tests::apiserver(move |_, _, _| {
                (axum::http::StatusCode::OK, encoded.clone())
            });
            let secrets: Api<Secret> = Api::namespaced(client, "ns");
            assert_eq!(
                hmac_key(&secrets, "webhook-key").await.is_ok(),
                accepted,
                "unexpected validation result for {length}-byte key"
            );
        }
    }
}
