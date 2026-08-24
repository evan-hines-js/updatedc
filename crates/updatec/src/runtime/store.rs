//! Talking to a repository's object store: building the S3 client from an `UpdateBackend`'s
//! credentials, presigning node uploads, and the bounded transfer helpers publication uses.

use super::*;

#[derive(Debug)]
pub struct StorageError(pub(crate) String);

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StorageError {}

/// Static S3 credentials, or all-`None` to fall back to the environment's workload identity.
#[derive(Default)]
pub struct S3Credentials<'a> {
    pub access_key: Option<&'a str>,
    pub secret_key: Option<&'a str>,
    /// Required by every temporary credential — STS `AssumeRole`, IRSA, an SSO session. Dropping
    /// it turns a valid temporary key pair into one S3 rejects, so an operator publishing with
    /// assumed-role credentials gets an authorization failure with nothing obviously wrong.
    pub session_token: Option<&'a str>,
}

/// Repository storage plus the capability signer for its one payload path. The signer is kept
/// beside the exact object store built from the same credentials, so a gateway reload swaps both
/// atomically.
pub struct RepositoryStore {
    pub(crate) objects: Arc<dyn ObjectStore>,
    pub(crate) signer: Arc<dyn Signer>,
    pub(crate) upload_signer: Arc<dyn UploadSigner>,
    pub(crate) destination: S3Destination,
}

pub(crate) struct BuiltS3 {
    pub(crate) objects: Arc<dyn ObjectStore>,
    pub(crate) signer: Arc<dyn Signer>,
    pub(crate) upload_signer: Arc<dyn UploadSigner>,
}

/// Mint one exact, storage-enforced S3 upload capability.
///
/// A presigned PUT constrains the method and key but signs `UNSIGNED-PAYLOAD`; neither S3 nor the
/// gateway can then limit how many bytes a compromised node stores. SigV4 POST policy is the S3
/// primitive that also binds `content-length-range`, so every direct write goes through it.
#[async_trait::async_trait]
pub(crate) trait UploadSigner: Send + Sync {
    async fn signed_upload(
        &self,
        key: &object_store::path::Path,
        max_bytes: usize,
        expires_in: Duration,
    ) -> Result<updated_contracts::dataflow::UploadCapability, StorageError>;
}

#[derive(Debug)]
pub(crate) struct S3UploadSigner {
    pub(crate) store: AmazonS3,
    pub(crate) bucket: String,
    pub(crate) region: String,
}

#[async_trait::async_trait]
impl UploadSigner for S3UploadSigner {
    async fn signed_upload(
        &self,
        key: &object_store::path::Path,
        max_bytes: usize,
        expires_in: Duration,
    ) -> Result<updated_contracts::dataflow::UploadCapability, StorageError> {
        if max_bytes == 0 || expires_in.is_zero() {
            return Err(StorageError(
                "S3 upload capability bounds must be positive".into(),
            ));
        }

        // `AmazonS3::path_url` is intentionally private. Ask its public signer for the bucket-root
        // URL so endpoint overrides, path-style MinIO, virtual-hosted AWS, and URL encoding stay
        // exactly aligned with the object client, then discard the unrelated query signature.
        let mut action = self
            .store
            .signed_url(
                reqwest::Method::GET,
                &object_store::path::Path::from(""),
                expires_in,
            )
            .await
            .map_err(|error| StorageError(format!("resolving S3 upload action: {error}")))?;
        action.set_query(None);
        action.set_fragment(None);

        let credential = self
            .store
            .credentials()
            .get_credential()
            .await
            .map_err(|error| StorageError(format!("resolving S3 upload credentials: {error}")))?;
        let now = chrono::Utc::now();
        let fields = s3_post_fields(
            &credential,
            &self.bucket,
            &self.region,
            key.as_ref(),
            max_bytes,
            now,
            expires_in,
        )?;
        let capability = updated_contracts::dataflow::UploadCapability {
            schema: updated_contracts::dataflow::UploadCapability::SCHEMA,
            url: action.into(),
            fields,
        };
        capability.validate().map_err(StorageError)?;
        Ok(capability)
    }
}

pub(crate) fn s3_post_fields(
    credential: &AwsCredential,
    bucket: &str,
    region: &str,
    key: &str,
    max_bytes: usize,
    now: chrono::DateTime<chrono::Utc>,
    expires_in: Duration,
) -> Result<BTreeMap<String, String>, StorageError> {
    let expires = now
        .checked_add_signed(
            chrono::Duration::from_std(expires_in)
                .map_err(|_| StorageError("S3 upload capability lifetime is invalid".into()))?,
        )
        .ok_or_else(|| StorageError("S3 upload capability expiry overflowed".into()))?;
    let short_date = now.format("%Y%m%d").to_string();
    let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
    let scope = format!("{short_date}/{region}/s3/aws4_request");
    let scoped_credential = format!("{}/{scope}", credential.key_id);

    let mut conditions = vec![
        serde_json::json!({"bucket": bucket}),
        serde_json::json!({"key": key}),
        serde_json::json!({"x-amz-algorithm": "AWS4-HMAC-SHA256"}),
        serde_json::json!({"x-amz-credential": scoped_credential}),
        serde_json::json!({"x-amz-date": timestamp}),
        serde_json::json!(["content-length-range", 1, max_bytes]),
    ];
    if let Some(token) = credential.token.as_deref() {
        conditions.push(serde_json::json!({"x-amz-security-token": token}));
    }
    let policy = serde_json::to_vec(&serde_json::json!({
        "expiration": expires.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "conditions": conditions,
    }))
    .map_err(|error| StorageError(format!("encoding S3 upload policy: {error}")))?;
    let encoded_policy = base64::engine::general_purpose::STANDARD.encode(policy);
    let signature =
        sigv4_policy_signature(&credential.secret_key, &short_date, region, &encoded_policy);

    let mut fields = BTreeMap::from([
        ("key".into(), key.into()),
        ("policy".into(), encoded_policy),
        ("x-amz-algorithm".into(), "AWS4-HMAC-SHA256".into()),
        ("x-amz-credential".into(), scoped_credential),
        ("x-amz-date".into(), timestamp),
        ("x-amz-signature".into(), signature),
    ]);
    if let Some(token) = credential.token.as_deref() {
        fields.insert("x-amz-security-token".into(), token.into());
    }
    Ok(fields)
}

pub(crate) fn sigv4_policy_signature(
    secret: &str,
    date: &str,
    region: &str,
    policy: &str,
) -> String {
    fn sign(key: &[u8], value: &[u8]) -> Vec<u8> {
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
        aws_lc_rs::hmac::sign(&key, value).as_ref().to_vec()
    }

    let mut prefixed_secret = Vec::with_capacity(4 + secret.len());
    prefixed_secret.extend_from_slice(b"AWS4");
    prefixed_secret.extend_from_slice(secret.as_bytes());
    let date_key = sign(&prefixed_secret, date.as_bytes());
    let region_key = sign(&date_key, region.as_bytes());
    let service_key = sign(&region_key, b"s3");
    let signing_key = sign(&service_key, b"aws4_request");
    hex::encode(sign(&signing_key, policy.as_bytes()))
}

pub(crate) fn s3_store(
    destination: &S3Destination,
    credentials: S3Credentials<'_>,
) -> Result<BuiltS3, StorageError> {
    let internal = s3_client(
        destination,
        &credentials,
        destination.endpoint.as_deref(),
        EndpointExposure::Internal,
    )?;
    let store = Arc::new(internal.store);
    let objects: Arc<dyn ObjectStore> = store.clone();
    let public_store = match destination.public_endpoint.as_deref() {
        None => {
            if internal.uses_http {
                return Err(StorageError(
                    "an internal non-HTTPS S3 endpoint requires a publicEndpoint for object capabilities"
                        .into(),
                ));
            }
            (*store).clone()
        }
        Some(endpoint) => {
            s3_client(
                destination,
                &credentials,
                Some(endpoint),
                EndpointExposure::Public,
            )?
            .store
        }
    };
    let signer: Arc<dyn Signer> = Arc::new(public_store.clone());
    let upload_signer: Arc<dyn UploadSigner> = Arc::new(S3UploadSigner {
        store: public_store,
        bucket: destination.bucket.clone(),
        region: destination.region.clone(),
    });
    Ok(BuiltS3 {
        objects,
        signer,
        upload_signer,
    })
}

pub(crate) struct S3Client {
    pub(crate) store: AmazonS3,
    pub(crate) uses_http: bool,
}

/// Build one S3 client through the shared destination, credential, and endpoint policy. Object
/// publishers use the internal client only; the gateway additionally builds a public HTTPS client
/// for signing bearer capabilities.
pub(crate) fn s3_client(
    destination: &S3Destination,
    credentials: &S3Credentials<'_>,
    endpoint: Option<&str>,
    exposure: EndpointExposure,
) -> Result<S3Client, StorageError> {
    let static_credentials = match (credentials.access_key, credentials.secret_key) {
        (None, None) if credentials.session_token.is_none() => None,
        (Some(access), Some(secret)) if !access.is_empty() && !secret.is_empty() => {
            Some((access, secret))
        }
        _ => {
            return Err(StorageError(
                "S3 credentials must be either absent or a non-empty access-key/secret-key pair; a session token is valid only with that pair"
                    .into(),
            ));
        }
    };
    validate_object_prefix(&destination.prefix)?;
    if destination.bucket.trim().is_empty() || destination.region.trim().is_empty() {
        return Err(StorageError(
            "S3 bucket and region must not be empty".into(),
        ));
    }
    let uses_http = endpoint
        .map(|endpoint| validate_s3_endpoint(endpoint, exposure))
        .transpose()?
        .unwrap_or(false);
    let mut builder = AmazonS3Builder::new()
        .with_bucket_name(&destination.bucket)
        .with_region(&destination.region);
    if let Some(endpoint) = endpoint {
        builder = builder
            .with_endpoint(endpoint)
            .with_allow_http(uses_http)
            .with_virtual_hosted_style_request(false);
    }
    if let Some((access, secret)) = static_credentials {
        builder = builder
            .with_access_key_id(access)
            .with_secret_access_key(secret);
        if let Some(token) = credentials.session_token {
            builder = builder.with_token(token);
        }
    }
    let store = builder
        .build()
        .map_err(|error| StorageError(format!("configuring S3 store: {error}")))?;
    Ok(S3Client { store, uses_http })
}

#[derive(Clone, Copy)]
pub(crate) enum EndpointExposure {
    Internal,
    Public,
}

/// Validate every configured S3 origin before either the object client or capability signer sees
/// it. Internal traffic may deliberately use cluster-local HTTP; a public origin is embedded in a
/// bearer capability and must use HTTPS. Neither kind is itself a credential or request, so
/// userinfo, query material, and fragments are always configuration errors.
pub(crate) fn validate_s3_endpoint(
    value: &str,
    exposure: EndpointExposure,
) -> Result<bool, StorageError> {
    let (transport, what) = match exposure {
        EndpointExposure::Internal => {
            (updated::http::EndpointTransport::HttpOrHttps, "S3 endpoint")
        }
        EndpointExposure::Public => (
            updated::http::EndpointTransport::HttpsOnly,
            "S3 public endpoint",
        ),
    };
    let parsed = updated::http::network_endpoint(value, transport, what)
        .map_err(|error| StorageError(error.to_string()))?;
    Ok(parsed.scheme() == "http")
}

/// Build the repository's object-store capability from an explicit destination and credential
/// set. CLI callers get only object access; the gateway-only direct-download signer stays coupled
/// to [`RepositoryStore`] and cannot leak into publication tooling.
pub fn repository_object_store(
    destination: &S3Destination,
    credentials: S3Credentials<'_>,
) -> Result<Arc<dyn ObjectStore>, StorageError> {
    Ok(Arc::new(
        s3_client(
            destination,
            &credentials,
            destination.endpoint.as_deref(),
            EndpointExposure::Internal,
        )?
        .store,
    ))
}

pub(crate) fn validate_object_prefix(prefix: &str) -> Result<(), StorageError> {
    let trimmed = prefix.trim_matches('/');
    // Empty = bucket root. Otherwise the prefix must already be normalized (no surrounding slashes)
    // and a confined relative path — the one shared traversal guard, so it can never climb out of
    // the bucket's key space.
    if prefix != trimmed
        || (!trimmed.is_empty() && !updated_contracts::path::is_confined_relative(trimmed))
    {
        return Err(StorageError(
            "S3 prefix must be a relative, normalized object-key prefix".into(),
        ));
    }
    Ok(())
}

/// The only object-key scope a managed repository may own. Kubernetes namespace/name pairs are
/// cluster-unique and contain no slash, so repositories cannot overlap one another even when they
/// share a bucket or reach the same physical store through different endpoints.
pub fn managed_repository_prefix(namespace: &str, name: &str) -> String {
    format!("routing/{namespace}/{name}")
}

pub(crate) fn managed_repository_destination(
    repository: &UpdateRepository,
) -> Result<S3Destination, StorageError> {
    let namespace = repository.namespace().ok_or_else(|| {
        StorageError("a managed repository must have a Kubernetes namespace".into())
    })?;
    Ok(S3Destination {
        bucket: repository.spec.s3.bucket.clone(),
        prefix: managed_repository_prefix(&namespace, &repository.name_any()),
        region: repository.spec.s3.region.clone(),
        credentials_secret_ref: repository.spec.s3.credentials_secret_ref.clone(),
        endpoint: repository.spec.s3.endpoint.clone(),
        public_endpoint: repository.spec.s3.public_endpoint.clone(),
    })
}

/// Resolve the repository's private object store using the same configuration for both
/// publication and the read-only HTTP gateway.
pub async fn repository_store(
    client: Client,
    namespace: &str,
    repository_name: &str,
) -> Result<RepositoryStore, Box<dyn std::error::Error>> {
    let repositories: Api<UpdateRepository> = Api::namespaced(client.clone(), namespace);
    let secrets: Api<Secret> = Api::namespaced(client, namespace);
    let repository = repositories.get(repository_name).await?;
    let destination = managed_repository_destination(&repository)?;
    let built = build_store(&secrets, &destination).await?;
    Ok(RepositoryStore {
        objects: built.objects,
        signer: built.signer,
        upload_signer: built.upload_signer,
        destination,
    })
}

/// Build the S3-backed object store for `destination`, reading its optional credentials Secret
/// (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`) or falling back to workload identity when none is
/// referenced. The single place credential resolution and store construction live, shared by
/// [`repository_store`] and the reconcile loop.
pub(crate) async fn build_store(
    secrets: &Api<Secret>,
    destination: &S3Destination,
) -> Result<BuiltS3, Box<dyn std::error::Error>> {
    let credentials = match &destination.credentials_secret_ref {
        Some(reference) => Some(secrets.get(&reference.name).await?),
        None => None,
    };
    let access = secret_string(credentials.as_ref(), "AWS_ACCESS_KEY_ID")?;
    let secret = secret_string(credentials.as_ref(), "AWS_SECRET_ACCESS_KEY")?;
    // A session token is present only for temporary credentials, so absence is normal.
    let token = optional_secret_string(credentials.as_ref(), "AWS_SESSION_TOKEN")?;
    Ok(s3_store(
        destination,
        S3Credentials {
            access_key: access.as_deref(),
            secret_key: secret.as_deref(),
            session_token: token.as_deref(),
        },
    )?)
}

/// The wiring harness `reconcile_once` never had: the full pass run for real against an
/// in-process S3 endpoint (the `spec.s3.endpoint` seam that already exists for MinIO — no
/// test-only code path in production) and the same mock apiserver the gateway tests use. Every
/// ordering defect of the adversarial review rounds — a projection held hostage by the signing
/// pipeline, cordons collected after the quarantine retain, conditions clobbered by a wholesale
/// patch — was a WIRING bug invisible to the pure planner tests; this module is where that class
/// gets locked instead of re-reviewed.
#[cfg(test)]
pub(crate) mod store_tests {
    use super::*;
    use object_store::memory::InMemory;

    fn destination() -> S3Destination {
        S3Destination {
            bucket: "fleet".into(),
            prefix: "routing".into(),
            region: "us-east-1".into(),
            credentials_secret_ref: None,
            endpoint: None,
            public_endpoint: None,
        }
    }

    #[tokio::test]
    async fn an_obsolete_publisher_cannot_replace_a_newer_timestamp() {
        let store = InMemory::new();
        let key = object_store::path::Path::from("routing/metadata/timestamp.json");
        store
            .put(&key, PutPayload::from(b"generation-1".to_vec()))
            .await
            .unwrap();

        // Publisher A captures generation 1, then stops making progress. Publisher B commits
        // generation 2 before A's delayed request reaches the object store.
        let local = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(local.path(), b"stale-generation-2").unwrap();
        let stale_write = prepare_conditional_publication_file(&store, &key, local.path())
            .await
            .unwrap();
        store
            .put(&key, PutPayload::from(b"generation-2".to_vec()))
            .await
            .unwrap();

        let error = commit_conditional_publication_file(&store, &key, "timestamp", stale_write)
            .await
            .unwrap_err();
        assert!(error.0.contains("another writer won the fence"), "{error}");
        let served = store.get(&key).await.unwrap().bytes().await.unwrap();
        assert_eq!(
            served.as_ref(),
            b"generation-2",
            "the delayed former leader cannot roll back the visible commit"
        );
    }

    #[tokio::test]
    async fn a_publisher_cannot_reuse_a_versioned_metadata_name_for_different_bytes() {
        let store = InMemory::new();
        let key = object_store::path::Path::from("routing/metadata/7.snapshot.json");
        let first = tempfile::NamedTempFile::new().unwrap();
        let second = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(first.path(), b"first signed snapshot").unwrap();
        std::fs::write(second.path(), b"different signed snapshot").unwrap();
        let relative = Path::new("metadata/7.snapshot.json");

        publish_immutable_metadata(&store, &key, relative, first.path())
            .await
            .unwrap();
        // Crash recovery with the same durable signed bytes is idempotent.
        publish_immutable_metadata(&store, &key, relative, first.path())
            .await
            .unwrap();
        let error = publish_immutable_metadata(&store, &key, relative, second.path())
            .await
            .unwrap_err();
        assert!(error.0.contains("different bytes"), "{error}");
        let served = store.get(&key).await.unwrap().bytes().await.unwrap();
        assert_eq!(served.as_ref(), b"first signed snapshot");
    }

    #[tokio::test]
    async fn publication_rejects_a_timestamp_rollback_even_with_a_fresh_object_version() {
        let store = InMemory::new();
        let key = object_store::path::Path::from("routing/metadata/timestamp.json");
        store
            .put(
                &key,
                PutPayload::from(br#"{"signed":{"version":9}}"#.to_vec()),
            )
            .await
            .unwrap();
        let local = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(local.path(), br#"{"signed":{"version":8}}"#).unwrap();

        let write = prepare_conditional_publication_file(&store, &key, local.path())
            .await
            .unwrap();
        let error = validate_timestamp_transition(&key, &write).unwrap_err();
        assert!(error.0.contains("older local generation 8"), "{error}");
    }

    #[tokio::test]
    async fn existing_content_addressed_targets_are_verified_and_never_replaced() {
        let store = InMemory::new();
        let expected = updated_contracts::digest::sha256_bytes(b"trusted target");
        let relative = std::path::PathBuf::from(format!("targets/{expected}.application"));
        let key = object_store::path::Path::from(format!("routing/{}", relative.display()));
        store
            .put(&key, PutPayload::from(b"wrong contents".to_vec()))
            .await
            .unwrap();
        let local = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(local.path(), b"trusted target").unwrap();

        let error = publish_content_addressed_target(
            &store,
            &key,
            &relative,
            local.path(),
            &expected,
            b"trusted target".len() as u64,
        )
        .await
        .unwrap_err();
        assert!(error.0.contains("publication destination"), "{error}");
        let served = store.get(&key).await.unwrap().bytes().await.unwrap();
        assert_eq!(served.as_ref(), b"wrong contents");
    }

    #[test]
    fn the_object_store_is_reused_until_its_destination_or_its_credentials_age_out() {
        let now = std::time::Instant::now();
        let cache = StoreCache {
            destination: destination(),
            store: Arc::new(InMemory::new()),
            built: now,
        };
        // The pass reuses the client this process already built — that warm TLS connection pool is
        // the whole point; rebuilding it every second made every request handshake again.
        assert!(cache.is_current(&destination(), now + std::time::Duration::from_secs(1)));
        // Temporary credentials (STS/IRSA) expire, so the store never outlives the reload window;
        // the rebuild re-reads the Secret.
        assert!(!cache.is_current(&destination(), now + STORE_RELOAD_INTERVAL));
        // And a repository re-pointed at another bucket takes effect on the very next pass.
        let mut moved = destination();
        moved.bucket = "elsewhere".into();
        assert!(!cache.is_current(&moved, now + std::time::Duration::from_secs(1)));
    }

    #[test]
    fn s3_credentials_never_fall_through_to_another_identity() {
        for credentials in [
            S3Credentials {
                access_key: Some("access"),
                secret_key: None,
                session_token: None,
            },
            S3Credentials {
                access_key: None,
                secret_key: Some("secret"),
                session_token: None,
            },
            S3Credentials {
                access_key: None,
                secret_key: None,
                session_token: Some("token"),
            },
            S3Credentials {
                access_key: Some(""),
                secret_key: Some("secret"),
                session_token: None,
            },
        ] {
            let error = match repository_object_store(&destination(), credentials) {
                Ok(_) => panic!("partial credentials unexpectedly built an object store"),
                Err(error) => error,
            };
            assert!(error
                .to_string()
                .contains("S3 credentials must be either absent"));
        }
    }

    #[test]
    fn internal_http_is_valid_for_publication_but_never_for_bearer_capabilities() {
        let mut destination = destination();
        destination.endpoint = Some("http://minio.internal:9000".into());

        repository_object_store(&destination, S3Credentials::default())
            .expect("an internal publisher may use cluster-local HTTP");

        let error = match s3_store(&destination, S3Credentials::default()) {
            Ok(_) => panic!("a gateway unexpectedly signed capabilities for an HTTP origin"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("requires a publicEndpoint"));
    }

    #[test]
    fn s3_endpoints_have_one_explicit_transport_and_authority_policy() {
        assert!(
            validate_s3_endpoint("http://minio.internal:9000", EndpointExposure::Internal).unwrap()
        );
        assert!(!validate_s3_endpoint(
            "https://objects.example/storage",
            EndpointExposure::Internal
        )
        .unwrap());
        assert!(
            !validate_s3_endpoint("https://objects.example/storage", EndpointExposure::Public)
                .unwrap()
        );

        for invalid in [
            "ftp://objects.example",
            "https://user@objects.example",
            "https://objects.example?credential=secret",
            "https://objects.example#fragment",
            "/objects.example",
        ] {
            assert!(
                validate_s3_endpoint(invalid, EndpointExposure::Public).is_err(),
                "accepted public endpoint {invalid}"
            );
        }
        assert!(
            validate_s3_endpoint("ftp://objects.internal", EndpointExposure::Internal).is_err()
        );
    }

    #[tokio::test]
    async fn direct_upload_policy_binds_the_bucket_key_expiry_and_size() {
        let mut destination = destination();
        destination.public_endpoint = Some("https://objects.example/storage".into());
        let built = s3_store(
            &destination,
            S3Credentials {
                access_key: Some("access"),
                secret_key: Some("secret"),
                session_token: Some("session"),
            },
        )
        .unwrap();
        let key = object_store::path::Path::from("routing/private/outputs/node.json");
        let capability = built
            .upload_signer
            .signed_upload(&key, 4096, Duration::from_secs(60))
            .await
            .unwrap();
        capability.validate().unwrap();
        assert_eq!(capability.url, "https://objects.example/storage/fleet/");
        assert_eq!(capability.fields["key"], key.as_ref());
        assert_eq!(capability.fields["x-amz-security-token"], "session");

        let policy = base64::engine::general_purpose::STANDARD
            .decode(&capability.fields["policy"])
            .unwrap();
        let policy: serde_json::Value = serde_json::from_slice(&policy).unwrap();
        let conditions = policy["conditions"].as_array().unwrap();
        for required in [
            serde_json::json!({"bucket": "fleet"}),
            serde_json::json!({"key": key.as_ref()}),
            serde_json::json!(["content-length-range", 1, 4096]),
            serde_json::json!({"x-amz-security-token": "session"}),
        ] {
            assert!(conditions.contains(&required), "missing {required}");
        }
        let expiration =
            chrono::DateTime::parse_from_rfc3339(policy["expiration"].as_str().unwrap())
                .unwrap()
                .with_timezone(&chrono::Utc);
        let remaining = expiration - chrono::Utc::now();
        assert!(remaining >= chrono::Duration::seconds(55));
        assert!(remaining <= chrono::Duration::seconds(60));
    }
}
