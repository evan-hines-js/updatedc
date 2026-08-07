# Production S3 layout

This document shows a production layout for `updated` when routing data and every
release repository share one S3 bucket. The bucket is only storage; each prefix below
is still an independent TUF repository with its own trust root, metadata history, writer,
and public URL.

Examples use:

```text
s3://acme-updates-prod
```

and reserve the top-level `prod/` prefix so the same bucket can also hold an isolated
staging environment if desired.

## Recommended object tree

```text
s3://acme-updates-prod/
└── prod/
    ├── routing/                              # written by updatec only
    │   ├── metadata/
    │   │   ├── root.json                    # current root, also served unversioned
    │   │   ├── 1.root.json                  # every root version is retained
    │   │   ├── 2.root.json
    │   │   ├── 7.targets.json               # versioned names only; no bare targets.json
    │   │   ├── 7.snapshot.json              # versioned names only; no bare snapshot.json
    │   │   └── timestamp.json               # unversioned; uploaded last, commit point
    │   └── targets/                          # every object is <sha256 of its bytes>.<signed path>
    │       ├── <sha256>.assignments/configs/<config-id>.json   # opaque deployment document
    │       ├── <sha256>.assignments/agents/web-001.json        # names one config by path + sha256
    │       ├── <sha256>.assignments/agents/web-002.json
    │       └── <sha256>.assignments/agents/author-001.json
    │
    └── releases/                             # written by release pipelines only
        ├── web-stable/                       # one release lineage / TUF repository
        │   ├── metadata/                     # same role names as routing above
        │   └── targets/                      # logical target names; see the note below
        │       ├── products/
        │       │   ├── web/stable/
        │       │   │   ├── 41.0.0/
        │       │   │   │   ├── linux-x86_64/web
        │       │   │   │   └── linux-aarch64/web
        │       │   │   └── 42.0.0/
        │       │   │       ├── linux-x86_64/web
        │       │   │       └── linux-aarch64/web
        │       │   ├── web-lifecycle/stable/7.0.0/
        │       │   │   ├── linux-x86_64/web-lifecycle
        │       │   │   └── linux-aarch64/web-lifecycle
        │       │   └── supervisor/stable/3.2.0/
        │       │       ├── linux-x86_64/supervisor
        │       │       └── linux-aarch64/supervisor
        │       └── provider-sets/
        │           └── web-7.json
        │
        ├── magnolia-author/                  # independent version semantics
        │   ├── metadata/                     # independent TUF repository
        │   └── targets/
        │       ├── products/magnolia/author/6.3.8/linux-x86_64/magnolia
        │       ├── products/magnolia-lifecycle/stable/4.1.0/linux-x86_64/magnolia-lifecycle
        │       └── provider-sets/magnolia-author-4.json
        │
        └── magnolia-public/                  # another release lineage if needed
            ├── metadata/
            └── targets/
                ├── products/magnolia/public/6.3.8/linux-x86_64/magnolia
                └── provider-sets/magnolia-public-4.json
```

The exact target names are authenticated by TUF metadata. Directories in this diagram
are S3 key prefixes, not mutable server-side folders.

Two naming rules apply to every repository published by this tooling, routing and release
alike, and the release subtrees above show *logical* target names rather than object keys:

- **Metadata is consistent-snapshot.** `targets` and `snapshot` are published only under
  version-prefixed names (`7.targets.json`, `7.snapshot.json`); there is no bare
  `targets.json` or `snapshot.json`. `root.json` is published both unversioned and as
  `N.root.json` for every version. `timestamp.json` is the one unversioned role and is
  written last.
- **Target objects are content-addressed.** A target signed under the logical name
  `assignments/agents/web-001.json` is stored at
  `targets/<sha256 of its bytes>.assignments/agents/web-001.json`, so a new generation
  never overwrites an object an older, still-valid snapshot points at.

`updatec` names each config document by the SHA-256 of its own canonical bytes, so a
config's object key repeats the same hash twice —
`targets/<sha256>.assignments/configs/<sha256>.json`. Configs are deduplicated by content:
N nodes on the same deployment share one config object, and the per-node
`assignments/agents/<node>.json` document is only an exact path + SHA-256 reference to it.
Config objects therefore have no operator-chosen names such as `edge.json` or `batch.json`.

## Public URL mapping

Each metadata URL is a release-lineage identity. It must map to exactly one prefix:

| Purpose | Public base URL | S3 prefix |
|---|---|---|
| Node routing | `https://updates.acme.example/routing/` | `prod/routing/` |
| Web stable releases | `https://updates.acme.example/releases/web-stable/` | `prod/releases/web-stable/` |
| Magnolia author | `https://updates.acme.example/releases/magnolia-author/` | `prod/releases/magnolia-author/` |
| Magnolia public | `https://updates.acme.example/releases/magnolia-public/` | `prod/releases/magnolia-public/` |

A node configured with routing base URL
`https://updates.acme.example/routing/` requests:

```text
GET /routing/metadata/timestamp.json
GET /routing/metadata/7.snapshot.json
GET /routing/metadata/7.targets.json
GET /routing/targets/<sha256>.assignments/agents/web-001.json
GET /routing/targets/<sha256>.assignments/configs/<config-id>.json
```

Each `<sha256>` is the digest the (already verified) metadata names for that object, so the
client knows the key before it makes the request.

The selected config then directs it to one release lineage (abridged — the signed
`RepositoryAssignment` also carries `release_root`, `ordered_install_fallback`, and a
`runtime` block; see `schemas/examples/desired-deployment.json` for a complete document):

```json
{
  "schema": 3,
  "deployment": "web-edge-2026-07-18",
  "metadata_url": "https://updates.acme.example/releases/web-stable/metadata/",
  "targets_url": "https://updates.acme.example/releases/web-stable/targets/",
  "application": {
    "path": "products/web/stable/42.0.0/linux-x86_64/web",
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "provider_set": {
    "path": "provider-sets/web-7.json",
    "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }
}
```

Changing only the deployment name or desired target does not reset version ordering.
Changing `metadata_url` changes the release lineage: version floors and rejected-artifact
history from the old lineage no longer apply. This permits intentional transitions such
as `web-stable:42` to `magnolia-author:6.3.8` without treating `6.3.8` as a downgrade.

Do not give two spellings to the same logical lineage. Host aliases, case changes, ports,
or path changes produce different metadata URL hashes and therefore different lineages.

## What `updatec` owns

For the routing repository CRD, use one S3 destination:

```yaml
spec:
  defaultDeployment:
    name: web-default
    releaseRepository:
      metadataUrl: https://updates.acme.example/releases/web-stable/metadata/
      targetsUrl: https://updates.acme.example/releases/web-stable/targets/
    application:
      path: products/web/stable/42.0.0/linux-x86_64/web
      sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    providerSet:
      path: provider-sets/web-7.json
      sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  signingSecretRef: {name: tuf-signing-keys}
  enrollment:
    labels: {updated.dev/role: edge}
  assignmentPrefix: assignments
  s3:
    bucket: acme-updates-prod
    prefix: prod/routing
    region: us-east-1
```

`spec.enrollment` carries nothing but `labels`, the trusted labels stamped onto dynamically
enrolled agents. There is no enrollment secret and no `enrollment-secret` Secret to create:
`/enroll` is authenticated by mutual TLS at the gateway, where the node presents the shared
fleet bootstrap client certificate the fleet CA issued, and the gateway signs the node's CSR
into a per-node client certificate used for every request thereafter.

`updatec` publishes only `prod/routing/metadata/**` and
`prod/routing/targets/assignments/**`. It does not publish applications, providers, or
supervisors. Release pipelines publish the independent repositories under
`prod/releases/**` and place exact target path/SHA-256 references into deployment
documents consumed by `updatec`.

The controller's PVC is not a mirror of the bucket. It contains the repository's durable
TUF signing/version history needed to issue the next generation. Losing it and rebuilding
from whatever happens to be in S3 is not a supported recovery procedure; back it up as
control-plane state.

## Publication protocol

Publish one repository independently of every other prefix:

1. Build immutable application/provider/supervisor bundles.
2. Upload target objects under that repository's `targets/` prefix.
3. Upload all new TUF metadata except `metadata/timestamp.json`.
4. Upload `metadata/timestamp.json` last.

`timestamp.json` is the visibility/commit object. A client sees either the prior complete
generation or the new complete generation; it must never see a timestamp that references
metadata or targets that have not finished uploading.

Objects beneath `targets/` are immutable. Correcting a release creates new bytes and a
new authenticated SHA-256, even if an operator chooses to republish the same human version.
Do not overwrite target bytes in place after their hash has been signed.

Root rotation publishes versioned root metadata such as `2.root.json` before clients are
directed to it. Retain every root version required to walk from the oldest supported pinned
root to the current root.

## Bucket controls

Recommended bucket configuration:

- Block all public access. Serve through private gateways, CloudFront with origin access,
  or authenticated S3 access.
- Enable bucket versioning as an operational recovery aid. TUF remains the client trust
  mechanism; S3 versioning is not a substitute for signatures or rollback protection.
- Encrypt at rest with SSE-KMS and log data events for all writes and deletes.
- Deny non-TLS requests and deny deletion outside a controlled retention role.
- Use lifecycle rules only for superseded S3 object versions and explicitly retired,
  unreferenced targets. Never expire active TUF metadata, required root rotations, or a
  target still reachable from supported metadata.
- Replicate the entire bucket or each complete repository prefix. Do not expose a replica
  until its `timestamp.json` and everything referenced by it are present.

## IAM separation

Use separate workload identities even though storage is shared:

| Principal | Required access |
|---|---|
| `updatec-controller` | Read/write/list only `prod/routing/*` |
| Routing gateway/CDN origin | Read only `prod/routing/*` |
| Web release publisher | Read/write/list only `prod/releases/web-stable/*` |
| Magnolia author publisher | Read/write/list only `prod/releases/magnolia-author/*` |
| Magnolia public publisher | Read/write/list only `prod/releases/magnolia-public/*` |
| Release gateways/CDN origin | Read only the release prefixes they serve |
| Backup/retention role | Versioned read and tightly controlled delete/restore access |

TUF private signing keys do not belong in S3. Keep them in an offline signing system,
KMS/HSM-backed signer, or the controller's Kubernetes Secret/workload boundary as
appropriate to the role. Nodes receive pinned root metadata through the installer or
another authenticated bootstrap channel, never by trusting an unauthenticated first read
from this bucket.

## Environment isolation

If production and staging must share one physical bucket, give them disjoint roots:

```text
prod/routing/**
prod/releases/**
staging/routing/**
staging/releases/**
```

They must also have distinct TUF roots, signing roles, IAM principals, public URLs, and
controller PVCs. Prefix separation alone is not an adequate trust boundary.
