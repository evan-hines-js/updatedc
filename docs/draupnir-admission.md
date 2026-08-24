# Draupnir release admission

updatedc has one external release-admission path: an `UpdateRepository` optionally references one
namespaced `UpdateAdmissionPolicy`. There are no environment variables, command-line flags,
per-group overrides, separate event stream, or hash allow-list mode.

The controller sends Draupnir the complete set of active release subjects. That includes desired
group and default deployments and every retained deployment that a node may still be running. A
subject currently consists of the application SHA-256 and provider-set SHA-256. Its `id` is the
SHA-256 of those canonical, versioned facts—not of a display name or mutable URL.

The request is both notification and query. updatedc sends it immediately when it encounters a
subject absent from the last request, then at most once per 30 seconds for an unchanged set. A
failed request is also held for that cadence so a one-second reconcile loop cannot hammer a broken
Draupnir. Response bodies and requests are limited to 1 MiB and redirects are refused.

The two directions are authenticated differently, on purpose.

The **request** proves which caller is asking:
`X-Updated-Signature: sha256=<HMAC-SHA256>` over the exact request bytes, using the `key` entry in
the policy's Secret, which must decode to 32–1,024 bytes. A shared secret is the right shape here,
because both ends may legitimately produce the value.

The **response** is an authoritative compliance assertion that gates deployment, so it is signed by
Draupnir alone: `X-Draupnir-Admission-Signature: es256:<base64 DER>`, an ECDSA P-256/SHA-256
signature over the **exact response body bytes**, verified against the public key pinned in
`spec.webhook.decisionPublicKey` — hex of an uncompressed P-256 point (65 bytes, `04`-prefixed),
the same encoding `UpdateAgent.spec.identity.publicKey` uses.

A shared HMAC cannot serve that direction. updatedc would hold a key capable of minting Draupnir's
verdict, so the signature would prove nothing to a third party and nothing about who decided.
Because the signed bytes are the bytes acted on, Draupnir's retained attestation — which embeds the
digest of exactly these bytes — cannot silently disagree with what updatedc enforced.

There is no unsigned or symmetric fallback and no algorithm negotiation: `es256` is named in the
header so a future algorithm is a visible protocol change rather than a reinterpretation of the same
bytes. A malformed pin is refused before any request is sent, because a policy that cannot verify a
decision has no safe reading.

## Request

```json
{
  "schema": 1,
  "requestId": "<fresh-256-bit-hex-nonce>",
  "namespace": "updated-system",
  "repository": "default",
  "subjects": [
    {
      "id": "<sha256-of-canonical-subject>",
      "applicationSha256": "<64-hex-sha256>",
      "providerSetSha256": "<64-hex-sha256>"
    }
  ]
}
```

Subjects are sorted by `id` and deduplicated. Later manifest constraints are added as explicit,
typed subject facts under a new protocol schema. updatedc does not send arbitrary manifests or
accept opaque policy JSON; that keeps the cache identity and the compatibility boundary precise.
`requestId` is newly generated for every network refresh.

## Response

```json
{
  "schema": 1,
  "requestId": "<exact-request-requestId>",
  "revision": "draupnir-policy-revision-42",
  "decisions": [
    {
      "subjectId": "<requested-subject-id>",
      "verdict": "compliant",
      "reason": "signed release matches policy"
    }
  ]
}
```

The signed response must echo `requestId` exactly. This binds it to the current exchange and makes
a captured decision from an older refresh unusable even when the subject set is unchanged. Every
requested subject must appear exactly once, and no unrequested subject may appear. The four
verdicts are:

- `compliant` — movement is allowed.
- `nonCompliant` — the CRD's `actions.nonCompliant` selects `Allow` or `Block`.
- `noInformation` — the CRD's `actions.noInformation` independently selects `Allow` or `Block`.
- `pending` — movement is held; uncertainty is never treated as `noInformation`.

`revision` is 1–256 UTF-8 bytes and an optional `reason` is at most 1,024 UTF-8 bytes, keeping the
result safe to project into bounded Kubernetes status.

Malformed, oversized, incomplete, duplicate, redirected, timed-out, or non-success responses hold
every subject without a fresh authoritative decision. So does a missing, malformed, or invalid
decision signature, and so does a `decisionPublicKey` that is not a well-formed pin. A still-fresh cached decision may continue to govern a known subject when a refresh
for a newly seen subject fails; the new subject remains held. At 30 seconds, expired decisions hold
movement until Draupnir responds again.

The resulting blocked deployment identities are unioned with updatec's evidence-derived regression
halts. That one movement set controls first admission, in-progress batches, concurrency-slot
accounting, cordoned nodes, greenfield nodes, and the unmatched default cohort. A block never rolls
back a node already on the subject; it freezes widening. A different compliant subject can proceed
normally.

Bootstrapping Draupnir itself is deployment orchestration, not a second controller mode: until Draupnir exists,
an `UpdateRepository` cannot reference this policy because no authority can answer it. The Draupnir installer
records that one-time state explicitly, installs the application, then atomically adds the reference. Once the
reference exists, updatec has no bootstrap flag, environment override, or fallback; every movement path above
uses the policy evaluation.
