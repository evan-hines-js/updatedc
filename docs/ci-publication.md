# Publish custom software from CI

`updatectl` has two public commands: `check` and `publish`. It packages existing software; it does
not compile the application, manage keys or nodes, or change Kubernetes resources.

Build your software using its normal build tools, and place its files and entrypoint in a package
directory. Validate that package:

```sh
updatectl check ./package --entrypoint install.sh
```

For application conformance tests, add `--against ./previous-package` with disposable fixtures.
Both fixtures use the supplied entrypoint and execution options. These checks execute package
code on the CI host. Without `--against`, validation executes no application code.

Publish using a provisioned release repository and mounted online signing keys. Repository options
can come from CI environment variables (`UPDATECTL_KEYS_DIR`, `UPDATECTL_BUCKET`,
`UPDATECTL_REGION`, and optional `UPDATECTL_PREFIX`/`UPDATECTL_ENDPOINT`). Object-store credentials
use the standard AWS environment.

```sh
updatectl publish --source ./package --entrypoint install.sh \
  --product my-app --version 4.0.0 --output json > release.json
```

The command snapshots the source, builds a deterministic bundle, signs and uploads it, and returns
`target`, `sha256`, `version`, `product`, `channel`, and `platform`. GitHub Actions also receives
`target`, `sha256`, and `version` step outputs. Only online signing keys are required; root-key
provisioning and rotation belong to the repository's trust-management process, outside CI builds.

Operators or GitOps automation place the reference in the existing `UpdateGroup` YAML:

| Publication output | YAML field |
| --- | --- |
| `target` | `spec.deployment.application.releases[version].package.path` |
| `sha256` | `spec.deployment.application.releases[version].package.sha256` |

Apply and inspect those resources with kubectl or your existing GitOps tooling. The project's
[primary design rule](../AGENTS.md#primary-design-rule) keeps Kubernetes operations in that interface.

Node selection, prerequisites, rollout limits, maintenance windows, and emergency corrections stay
in Kubernetes resources. Publication does not require a group, Kubernetes credentials, or cluster
connectivity. Publishing bytes alone does not change any machine's desired deployment.

The package entrypoint owns installation and upgrade logic. Operators select the final package;
they do not author execution-helper JSON or enumerate upgrade commands. See
[installation and ordered upgrades](install-and-upgrade.md) for that implementation boundary.
