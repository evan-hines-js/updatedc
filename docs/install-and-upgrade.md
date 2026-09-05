# Installation and ordered upgrades

The operator deploys a target package. Its entrypoint observes the application and chooses the work
needed to reach that target. Fresh installation, adoption of an existing application, upgrades, and
repair can call entirely different scripts through that same entrypoint. A new agent installation
does not prove that the application or its database is absent. Invocation reasons and package
version markers are context, not evidence about application state.

Ordinary scripts remain ordinary scripts: no helper, migration manifest, or special output format
is required. They run through the existing command adapter with its usual deadlines, replay policy,
and recovery policy. Scripts that need durable checked steps can opt into the native `sequence`
helper. One step and many steps use the same executor; there is no separate upgrade runner.

## Ownership

| Package author owns | updatedc owns |
| --- | --- |
| Inspecting actual application state and selecting install, upgrade, or repair | Authenticated package selection and the existing bounded entrypoint runtime |
| Declaring the supported path and supplying every intermediate tool or artifact | Validating the entire sequence declaration before executing it |
| Implementing checks, safe transitions, and application health gates | Running steps in the supplied order, verifying before and after each apply, and stopping at the first failure |
| Distributed coordination, node order, draining, and supported version skew | One nonblocking lock for cooperating callers sharing a local resource state directory |
| Proving partial effects safe to repeat and defining recovery | Durable step identities, fresh checks on authorized replay, process containment, deadlines, and existing attention holds |

updatedc does not download or activate historical packages to fill gaps in a script's plan. Package
release numbers and application versions are independent. The selected package may orchestrate
several application versions before its deployment is complete.

## Kubernetes example

For a kubeadm-managed cluster, skipping minor versions during an upgrade is unsupported. A target
of 1.35 from 1.31 therefore needs 1.32, 1.33, 1.34, then 1.35. A genuinely new cluster can instead
be initialized at the target version. Follow the release-specific
[kubeadm upgrade procedure](https://v1-35.docs.kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/)
and [version skew policy](https://kubernetes.io/releases/version-skew-policy/).

An application entrypoint can express the distinction as follows. This is illustrative planning
code: `inspect_cluster`, `install_step`, and `upgrade_step` are supplied by the integration, and
`helper` is the JSON caller shown in [the helper documentation](reconciler-helper.md).

```python
target_minor = 35
observed = inspect_cluster()  # Raise on an unreachable, unsupported, or uncertain cluster.
if observed.absent:           # Must establish absence, not just a failed connection.
    steps = [install_step(target_minor)]
elif observed.healthy and 31 <= observed.minor < target_minor:
    steps = [upgrade_step(minor) for minor in range(observed.minor + 1, target_minor + 1)]
elif observed.healthy and observed.minor == target_minor:
    helper("succeed", changed=False)
    raise SystemExit(0)
else:
    raise RuntimeError("unsupported starting state; inspect the cluster before changing it")

result = helper("sequence", resource="kubernetes-cluster", steps=steps, timeoutSeconds=3300)
helper("succeed", changed=result["changed"])
```

Each step returns an object with `id`, `definitionSha256`, `check`, `apply`, and `timeoutSeconds`.
For example, the install step can call `install.py`, while each upgrade step calls `upgrade.py`
with an explicitly pinned destination release. Supply the relevant tools and integrity-verified
artifacts for every hop, not just those for the final release. Author each hop against its own
release's procedure. The numbers above represent minor releases; real commands need tested patch
versions as well.

The check must inspect the actual cluster and required health conditions. Exit 0 means the step's
effect is satisfied, including a healthy later version where appropriate. Exit 10 authorizes the
step's apply from the observed state; all other outcomes stop execution. A version comparison alone
does not prove health or that every node completed the transition. A step must finish the necessary
control-plane, worker, and add-on coordination before allowing the next minor upgrade. The local
helper lock cannot coordinate independent agents across a cluster.

## Failure, replay, and visibility

For `1.31 → 1.32 → 1.33 → 1.34 → 1.35`, a failure in the 1.33 step prevents 1.34 and 1.35 from
running. Completed external changes remain in place. The helper identifies the step and position in
its error and logs; the script must propagate failure rather than reporting deployment success.
After the deployment policy authorizes another invocation, inspect again and finish only work
whose preconditions are established. A process death after an external effect must not cause a
blind repeat. Mixed states need application-specific recovery or resumable logic.

The helper does not publish a live fleet upgrade plan. Applications can expose measured state via
the existing `--inspect` command; normal deployment results and attention holds retain their meaning.
Do not report the final target as healthy until every required hop and final health gate succeeds.

Budget the entrypoint timeout for the whole sequence plus planning. For longer operations, the
integration needs bounded work and reliable inspection under the existing replay/retry contract;
it must not let background work escape containment or treat a reboot request as a completed reboot.

Do not configure automatic recovery as a Kubernetes downgrade. Recovery must be an explicit,
tested application procedure; the platform cannot undo cluster or database changes by restoring an
old package. Keep manual recovery when the integration cannot establish a safe automatic action.

Test fresh install, adoption, every supported starting minor, already-current health and drift,
missing hops, invalid plans, failure and interruption at every external effect, observation failure,
safe continuation, lock contention, and deadlines. Runtime tests cover execution mechanics;
cluster integration tests must prove Kubernetes-specific safety.
