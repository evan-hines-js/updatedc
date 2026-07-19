# Demo readiness-watch — adversarial review findings

Scope: the readiness-watch / rollback-detection change in `crates/updatec-demo` (plus the
`updated-healthproxy` logging), and adjacent smells found while reviewing it. Items marked
**FIXED** were changed in place; the rest are open for discussion.

## Fixed

- **FIXED — RBAC gap silently re-broke the rollout.** The `updatec-demo` Role granted pods
  `get,list,delete,patch` but not `watch`. `spawn_readiness_watcher` uses `kube::runtime::watcher`,
  which needs `watch`; without it the stream 403s in a tight reconnect loop, `left_lb`/`readiness`
  never populate, and broken cohorts never satisfy `attempted` — i.e. the exact stuck-rollout the
  watch was meant to cure. Added `watch` to the pods rule (`setup.rs`) and patched the live Role.
- **FIXED — chaos shelled out to a `kubectl` the image doesn't ship.** `inject_chaos` and
  `crash_controller` ran `kubectl delete pod …`, but the demo image installs no `kubectl` (only
  `bootstrap, supervisor, server, sampleapp, updatec-demo, demo-lifecycle, updated-healthproxy,
  updatectl, magnolia-like`). Every SIGKILL/controller-crash silently failed with `No such file or
  directory` (the same reason the pod labeler was already ported). Converted both to the kube API
  (`pods.delete` / `pods.delete_collection`).
- **FIXED — UI "in LB" now comes from the watch, not per-node curls.** `fleet()` and
  `ready_endpoints()` previously fanned out a `:9090/readyz` curl per agent every refresh; they now
  read the watch-maintained `Demo::readiness` map, so the UI's IN/OUT and the synthetic load
  balancer's pool reflect the same `Ready` condition Kubernetes routes the per-set Services on, with
  no probe storm and no poll blind spot. Removed the now-dead `probe_failure` helper.
- **FIXED — watcher relist could strand a vanished pod as IN.** The stream is consumed as raw
  `Event`s with the standard informer pattern: buffer `Init → InitApply* → InitDone` into a fresh
  snapshot and swap it in atomically, so a pod deleted during a watch gap drops out of the map
  instead of lingering `Ready`.

## Open — needs discussion

- **`readyz_probe_millis` is now always `0`.** The watch carries no probe timing, so the UI tooltip
  renders `readyz 0ms`. Options: drop the field, or relabel it as the readiness source
  (`page.rs` shows `readyz ${node.readyzProbeMillis}ms`). Cosmetic, but currently misleading.
- **Magnolia / manual-VM readiness.** Pod `Ready` (kubelet probe on guardian `:9090`) is the only
  signal now. Per the plan, app-level Magnolia probing would move to a dedicated sidecar container;
  the manual VM (`magnolia-manual-vm`) is not pod-backed and now always reads OUT (no curl
  fallback). Acceptable while the VM path is unfinished — flag when it lands.
- **Premature-settle window on a spurious blip.** A broken cohort settles on `attempted` (seen out
  of the pool this generation) AND `held` (all nodes healthy, in-LB, version major < bad). At
  generation start nodes sit at baseline == `bad-1`, so `held` is already true; a single spurious
  `NotReady` (readinessProbe `failureThreshold: 1`) before the real bad-release attempt could
  satisfy `attempted` and settle the cohort before it ever tries the bad version. Low probability
  (the real drain follows within seconds), but consider gating on the node having actually consumed
  the bad assignment (`published_digest`) before crediting the drain.
- **`readyz_failing_since` debounce is now largely redundant.** `fleet_for_ui` keeps a node IN for
  ~2s after it first reads OUT, to smooth a single missed poll. The kubelet already debounces via
  the probe's `failureThreshold`, and the watch reflects that settled state, so this second layer
  mostly just delays showing a genuine drain. Consider removing it.
- **Pre-existing clippy (not from this change):** trailing `return Err(...)` in `run_generation`;
  "too many arguments" on `updatec` `runtime.rs` and `setup.rs::apply_demo_resources`. Cheap to
  clean up if we want a warning-free `cargo clippy`.
