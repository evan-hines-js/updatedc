# Provider refactor — design notes & open items

The supervisor is a **rollout state machine with providers**: TUF delivery + a durable
update/rollback state machine that invokes operator providers at each phase. It manages no
process itself unless the built-in default (`stop-start`, guardian-owned) is chosen.

## Provider capabilities (all optional, mix per deployment)

- **Lifecycle** — operator scripts at each phase (preflight, prepare, pre-drain, drain, stop,
  activate, start, verify, finalize, rollback, pre-start). Does the actual work.
- **HealthCheck** — external CLI readiness signal (exit 0 = healthy); replaces the HTTP probe.
- **Process** — external CLI PID + roll-up oracle for a `custom` deployment: run it to learn the
  managed PID (exit 0 + PID on stdout) or to be told the process is gone and to perform the
  normal crash roll-up (non-zero exit). May be an exec wrapper or a systemd-unit watcher.

## Deployment shapes (`process` mode)

- `stop-start` (default): the guardian launches/owns the process; crash detection + adoption as
  today. Works in docker / as a supervisor. **The guardian keeps its PID management here.**
- `custom`: the operator's providers own the process. Only the **lifecycle** provider is
  required. The **process** and **health** providers are optional:
  - lifecycle + process + health → full: reload in place, watch the PID, gate on the health CLI.
  - lifecycle only → **the simplest deployment**: a single install/update script with pre/post
    drain hooks and *no process management at all*. No PID, no crash-watch; health falls back to
    the HTTP URL or surviving the grace window.

## Key rule (per user)

Grab the PID **after** the install/startup section — a custom deployment's process provider only
knows the running PID once its process is up (and it can change during install/startup, e.g. a
systemd `MainPID`). `resolve_pid` runs the provider live at each use so it always reflects the
current PID.

## Open items to review during hardening

- [ ] **Boot-launch rip-out for `custom`:** the guardian must NOT launch the app for a `custom`
      deployment (the process is external / provider-owned). Today's boot still routes through
      `launch_with_pre_start` → guardian launch. Need a boot path that runs pre-start, lets the
      lifecycle/process provider bring the process up, then resolves the PID from the process
      provider. `App` for `custom` holds the provider PID, not a guardian-launched one.
- [ ] **Boot-side roll-up detection for `custom`:** a steady-state `RollUp` returns Err (tears the
      tower down). The next boot must re-run the process provider and, if still `RollUp` + pending,
      revert — feeding the same path `service_exited` drives for a guardian-owned crash.
- [ ] **`resolve_pid(None, app)` for `custom` without a process provider** currently returns the
      guardian PID; once the boot rip-out lands, a process-less `custom` deployment has no PID and
      this should be `None`.
- [ ] Confirm `traffic_ready` policy for `custom` (currently a no-op; readiness rotation may need
      the guardian flip or be entirely operator-owned).
- [ ] Duplicate-code check: the per-tick health/process resolution in `run()` vs the transaction
      gate vs the boot gate — factor a single `resolve_pid` + health-decision helper if they drift.

## CI e2e coverage (in-k8s and out)

The reexec removal broke several CI e2e jobs beyond `cargo run -p e2e`. All fixed by the same
`reexec`→`custom` swap the cargo e2e used — each already ships a lifecycle provider that reloads
in place, so only the activation *value* changed (mode labels/providers unchanged):

- `cargo run -p e2e` — green (41/41), verified locally.
- `scripts/linux-haproxy-e2e.sh` — real HAProxy SIGUSR2 reload; `activation:"custom"` now.
  **Not verifiable locally (needs Linux + HAProxy); CI `linux-haproxy-e2e` verifies.**
- `scripts/macos-smoke.sh` / `macos-publish-fuzz.sh` — **removed** (script + CI job). It was a
  hand-rolled shell reimplementation of the e2e "Magnolia" lifecycle provider that had drifted from
  the product (activation enum, mTLS enrollment, the `pre-drain`/`pre-start` phases) and tested
  nothing the `cargo run -p e2e` suite doesn't already cover on the macOS runners (`macos-14` +
  `macos-15-intel`). Its only unique angle was a real launchd LaunchAgent, which we decided not to
  keep.
- `scripts/kind-updatec-e2e.sh` (k8s operator) + `updatec-demo` — use `stop-start`/`custom`, not
  reexec. Being run locally now to confirm; CI `updatec-e2e` + `updatec-demo-e2e`.
- `deploy/windows/test-scm-e2e.ps1` — `stop-start`, unaffected.

## Adversarial-review findings (loop)

- [x] **Dedup:** `run_healthcheck_command` and `run_process_provider` shared the resolve→spawn→
      bounded-wait machinery — factored into `run_provider_probe` (with a 64 KiB stdout read cap
      as light hardening). `run_lifecycle_command` kept separate: it needs distinct timeout-vs-
      exit-code error messages for operator debugging on the rollback path.
- [ ] **Dead code — `install_runs_activate` is always `false`** (both `Managed` and `Provided`),
      so `InstallProvider` / `DefaultInstallProvider::place()` are dead. First-install placement
      for a custom deployment should run in the `pre-start` hook (`reason=install`), which is
      reexec-compatible (an activate-at-install hook can't HUP a process that isn't up yet). Rip
      out the trait + impl + the `place()` call + the `install_runs_activate` trait method after
      confirming the e2e baseline is green.
- [ ] **`traffic_ready` for custom is a no-op** (preserved from old reexec) — a custom node never
      publishes readiness to the guardian, so a healthproxy-fronted custom deployment would sit
      out of rotation. Needs a decision: publish via the guardian from the health/process signal,
      or declare readiness operator-owned for custom.
- [ ] **Custom + process-provider incoherence:** the guardian still launches the app for custom
      (hybrid), so a custom deployment that *also* ships a process provider has two processes. Only
      resolved by the boot-launch rip-out (top of this list). No e2e exercises this yet.
- [ ] **`RollUp` during the pending window crash-loops (no revert yet):** a steady-state `RollUp`
      does `return Err` → guardian restarts the supervisor, but boot recovery reverts only on
      `service_exited`, which the guardian never sets for a custom process it didn't launch. So a
      genuinely-down custom process re-runs the same (possibly bad) release instead of reverting.
      Fix with the boot-side detection above: `gather_situation` runs the process provider and, on
      `RollUp` + pending, feeds the revert exactly as `service_exited` does. Ties into the
      boot-launch rip-out; no e2e exercises it, so the suite stays green meanwhile.
- [x] **Dead `install_runs_activate` / `InstallProvider` / `place()`** — ripped out. First-install
      placement now runs in the `pre-start` hook (`reason=install`), which is reexec-compatible.
- [x] **e2e harness gap:** the empty-`default` provider-set fallback overwrote a health-only
      deployment's published set (guarded on `lifecycle_command.is_none()`); now also guards on
      `health_command.is_none()`. Health-provider scenario passes.
- [x] **Process-provider stdout hang (hardened):** `run_provider_probe` read stdout with
      `read_to_string` (blocks until EOF). If the provider forks a daemon that inherits the pipe,
      EOF never arrives → wedge. Now reads only the first newline-terminated line (`read_first_line`,
      64 KiB cap). **Provider contract:** print the PID + newline promptly, fork-and-report (never
      exec-and-stay — the supervisor would time out and `kill_tree` the process it just launched),
      and don't hold the probe's stdout open. Documented on `ProviderCapability::Process`.
- [ ] **Chaos-recovery flakiness (pre-existing):** `crash at every {update,cold-install} boundary`
      occasionally fails with "initial health check" / "live=false" after recovery at a boundary
      (orphaned-process port, tight health grace under load). Passed on isolated re-run; not a
      regression (`run_lifecycle_command` untouched, `place()` removal is a no-op for stop-start).
      Candidate hardening (not test-weakening): reap the crashed app's process group before the
      recovery relaunch, or widen the recovery health grace. Investigate if it recurs.
- [ ] **Process-provider path is unexercised:** `run_process_provider` / `resolve_pid` / the
      steady-state `RollUp` crash-watch have no unit test and no e2e (a coherent custom+process
      scenario needs the boot-launch rip-out first). Well-formed but untested. Add a
      process-provider e2e once the boot rip-out lands; consider a focused unit test that stages a
      tiny process-provider bundle and asserts `Running`/`RollUp` parsing.
- [ ] **CRD enum regen:** `deploy/kubernetes/updatec.yaml`'s `activation` enum (if inlined) may
      still list removed variants after dropping `reexec`/`delegated` from `ActivationSpec`.
      Re-run the crdgen example and diff. (The operator also validates via serde, so this is
      cosmetic for the API surface.)
