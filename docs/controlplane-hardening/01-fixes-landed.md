# 1. Fixes landed — runtime config must follow the live assignment

**Status: implemented, unit-tested, and validated end-to-end. Uncommitted in the working tree.**

## Symptom

`cargo run -p updatec-demo -- e2e --exit` stalled at fleet convergence:

```
[demo] waiting for fleet API convergence (16/32 exact)   # forever
Error: "fleet did not converge at 22.0.0: ... lagging [agent-0=…version:1.0.0…, agent-1…]"
```

Exactly the 16 **reload/reexec** cohorts (even sets: agents 0–3, 8–11, 16–19, 24–27) were stuck
at 1.0.0; the 16 **restart** cohorts converged fine.

## Root cause — two sources of truth for runtime config

The control-plane refactor (the last two commits before this work) split the node's runtime
configuration across two sources:

- **Version + provider-set** came from the **live routing assignment**, re-resolved every loop
  cycle (`TrustedRepository::assigned`) and persisted to
  `<install_root>/state/repository-assignment.json`.
- **`args`, health checks, timeouts, storage** came from the assignment **frozen into the
  enrollment bundle** at enrollment time (`verify_embedded_assignment` in
  `crates/updated-tuf/src/lib.rs`, consumed by `resolve_managed_config`).

A node enrolls into the `edge` group (args `--addr 0.0.0.0:8080`), cold-installs, then the demo
relabels it into `demo-cohort-NN`, whose deployment adds `--reload-mode reexec`. The **version
followed** the reassignment (→ 22.0.0, reload provider set), but the **launch args did not** —
they stayed frozen at the enrollment value. So the reload cohort's app launched in `mode restart`,
ignored the reload SIGHUP the `activate` hook sent, never became 22.0.0, and rolled back.

Evidence: agent-0's on-disk `repository-assignment.json` carried the **correct** args
(`--reload-mode reexec`), but the running process was launched with only `--addr 0.0.0.0:8080`.
Exactly half the fleet (the reload cohorts) hung → 16/32.

This is a general defect, not demo-specific: **any** control-plane reassignment that changes
runtime (health-check URLs, timeouts, args) was silently dropped once the node was enrolled.

## The fix — collapse onto the one live source

Five changes, all toward "the live assignment is the single source of truth."

### Supervisor (the core fix)

1. `crates/updated/src/config.rs` — factored `ManagedRuntime → Application / Timeouts / Storage`
   into shared constructor methods (`.application()`, `.timeouts()`, `.storage()`), used by both
   `materialize()` and the new reconciliation. One construction path.

2. `crates/supervisor/src/main.rs`:
   - `Options::apply_runtime(&ManagedRuntime) -> bool` — reconciles the runtime from the live
     assignment each loop cycle; returns whether the **launch spec** (args) changed.
   - In the update loop, after `TrustedRepository::assigned`, apply it. If the launch spec
     changed, **stop-start the app** to apply the new args (a live process's argv can't be
     rewritten in place). This is the only way a node moved into a reexec cohort starts honoring
     the reload signal — otherwise the in-place reload upgrade silently no-ops and rolls back.
   - `readiness_url` / `liveness_url` changed from borrowed `&str` to owned `Option<String>` so
     `opts` can be mutated; `run(mut opts: Options)`; `health_probe` built unconditionally.

3. `crates/updated-tuf/src/lib.rs` — `resolve_managed_config` now **seeds runtime from the
   persisted live assignment** (`persisted_assignment(<install_root>/state/…)`) when present,
   falling back to the embedded enrollment assignment only on first boot. This stops a supervisor
   restart from reverting to the frozen args and doing a spurious stop-start — which would turn a
   zero-downtime reexec-rejection into an outage.

### Demo binary consistency (exposed by the fix)

The supervisor fix made the reexec args actually reach the app — which then exposed that some
demo app bundles were the **plain** `sampleapp` (not reexec-capable), so a reload cohort couldn't
reexec into them. The kind world should use one universal binary (`sampleapp-reexec`; it reports
the same `sampleapp` identity and behaves identically in default `restart` mode):

4. `crates/updatec/e2e/release-server.sh` — the `edge` baseline app: `sampleapp` → `sampleapp-reexec`.
5. `crates/updatec-demo/src/demo.rs` — `build_release_source` (the chaos publisher for versions
   101.0.0, etc.): `sampleapp` → `sampleapp-reexec`. Without this the fleet-chaos convergence
   phase can never settle a reload cohort onto a chaos-published version.

The deliberately-`broken` release path (corrupt entrypoint → `ENOEXEC` on reexec) is left as-is —
that is the intended zero-downtime *rejection* test, and it works: the old process keeps serving,
the candidate is rejected, the node rolls back.

## Validation

- All affected unit tests pass (supervisor, updated, updated-tuf, updatec-demo).
- Live `e2e --exit`: reached `all 32 cohort members are healthy at 22.0.0`. agent-0 (reload
  cohort) log shows the money shot — a genuine same-PID reexec:
  ```
  assignment runtime changed the launch spec; relaunching the application to apply it
  sampleapp 1.0.0 listening on http://0.0.0.0:8080 (pid 129, mode reexec)
  sampleapp 22.0.0 listening on http://0.0.0.0:8080 (pid 129, mode reexec)
  upgraded to 22.0.0 (pid 129)
  ```
- The run then failed **later**, at the HAProxy zero-downtime SLA — a **separate** issue (doc 2),
  not caused by these changes (the HAProxy nodes reexec via their own SIGUSR2 with no reconciliation
  relaunch).

## Files touched (uncommitted)

```
crates/updated/src/config.rs          # ManagedRuntime constructors + materialize refactor
crates/supervisor/src/main.rs         # apply_runtime + loop reconciliation + relaunch-on-drift
crates/updated-tuf/src/lib.rs         # resolve_managed_config seeds from persisted live assignment
crates/updatec-demo/src/demo.rs       # chaos publisher uses sampleapp-reexec
crates/updatec/e2e/release-server.sh  # edge baseline uses sampleapp-reexec
```

These are safe to commit independently of the larger refactor (docs 3–5). Recommended: land them
first so the convergence fix is durable before the control-plane work begins.
