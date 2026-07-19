# Provider = a forward entrypoint + a local rollback

## Scope (deliberately small)

We are **not** becoming a generic workflow engine. We are adding exactly what a risk-averse
enterprise upgrading machines needs, and nothing more:

- A provider is **just a directory with an entrypoint** — shell, PowerShell, whatever — that does
  anything the operator wants.
- It ships **two scripts**: the **forward entrypoint** (the deploy/upgrade action) and a
  **`rollback`** script (the local undo). Operators name the files whatever they like — e.g.
  `deploy.sh` and `rollback.sh` — and the manifest records the paths.
- The rollback is **co-located and local**. Undoing an upgrade needs **no control-plane contact** —
  the rollback script is already on disk in the same package. It can be **dropped on a box and run
  standalone**, exactly like today.
- We **keep the current hook points** (preflight → prepare → pre-drain → drain → stop → pre-start →
  activate → start → verify → finalize). The forward entrypoint is invoked at each, with
  `UPDATED_LIFECYCLE_PHASE` set, so it can branch. The **rollback** hook goes to the rollback script.

This is a **linear** sequence with a **local rollback** — no DAG, no distributed coordinator. Two
plainly-named scripts (do it / undo it) are the whole operator API.

## What does not change

- **The control plane still owns the rollout**, exactly as today: `UpdateGroup` / `UpdateGroupSet`
  pace it across the fleet. That machinery is mostly fine and stays.
- **TUF delivery, the crash-safe transaction, and boot-recovery rollback** are untouched. The
  rollback script is run *by* the existing rollback path; we only split *which script* the
  compensation invokes.
- Local, control-plane-optional operation stays a first-class mode.

## Three scripts, and how the process is managed

A provider bundle declares up to **three** scripts in its manifest — all verified (hash +
executable bit) like any other bundle file:

- **`entrypoint`** (required) — the forward action, invoked at every forward hook point.
- **`activate`** (optional) — the operator-owned process transition, invoked at the `Activate` hook.
- **`rollback`** (optional) — the local undo, invoked at the `Rollback` hook (falls back to
  `entrypoint` when absent).

**The `activate` script is how the operator decides process management.** The guardian *always
holds* the process (launch/adopt/crash-watch — so it runs in a container and in tests). What differs
is activation:

- **No `activate` script → restart.** The guardian stop-starts the process: it stops the running
  release and launches the candidate fresh. The default.
- **`activate` script present → reload in place.** The guardian does **not** stop-start; the
  `activate` script transitions the running process (a SIGHUP/exec/vendor reload) and is handed the
  guardian's live PID (`UPDATED_CHILD_PID`). Because the process keeps its launch token, readiness
  must **prove the version**, and the operator's drain/activate scripts own the drain.

There is **no signed process-mode flag** — reload-vs-restart is *derived from the artifact*: does the
lifecycle provider ship an `activate` script? This deleted the entire `ProcessMode` /
`ManagedActivation` config, the `ProcessProvider` trait, and the external process-provider oracle.

## Naming

The compensation is called **`rollback`** — the word operators already use, and the same word the
rest of the system uses (`LifecyclePhase::Rollback`, "roll back to the predecessor"). The forward
script keeps the generic name **`entrypoint`**, which is the shared manifest field an application
bundle also uses (an app's binary genuinely is its entrypoint); operators point it at a
descriptively-named file (`deploy.sh`, `upgrade.ps1`, …).

## Path forward (not now)

- Service-to-service **label connectors** for cross-tier rollout ordering — a control-plane concern,
  deferred.
- If a true multi-step or multi-machine flow is ever needed, it grows on top of the rollout
  machinery; the node stays a dumb executor of a directory with a forward entrypoint and a rollback.
