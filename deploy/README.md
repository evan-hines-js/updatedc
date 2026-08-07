# Deployment: supervised service adapters

An update hierarchy must terminate at an independently managed lifecycle owner. These
templates run the tiny, installer-owned **bootstrap guardian** under systemd, launchd,
or Windows SCM. A desktop product can provide the same start/relaunch/stop contract
through a login item or startup host. The guardian
owns both the replaceable **supervisor** and the managed application. The supervisor
selects releases and requests application lifecycle operations through the guardian,
but it is never the application's process parent.

```
  outer lifecycle owner ──manages──► bootstrap guardian
                                  ├──owns/readiness-gates──► supervisor
                                  └──owns──────────────────► application

               supervisor ──authenticated control requests──► guardian
               supervisor ──health probes───────────────────► application

  The guardian readiness-gates and pointer-commits supervisor replacements.
  The supervisor verifies and journal-updates the application through the guardian.
```

The verbs on the arrows are intentional. The outer lifecycle owner **manages** the
guardian's process lifecycle. The guardian **activates** supervisor releases: it
launches a staged candidate, waits for it to prove it can run, and either commits
its path or retains the previous pointer — but it never updates *itself*. The
supervisor **updates** the application through journaled immutable-bundle activation,
but asks the guardian to stop, start, or adopt that application. It also stages its own next
version for the guardian to activate. Supervisor releases use the reserved
`supervisor` product on the application's configured channel.

Ending the hierarchy at an independently updated lifecycle owner is the point. On a
service installation that owner is systemd, launchd, or SCM; on a desktop it can be a
login item or launcher. It starts and relaunches the bootstrap without participating in
release policy. The bootstrap is the one thing we ship that it
manages, and the bootstrap is small, network-unaware, and does so little that it
changes only with the installer — so the chain terminates without another
self-updating turtle.

### Why a bootstrap, and not supervisor self-replacement

A supervisor cannot safely replace its own running binary and prove the result:
if the new bytes cannot execute at all — corruption, a missing runtime, an ABI
break, an immediate pre-`main` crash — there is no working supervisor left to roll
back. The bootstrap is an *external* observer with one durable
`desired-supervisor` pointer. Verified candidates are staged under
`supervisors/<content-id>/`; the bootstrap launches a candidate with a one-time
readiness token and timeout. The candidate proves itself after it initializes and
re-adopts the application. On proof the bootstrap atomically advances the pointer;
otherwise it records the candidate path for rejection and relaunches the previous
supervisor. The supervisor skips rejected hashes, so a bad release cannot loop.
Every candidate gets a fresh path, so a running executable is never overwritten—
including on Windows, where replacing a running image is forbidden.

### A supervisor restart never disrupts the application

The supervisor is not on the data path and is not the application's process parent.
The guardian keeps the application alive across supervisor crashes and replacements,
then lets the replacement supervisor adopt the existing PID through the authenticated
control channel. If the guardian stops, it stops both children. Neither the supervisor
nor the application outlives its permanent guardian.

### Terminology invariant

In this documentation, **owns** means OS process parent and lifetime boundary,
**manages** means outer process lifecycle (start, stop, restart),
**activates** means launch-a-candidate-and-commit-or-roll-back, and **updates**
means release installation, verification, commit, and rollback. Do not describe an
outer lifecycle owner as updating anything: it manages the bootstrap. Do not describe the
supervisor as owning the application: it requests lifecycle operations from the
guardian. Do not describe the application as "self-updating": the supervisor owns
that transaction. The one component whose replacement is gated by proof-of-execution
is the supervisor, and
the guardian — not the outer lifecycle owner, and not the supervisor itself — performs
that activation.

## Layout assumed by the templates

| Path | Contents |
| --- | --- |
| `/usr/lib/updated/bootstrap` (Linux), `/etc/updated/bootstrap` (macOS) | Installer-owned `bootstrap` — the root we ship; never self-updates, read-only |
| `/etc/updated/bootstrap.toml` (Windows: `C:\Program Files\updated\bootstrap.toml`) | Read-only enrollment bootstrap: the HTTPS enrollment URL, this node's self-asserted name, and the paths to the fleet client certificate, its key, and the fleet CA. Enrollment is mutual TLS, so this file holds no secret. The **canonical** config location — `control::DEFAULT_BOOTSTRAP_CONFIG`, which the bootstrap reads with no argument. Not a per-deployment choice: a co-resident process that must learn which fleet node it runs on looks exactly here. |
| `/var/lib/updated/` (Linux), `/usr/local/var/updated/` (macOS) | Writable guardian state, the consumed signed enrollment bundle, supervisor candidates, application state, and TUF caches |

Because supervisor candidates and immutable application bundles are updated, they live
in writable state directories. The two things that must never be forged — the
bootstrap and bootstrap config — stay read-only. Enrollment supplies the pinned TUF root;
a leaked or misused role key still cannot make a client run unsigned content.

The installer always places the bootstrap and initial supervisor and passes the latter
with `bootstrap --supervisor`; the bootstrap seeds its durable supervisor pointer on
first launch. For offline-first installation against a remote gateway it also preplaces
the exported signed `enrollment.json`, the node's already-minted `agent.crt`/`agent.key`,
and the verified initial application bundle. For online-first installation it places the
enrollment bootstrap file and the supervisor mints its per-node identity and cold-installs
the first trusted assignment. Both paths converge on the same durable layout and
transaction.

**Offline-capable, fail-closed first start.** If signed installer material is present,
the supervisor verifies every manifested file before launch and refuses missing,
corrupt, or drifted state; it never synthesizes trust from loose executable bytes. No
network is required to launch that verified active bundle. Without installer material,
network enrollment and cold installation are allowed but must complete before any
application launches.

## Linux (systemd)

```sh
install -m0644 systemd/updated-supervisor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now updated-supervisor
journalctl -u updated-supervisor -f      # watch bootstrap + supervisor + app
```

Install `bootstrap.toml` read-only at the canonical path:
`install -m0644 bootstrap.toml /etc/updated/bootstrap.toml`. No template passes
`--supervisor-config` — the bootstrap defaults to that path. Pass the flag only for a
deployment that deliberately keeps the config elsewhere.

The templates enable the guardian probe listener on loopback port 9090. `/readyz`
withdraws before a planned stop while `/livez` remains successful; an application crash
or sustained signed liveness-check failure makes `/livez` fail until the outer lifecycle
owner replaces the tower. `/startupz` latches after the first accepted application. Bind
to `0.0.0.0` only inside a container network namespace where the runtime must reach it.

**Updating the supervisor:** publish a signed supervisor release on its channel;
the running supervisor stages it under `supervisors/<content-id>/` and exits, and the
bootstrap activates it under the readiness gate.

## macOS (launchd)

```sh
sudo cp launchd/com.example.updated-supervisor.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.example.updated-supervisor.plist
```

## Windows (Service Control Manager)

The bootstrap remains a small console program, while the repository ships a native
`selfupdate-service.exe` SCM host (`crates/windows-service`). The wrapper provides
the Windows equivalents of systemd `Restart=always` plus a restricted `User=`:

1. **Restart on exit** — relaunch the bootstrap whenever it exits, so a crash of the
   root is recovered. A guardian exit also ends its application; the new guardian
   launches the committed application again.
2. **Graceful, isolated stop** — launch the bootstrap as a new console process group
   and deliver CTRL_BREAK to that group on service stop. The supervisor launches the
   application in a separate group; the bootstrap coordinates its shutdown.
3. **A restricted service account** — run as a per-service virtual account, NOT
   LocalSystem, so a leaked or misused role key cannot become SYSTEM code execution.

Build `selfupdate-service.exe` for Windows and install it alongside the bootstrap.
The full native SCM registration and ACL configuration is
[`windows/install-updated-supervisor.bat`](windows/install-updated-supervisor.bat);
edit the paths at its top, then run it from an elevated prompt:

```bat
:: from an Administrator command prompt
windows\install-updated-supervisor.bat
```

The template runs under the restricted `NT SERVICE\SelfUpdateSupervisor` virtual
account and grants write access only to the state directory. Both wrapper and
bootstrap are installer-owned, read-only, and deliberately updated out of band.

The application inherits this same account, so this bounds the whole tower against
the host but is not a sandbox between the updater and the application — the app runs
at the updater account's privilege. A product needing that boundary must provision a
separate OS identity or sandbox and a platform-specific launch/control bridge, which
this reference supervisor deliberately leaves out.

The bootstrap binary itself is installer-owned and read-only (place it under
`C:\Program Files\updated`). Because supervisor candidates and immutable application
bundles update in writable storage, place the bootstrap state directory
(`C:\ProgramData\updated`) where the service account can write and grant it write access to only that
(`icacls ... /grant "NT SERVICE\SelfUpdateSupervisor:(OI)(CI)M"`). Keep the pinned
TUF root administrator-owned and read-only. This mirrors the systemd
`User=updated` + `ReadWritePaths=` and launchd `UserName=_updated` templates.

The initial supervisor path is passed directly; its own version is baked into that
executable at build time. The installer must seed the exact initial bundle identity and
must never synthesize a trusted baseline from loose files.
