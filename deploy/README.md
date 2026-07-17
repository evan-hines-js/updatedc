# Deployment: running the bootstrap under the OS init system

An update hierarchy must terminate somewhere. These templates run the tiny,
installer-owned **bootstrap guardian** under the host's init system. The guardian
owns both the replaceable **supervisor** and the managed application. The supervisor
selects releases and requests application lifecycle operations through the guardian,
but it is never the application's process parent.

```
  init system ──manages──► bootstrap guardian
                                  ├──owns/readiness-gates──► supervisor
                                  └──owns──────────────────► application

               supervisor ──authenticated control requests──► guardian
               supervisor ──health probes───────────────────► application

  The guardian readiness-gates and pointer-commits supervisor replacements.
  The supervisor verifies and journal-updates the application through the guardian.
```

The verbs on the arrows are intentional. The init system **manages** the
guardian's process lifecycle. The guardian **activates** supervisor releases: it
launches a staged candidate, waits for it to prove it can run, and either commits
its path or retains the previous pointer — but it never updates *itself*. The
supervisor **updates** the application with an in-place, journaled swap, but asks the
guardian to stop, start, or adopt that application. It also stages its own next
version for the guardian to activate. Supervisor releases use the reserved
`supervisor` product on the application's configured channel.

Ending the hierarchy at the init system (systemd / launchd / SCM) is the whole
point: it is present on every target, restarts a process that exits, and is updated
by the OS vendor — a real root. The bootstrap is the one thing we ship that it
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
**manages** means init-system process lifecycle (start, stop, restart),
**activates** means launch-a-candidate-and-commit-or-roll-back, and **updates**
means release installation, verification, commit, and rollback. Do not describe an
init system as updating anything: it manages the bootstrap. Do not describe the
supervisor as owning the application: it requests lifecycle operations from the
guardian. Do not describe the application as "self-updating": the supervisor owns
that transaction. The one component whose replacement is gated by proof-of-execution
is the supervisor, and
the guardian — not the init system, and not the supervisor itself — performs that
swap.

## Layout assumed by the templates

| Path | Contents |
| --- | --- |
| `/usr/lib/selfupdate/bootstrap` (Linux), `/etc/selfupdate/bootstrap` (macOS) | Installer-owned `bootstrap` — the root we ship; never self-updates, read-only |
| `/etc/selfupdate/root.json` | Installer-pinned TUF root — the anchor of trust, read-only |
| `/var/lib/selfupdate/` (Linux), `/usr/local/var/selfupdate/` (macOS) | Writable guardian state: `desired-supervisor`, crash/rejection markers, and content-addressed `supervisors/` candidates; application state and the TUF cache live beside paths selected in `config.toml` |

Because supervisor candidates and immutable application bundles self-update, they live
in writable state directories. The two things that must never be forged — the
bootstrap and the pinned TUF root — stay read-only. A leaked or misused role key
still cannot make a client run anything the pinned root's roles did not sign.

The installer places the initial supervisor, pins the TUF root, and stages a verified
initial application bundle into `application.install_root`, including `active-release`
and `state/installed.json`. It passes the initial supervisor with
`bootstrap --supervisor`; the bootstrap seeds its durable supervisor pointer on first
launch. After that the system is self-sustaining.

**Offline-capable, fail-closed first start.** The supervisor requires the installer-seeded
release, strict installed record, and active pointer. It verifies every manifested file
before launch and refuses missing, corrupt, or drifted state; it never synthesizes trust
from loose executable bytes. No network is required to launch the verified active bundle.

## Linux (systemd)

```sh
install -m0644 systemd/selfupdate-supervisor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now selfupdate-supervisor
journalctl -u selfupdate-supervisor -f      # watch bootstrap + supervisor + app
```

Install `config.toml` read-only alongside the pinned root:
`install -m0644 config.toml /etc/selfupdate/config.toml` (substitute the version
version and digest tokens first).

**Updating the supervisor:** publish a signed supervisor release on its channel;
the running supervisor stages it under `supervisors/<content-id>/` and exits, and the
bootstrap activates it under the readiness gate.

## macOS (launchd)

```sh
sudo cp launchd/com.example.selfupdate-supervisor.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.example.selfupdate-supervisor.plist
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
[`windows/install-selfupdate-supervisor.bat`](windows/install-selfupdate-supervisor.bat);
edit the paths at its top, then run it from an elevated prompt:

```bat
:: from an Administrator command prompt
windows\install-selfupdate-supervisor.bat
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
`C:\Program Files\selfupdate`). Because supervisor candidates and the application
binary self-update, place the bootstrap state directory (`C:\ProgramData\selfupdate`) where the
service account can write and grant it write access to only that
(`icacls ... /grant "NT SERVICE\SelfUpdateSupervisor:(OI)(CI)M"`). Keep the pinned
TUF root administrator-owned and read-only. This mirrors the systemd
`User=selfupdate` + `ReadWritePaths=` and launchd `UserName=_selfupdate` templates.

Replace `APPLICATION_VERSION` with the exact semver of the application the installer
packaged. The initial supervisor path is passed directly; its own version is baked
into that executable at build time. Never default the trusted application baseline
to `0.0.0`.
