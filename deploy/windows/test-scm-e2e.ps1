# Requires an elevated PowerShell. Exercises the native SCM host with the current bundle-only
# installation model: SCM -> wrapper -> launcher -> agent, a real signed PowerShell reconciler that
# the agent invokes to converge the release, a clean service stop, and a fresh launch of the
# committed bundle.
#
# SCOPE, deliberately: this drives the launcher + agent lifecycle and one full reconciler converge.
# It does NOT have the reconciler start a workload process. The property that matters here is
# ownership, and it is asserted directly: an SCM stop must cleanly end the tree the service owns —
# the wrapper, the launcher and the agent — and a workload is provably not part of that tree,
# because the agent never launches, holds, or stops one. What runs the workload is the operator's
# own mechanism, driven from the reconciler (`sc.exe`, a container runtime, a config reload); a
# reconciler that instead forks a workload directly must create it with CREATE_BREAKAWAY_FROM_JOB,
# which the agent's job object permits, so that the workload leaves the hook's disposable tree.
# Driving the service manager is the shape this test's reconciler stands in for — that is scope,
# not a platform limitation.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$service = 'SelfUpdateAgent'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
# Runtime state must never live below Cargo's cached target directory. Restoring that directory
# can otherwise turn this cold-install test into a restart while still leaving the binary build
# cache perfectly valid. The service runs as LocalSystem, so its fixture belongs under the same
# machine-wide ProgramData boundary as a real installation—not the interactive runner's private
# user-profile temp directory. A unique child still makes "empty node" true by construction.
$machineData = [System.Environment]::GetFolderPath(
    [System.Environment+SpecialFolder]::CommonApplicationData
)
$work = Join-Path $machineData "updated-scm-e2e-$([Guid]::NewGuid().ToString('N'))"
$routingRepo = Join-Path $work 'routing-repo'
$routingKeys = Join-Path $work 'routing-keys'
$releaseRepo = Join-Path $work 'release-repo'
$releaseKeys = Join-Path $work 'release-keys'
$certs = Join-Path $work 'certs'
$launcherState = Join-Path $work 'launcher-state'
$install = Join-Path $work 'install'
$bundle = Join-Path $work 'bundle-1.0.0'
$providerSource = Join-Path $work 'reconciler-source'
$receipts = Join-Path $work 'reconciler-operations'
$config = Join-Path $work 'config.toml'
$runtime = Join-Path $work 'runtime.json'
$repoPort = 21980
$objectPort = 21981
$gatewayProcess = $null
$objectProcess = $null

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'SCM service creation requires an elevated PowerShell.'
}

function Wait-ServiceState([string]$wanted, [int]$seconds = 30) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status.ToString() -eq $wanted) { return }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    throw "service did not reach $wanted within ${seconds}s"
}

function Wait-ServiceDeleted([int]$seconds = 30) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        if (-not (Get-Service -Name $service -ErrorAction SilentlyContinue)) { return }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    throw "service was still registered ${seconds}s after deletion"
}

# The reconciler's recorded history: one immutable file per invocation, containing
# `operation<TAB>attempt-id<TAB>reason`. A shared append-only file makes the hook's write race the
# harness's polling reads on Windows; publish a complete uniquely named receipt instead.
function Read-Operations() {
    if (-not (Test-Path $receipts)) { return @() }
    return @(Get-ChildItem -LiteralPath $receipts -Filter '*.log' | Sort-Object Name |
        ForEach-Object { [IO.File]::ReadAllText($_.FullName) })
}

function Wait-Operation(
    [string]$operation,
    [string]$reason = '',
    [int]$after = 0,
    [int]$seconds = 15
) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        $match = Read-Operations | Select-Object -Skip $after | Where-Object {
            $fields = $_ -split "`t"
            $fields[0] -eq $operation -and (-not $reason -or $fields[2] -eq $reason)
        } | Select-Object -Last 1
        if ($match) { return $match }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    $suffix = if ($reason) { " with reason '$reason'" } else { '' }
    throw "the agent never invoked the reconciler's $operation operation$suffix"
}

# A hook receipt proves invocation, not completion. The agent only owns a release durably once the
# hook result has passed the boot gate and installed.json has been atomically promoted to a
# confirmed head. Waiting on that state is the single completion barrier before exercising SCM
# stop/restart; otherwise the test can kill the agent between the healthcheck receipt and commit.
# This fixture has a four-second health grace and an immediate health hook. The agent enforces that
# grace on the hook process itself. The outer 45-second deadline also covers the separately bounded
# initial apply plus service startup before producing diagnostics for a broken first boot.
function Wait-ConfirmedInstall([string]$version, [int]$seconds = 45) {
    $path = Join-Path $install 'state\installed.json'
    $deadline = (Get-Date).AddSeconds($seconds)
    $lastJson = '<missing>'
    $lastReadError = '<none>'
    do {
        if (Test-Path -LiteralPath $path) {
            try {
                # The agent promotes this record with atomic replacement. Open with delete sharing
                # so observing the barrier can never prevent the very transition being observed.
                $stream = [IO.File]::Open(
                    $path,
                    [IO.FileMode]::Open,
                    [IO.FileAccess]::Read,
                    ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                )
                try {
                    $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true, 4096, $true)
                    try { $json = $reader.ReadToEnd() } finally { $reader.Dispose() }
                } finally {
                    $stream.Dispose()
                }
                $lastJson = $json
                $lastReadError = '<none>'
                $state = $json | ConvertFrom-Json
                if ($state.release.version -eq $version -and
                    $state.confirmed -eq $true -and
                    $null -eq $state.pending) {
                    return $state
                }
            } catch {
                # The state writer uses atomic replacement. A sharing violation from an antivirus
                # or indexer is transient and remains bounded by the same completion deadline.
                $lastReadError = $_.Exception.Message
            }
        }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)

    # The service's stdout is not attached to Actions. Make a timeout identify which boundary was
    # missed without changing the lifecycle timing: hook history distinguishes a missing health
    # gate from a failed durable commit, while the last raw record exposes parse/sharing failures.
    $installedService = Get-CimInstance Win32_Service -Filter "Name='$service'" -ErrorAction SilentlyContinue
    $serviceState = if ($installedService) {
        "$($installedService.State), pid=$($installedService.ProcessId), exit=$($installedService.ExitCode)"
    } else {
        '<missing>'
    }
    $tree = @(Get-TreeProcessDetails)
    $operations = @(Read-Operations)
    $launcherLog = Join-Path $launcherState 'launcher.log'
    $reconciliationPath = Join-Path $install 'state\reconciliation.json'
    $lastReconciliation = if (Test-Path -LiteralPath $reconciliationPath) {
        try { [IO.File]::ReadAllText($reconciliationPath) }
        catch { "<unreadable: $($_.Exception.Message)>" }
    } else {
        '<missing>'
    }
    throw "release $version never reached a confirmed installed state; service=[$serviceState]; " +
        "process-tree=[$($tree -join ' | ')]; operations=[$($operations -join ' | ')]; " +
        "installed.json=[$lastJson]; last-read-error=[$lastReadError]; " +
        "reconciliation.json=[$lastReconciliation]; " +
        "launcher-log=[$launcherLog]"
}

function Get-TreeProcessIds() {
    $ids = @()
    foreach ($name in @('updated-launcher', 'updated-agent', 'selfupdate-service')) {
        $ids += (Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
    }
    return $ids
}

function Get-TreeProcessDetails() {
    # Every process under the service host, not only the three binaries this test owns: a
    # reconciler hook (powershell.exe) that never returned is the interesting one, and its threads'
    # wait reasons say whether it is suspended, blocked on the console, or still starting up.
    $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $tree = @()
    $frontier = @($all | Where-Object { $_.Name -eq 'selfupdate-service.exe' } | ForEach-Object { $_.ProcessId })
    while ($frontier.Count -gt 0) {
        $tree += $frontier
        $frontier = @($all |
            Where-Object { $frontier -contains $_.ParentProcessId -and $tree -notcontains $_.ProcessId } |
            ForEach-Object { $_.ProcessId })
    }
    return @($all | Where-Object { $tree -contains $_.ProcessId } | Sort-Object CreationDate | ForEach-Object {
        $threads = '<gone>'
        $live = Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
        if ($live) {
            $threads = @($live.Threads | ForEach-Object {
                try { "$($_.ThreadState)/$($_.WaitReason)" } catch { "$($_.ThreadState)" }
            }) -join ','
        }
        $command = if ($_.CommandLine) { $_.CommandLine } else { '' }
        if ($command.Length -gt 200) { $command = $command.Substring(0, 200) + '...' }
        $started = if ($_.CreationDate) { $_.CreationDate.ToString('HH:mm:ss') } else { '?' }
        "$($_.Name):pid=$($_.ProcessId),parent=$($_.ParentProcessId),started=$started,threads=[$threads],cmd=[$command]"
    })
}

function Wait-ProcessExit([int[]]$ids, [int]$seconds = 30) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        $alive = $ids | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue }
        if (-not $alive) { return }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    throw "the service tree left processes running after a clean stop: $($alive -join ', ')"
}

function Read-DesiredAgent() {
    $pointer = Join-Path $launcherState 'desired-agent'
    $lines = [IO.File]::ReadAllLines($pointer)
    if ($lines.Count -ne 2 -or $lines[0] -ne 'agent-v1' -or -not $lines[1]) {
        throw "invalid desired-agent pointer: $($lines -join ' | ')"
    }
    return [IO.Path]::GetFullPath($lines[1])
}

try {
    $existingService = Get-Service -Name $service -ErrorAction SilentlyContinue
    if ($existingService) {
        if ($existingService.Status.ToString() -ne 'Stopped') {
            & sc.exe stop $service 2>$null | Out-Null
            Wait-ServiceState 'Stopped'
        }
        & sc.exe delete $service 2>$null | Out-Null
        if ($LASTEXITCODE) { throw "deleting the previous service failed with exit code $LASTEXITCODE" }
        Wait-ServiceDeleted
    }
    New-Item -ItemType Directory -Force $work | Out-Null
    New-Item -ItemType Directory -Force $launcherState | Out-Null
    New-Item -ItemType Directory -Force (Join-Path $bundle 'bin') | Out-Null
    New-Item -ItemType Directory -Force (Join-Path $bundle 'config') | Out-Null
    New-Item -ItemType Directory -Force (Join-Path $providerSource 'bin') | Out-Null
    New-Item -ItemType Directory -Force $receipts | Out-Null

    Push-Location $root
    try {
        & cargo build --release -p server -p launcher -p agent -p windows-service -p sampleapp
        if ($LASTEXITCODE) { throw 'building SCM test binaries failed' }
    } finally {
        Pop-Location
    }

    $bin = Join-Path $root 'target\release'
    Copy-Item (Join-Path $bin 'sampleapp.exe') (Join-Path $bundle 'bin\app.exe')
    [IO.File]::WriteAllText(
        (Join-Path $bundle 'config\release.toml'),
        "version = `"1.0.0`"`n",
        [Text.UTF8Encoding]::new($false)
    )
    $initialAgent = Join-Path $work 'updated-agent.exe'
    Copy-Item (Join-Path $bin 'updated-agent.exe') $initialAgent

    # The release's own node reconciler: an ordinary PowerShell script, which is the whole point of
    # the protocol. It records every invocation and converges nothing further, standing in for the
    # `sc.exe`/config-reload work an operator's script does here.
    $reconcilerText = @"
[CmdletBinding()] param([Parameter(ValueFromRemainingArguments = `$true)] [string[]] `$rest)
`$ErrorActionPreference = 'Stop'
`$operation = `$rest[0]
function Value([string] `$name) {
    for (`$i = 0; `$i -lt `$rest.Count - 1; `$i++) { if (`$rest[`$i] -eq `$name) { return `$rest[`$i + 1] } }
    return ''
}
if ((Value '--protocol') -ne '1') { exit 2 }
`$line = "`$operation`t`$(Value '--attempt-id')`t`$(Value '--reason')`t`$(Value '--candidate-version')"
`$token = "`$([DateTime]::UtcNow.Ticks)-`$([Guid]::NewGuid().ToString('N'))"
`$pendingReceipt = Join-Path '$receipts' "`$token.tmp"
`$completeReceipt = Join-Path '$receipts' "`$token.log"
[IO.File]::WriteAllText(`$pendingReceipt, `$line, [Text.UTF8Encoding]::new(`$false))
Move-Item -LiteralPath `$pendingReceipt -Destination `$completeReceipt
if (`$operation -eq 'inspect') { Write-Output "candidate-version=`$(Value '--candidate-version')" }
if (`$operation -eq 'apply' -or `$operation -eq 'rollback') {
    [IO.File]::WriteAllText(
        (Value '--result-file'),
        '{"schema":1,"status":"succeeded","changed":true,"hostAction":"none","message":null}',
        [Text.UTF8Encoding]::new(`$false)
    )
}
exit 0
"@
    [IO.File]::WriteAllText(
        (Join-Path $providerSource 'bin\reconciler.ps1'),
        $reconcilerText,
        [Text.UTF8Encoding]::new($false)
    )

    & (Join-Path $bin 'server.exe') init --repo $routingRepo --keys $routingKeys
    if ($LASTEXITCODE) { throw 'routing repository initialization failed' }
    & (Join-Path $bin 'server.exe') init --repo $releaseRepo --keys $releaseKeys
    if ($LASTEXITCODE) { throw 'release repository initialization failed' }
    # One TLS hierarchy covers two origins with distinct duties: routing authenticates the node
    # before minting an exact bearer; the release origin never receives the node identity.
    & (Join-Path $bin 'server.exe') gen-certs --dir $certs --san 127.0.0.1 --san localhost
    if ($LASTEXITCODE) { throw 'minting the fleet mTLS material failed' }
    & (Join-Path $bin 'server.exe') publish-app --repo $releaseRepo --keys $releaseKeys --product app `
        --channel stable --version 1.0.0 --bundle "windows-x86_64=$bundle" --entrypoint bin/app.exe
    if ($LASTEXITCODE) { throw 'publishing baseline bundle failed' }
    & (Join-Path $bin 'server.exe') publish-provider-artifact --repo $releaseRepo --keys $releaseKeys `
        --product app-lifecycle --version 1.0.0 --bundle "windows-x86_64=$providerSource" `
        --entrypoint bin/reconciler.ps1
    if ($LASTEXITCODE) { throw 'publishing the node reconciler failed' }
    $providerTarget = 'products/app-lifecycle/stable/1.0.0/windows-x86_64/app-lifecycle'
    $providerSha = (& (Join-Path $bin 'server.exe') target-sha256 --repo $releaseRepo --name $providerTarget).Trim()
    if ($LASTEXITCODE) { throw 'resolving the reconciler hash failed' }
    & (Join-Path $bin 'server.exe') publish-provider-set --repo $releaseRepo --keys $releaseKeys --id default `
        --provider-path $providerTarget --provider-sha256 $providerSha --provider-timeout-ms 30000
    if ($LASTEXITCODE) { throw 'publishing provider set failed' }
    $appTarget = 'products/app/stable/1.0.0/windows-x86_64/app'
    $setTarget = 'provider-sets/default.json'
    $appSha = (& (Join-Path $bin 'server.exe') target-sha256 --repo $releaseRepo --name $appTarget).Trim()
    if ($LASTEXITCODE) { throw 'resolving the published application hash failed' }
    $setSha = (& (Join-Path $bin 'server.exe') target-sha256 --repo $releaseRepo --name $setTarget).Trim()
    if ($LASTEXITCODE) { throw 'resolving the published provider-set hash failed' }
    $runtimeJson = @{
        product = 'app'; channel = 'stable'; installRoot = $install
        repository = @{metadataLimit=1048576; targetLimit=536870912; transportTimeoutSeconds=30}
        storage = @{inactiveReleases=2; inactiveProviders=2; inactiveAgents=1; inactiveBytes=1073741824; inactiveRepositoryCaches=2}
        # `checkIntervalSeconds` is capped at MAX_CHECK_INTERVAL_SECONDS (16) — three of a node's
        # report gaps must fit inside the 60s freshness window every reader ages reports against, so
        # a signed assignment carrying a slower cadence is rejected at publish. The fixture's hook
        # is immediate and deterministic, so use the same short health/confirmation timing as the
        # native HAProxy lifecycle test. A long production soak window would only burn CI time here.
        timeouts = @{checkIntervalSeconds=16; healthGraceSeconds=4; healthSuccesses=1; healthIntervalSeconds=1; refreshRetrySeconds=5; confirmationWindowSeconds=2; agentCheckIntervalSeconds=3600}
    } | ConvertTo-Json -Depth 5 -Compress
    [IO.File]::WriteAllText($runtime, $runtimeJson, [Text.UTF8Encoding]::new($false))
    & (Join-Path $bin 'server.exe') publish-assignment --repo $routingRepo --keys $routingKeys `
        --release-root (Join-Path $releaseRepo 'metadata\root.json') `
        --name assignments/agents/agent.json --metadata-url "https://127.0.0.1:$objectPort/metadata/" `
        --targets-url "https://127.0.0.1:$objectPort/targets/" --deployment initial `
        --application-path $appTarget --application-sha256 $appSha `
        --provider-set-path $setTarget --provider-set-sha256 $setSha --runtime $runtime
    if ($LASTEXITCODE) { throw 'publishing routing assignment failed' }

    $gatewayProcess = Start-Process -PassThru -WindowStyle Hidden (Join-Path $bin 'server.exe') `
        -ArgumentList @('serve-capability', '--repo', $routingRepo, '--addr', "127.0.0.1:$repoPort",
            '--public-url', "https://127.0.0.1:$repoPort",
            '--cert', (Join-Path $certs 'server.crt'),
            '--key', (Join-Path $certs 'server.key'),
            '--ca', (Join-Path $certs 'ca.crt'))
    $objectProcess = Start-Process -PassThru -WindowStyle Hidden (Join-Path $bin 'server.exe') `
        -ArgumentList @('serve-object', '--repo', $releaseRepo, '--addr', "127.0.0.1:$objectPort",
            '--cert', (Join-Path $certs 'server.crt'),
            '--key', (Join-Path $certs 'server.key'))
    & (Join-Path $bin 'server.exe') export-enrollment --repo $routingRepo `
        --assignment assignments/agents/agent.json --agent-id agent `
        --routing-base-url "https://127.0.0.1:$repoPort/" `
        --output (Join-Path $launcherState 'enrollment.json')
    if ($LASTEXITCODE) { throw 'exporting enrollment bundle failed' }
    # Enrollment is preplaced (export-enrollment wrote enrollment.json above), so the agent never
    # calls /enroll — but only because its steady-state identity is preplaced too. A preplaced
    # bundle whose routing base URL is remote makes the node mint a per-node leaf at /enroll on
    # first boot unless agent.crt/agent.key already exist in the state dir, and that mint reads the
    # config's identity paths for real. Seed them with this fixture node's named client leaf,
    # exactly as an offline installer would; the repository verifies it against the same CA.
    Copy-Item (Join-Path $certs 'client.crt') (Join-Path $launcherState 'agent.crt')
    Copy-Item (Join-Path $certs 'client.key') (Join-Path $launcherState 'agent.key')
    # The node identity is presented only to the routing capability origin. Release bytes are
    # downloaded through the anonymous object client, which trusts the same local CA.
    $configText = @"
[enrollment]
url = 'https://127.0.0.1:$repoPort/enroll'
name = 'agent'
ca = '$(Join-Path $certs 'ca.crt')'
"@
    [IO.File]::WriteAllText($config, $configText, [Text.UTF8Encoding]::new($false))

    $wrapper = Join-Path $bin 'selfupdate-service.exe'
    $launcher = Join-Path $bin 'updated-launcher.exe'
    $installerVariables = @{
        UPDATED_WINDOWS_SERVICE = $service
        UPDATED_WINDOWS_WRAPPER = $wrapper
        UPDATED_WINDOWS_LAUNCHER = $launcher
        UPDATED_WINDOWS_STATE_DIR = $launcherState
        UPDATED_WINDOWS_CONFIG = $config
        UPDATED_WINDOWS_AGENT = $initialAgent
        UPDATED_WINDOWS_START = 'demand'
    }
    foreach ($entry in $installerVariables.GetEnumerator()) {
        Set-Item -Path "Env:$($entry.Key)" -Value $entry.Value
    }
    try {
        & (Join-Path $PSScriptRoot 'install-updated-agent.bat') | Out-Null
        if ($LASTEXITCODE) { throw "production Windows installer failed with exit code $LASTEXITCODE" }
    } finally {
        foreach ($name in $installerVariables.Keys) { Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue }
    }
    $installedService = Get-CimInstance Win32_Service -Filter "Name='$service'"
    if (-not $installedService -or $installedService.StartName -ne 'LocalSystem') {
        throw "installer did not grant the configuration agent machine authority: $($installedService.StartName)"
    }
    Wait-ServiceState 'Running'

    # The agent converged the release the only way it can: through the release's own hooks. The
    # first boot's apply carries `install`. The authoritative completion barrier is installed.json:
    # it cannot become confirmed until the boot health gate has passed and the state transition has
    # committed. Do not maintain a second, receipt-derived definition of "healthy installation".
    $installed = Wait-ConfirmedInstall '1.0.0'
    # The installed record is the authoritative completion barrier. Keep the receipt assertion as
    # proof of the path taken, but check it only after completion so its narrower diagnostic cannot
    # hide the service/process/state evidence emitted by Wait-ConfirmedInstall on a failed boot.
    $null = Wait-Operation 'apply' 'install' 0 1

    $desired = Read-DesiredAgent
    if (-not $desired.Equals([IO.Path]::GetFullPath($initialAgent), [StringComparison]::OrdinalIgnoreCase)) {
        throw "the launcher pointer does not name the initial agent: $desired"
    }
    $active = Get-Content (Join-Path $install 'active-release') -Raw | ConvertFrom-Json
    if ($active.version -ne $installed.release.version -or $active.manifest_sha256 -ne $installed.release.manifest_sha256) {
        throw 'active-release does not name the committed bundle'
    }

    # A clean stop must end the tree the service owns — wrapper, launcher and agent — with no
    # external reaper. Nothing else is in that tree: the agent holds no workload process.
    $tree = Get-TreeProcessIds
    if (-not $tree) { throw 'the running service exposed no launcher/agent processes to stop' }
    & sc.exe stop $service | Out-Null
    Wait-ServiceState 'Stopped'
    Wait-ProcessExit $tree

    # A fresh launch re-converges the committed bundle through the same reconciler, this time as a
    # restart, and never moves the agent pointer.
    $before = @(Read-Operations).Count
    & sc.exe start $service | Out-Null
    Wait-ServiceState 'Running'
    $restart = Wait-Operation 'apply' 'restart' $before
    if ((Read-DesiredAgent) -ne $desired) { throw 'the SCM restart changed the agent pointer' }

    Write-Host "SUCCESS: SCM stop ended the launcher+agent tree cleanly and a fresh start re-converged committed bundle 1.0.0 through its own reconciler" -ForegroundColor Green
}
finally {
    if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
        & sc.exe stop $service 2>$null | Out-Null
        try { Wait-ServiceState 'Stopped' 10 } catch { }
    }
    & sc.exe delete $service 2>$null | Out-Null
    # The service host appends the launcher's and agent's output here. Always surface a bounded
    # tail so both CI and an operator can see the fatal boundary without flooding the job log.
    foreach ($name in @('launcher.previous.log', 'launcher.log')) {
        $launcherLog = Join-Path $launcherState $name
        if (Test-Path -LiteralPath $launcherLog) {
            Write-Host "--- $name (last 200 launcher + agent lines) ---"
            Get-Content -LiteralPath $launcherLog -Tail 200 |
                ForEach-Object { Write-Host $_ }
            Write-Host "--- end $name ---"
        }
    }
    if ($gatewayProcess) { Stop-Process -Id $gatewayProcess.Id -Force -ErrorAction SilentlyContinue }
    if ($objectProcess) { Stop-Process -Id $objectProcess.Id -Force -ErrorAction SilentlyContinue }
}
