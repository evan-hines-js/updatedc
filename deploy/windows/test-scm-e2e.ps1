# Requires an elevated PowerShell. Exercises the native SCM host with the current bundle-only
# installation model: SCM -> wrapper -> agent, the same signed native reconciler fixture
# as the cross-platform E2E suite, a clean service stop, and a fresh launch of the committed bundle.
#
# SCOPE, deliberately: this drives the agent lifecycle and one full reconciler converge.
# It does NOT have the reconciler start a workload process. The property that matters here is
# ownership, and it is asserted directly: an SCM stop must cleanly end the tree the service owns —
# the wrapper and the agent — and a workload is provably not part of that tree,
# because the agent never launches, holds, or stops one. What runs the workload is the operator's
# own mechanism, driven from the reconciler (`sc.exe`, a container runtime, a config reload); a
# reconciler that instead forks a workload directly must create it with CREATE_BREAKAWAY_FROM_JOB,
# which the agent's job object permits, so that the workload leaves the hook's disposable tree.
# Driving the service manager is the shape this test's reconciler stands in for — that is scope,
# not a platform limitation.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$testId = [Guid]::NewGuid().ToString('N')
$service = "UpdatedAgentE2E-$testId"
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
# Runtime state must never live below Cargo's cached target directory. Restoring that directory
# can otherwise turn this cold-install test into a restart while still leaving the binary build
# cache perfectly valid. The service runs as LocalSystem, so its fixture belongs under the same
# machine-wide ProgramData boundary as a real installation—not the interactive runner's private
# user-profile temp directory. A unique child still makes "empty node" true by construction.
$machineData = [System.Environment]::GetFolderPath(
    [System.Environment+SpecialFolder]::CommonApplicationData
)
$work = Join-Path $machineData "updated-scm-e2e-$testId"
$routingRepo = Join-Path $work 'routing-repo'
$routingKeys = Join-Path $work 'routing-keys'
$releaseRepo = Join-Path $work 'release-repo'
$releaseKeys = Join-Path $work 'release-keys'
$certs = Join-Path $work 'certs'
$agentState = Join-Path $work 'agent-state'
$install = Join-Path $work 'install'
$bundle = Join-Path $work 'bundle-1.0.0'
$fixtureState = Join-Path $work 'lifecycle-fixture'
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

# The shared native fixture records `operation<TAB>attempt-id<TAB>reason<TAB>version` in one
# append-only log. Read it with sharing enabled because the hook may append while this harness polls.
function Read-Operations() {
    $path = Join-Path $fixtureState 'operations.log'
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    try {
        $stream = [IO.File]::Open(
            $path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        )
        try {
            $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true, 4096, $true)
            try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        } finally {
            $stream.Dispose()
        }
        return @($text -split '\r?\n' | Where-Object { $_ })
    } catch {
        # A hook may be appending the next complete line while the harness polls. The caller owns
        # the bounded retry; an observation race is not evidence that the invocation never ran.
        return @()
    }
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
# This fixture has a ten-second health grace and an immediate native health hook. The agent enforces
# that grace on the hook process itself. The outer 45-second deadline also covers the separately
# bounded initial converge plus service startup before producing diagnostics for a broken first boot.
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
                    $state.maturity -eq 'proven' -and
                    $null -eq $state.rollback_guard) {
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
    $agentLog = Join-Path $agentState 'agent.log'
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
        "agent-log=[$agentLog]"
}

function Get-ServiceProcessTree() {
    # Scope both diagnostics and stop assertions to this test's SCM-owned tree. Other running
    # installations may use the same executable names and must never become test subjects.
    $ownedService = Get-CimInstance Win32_Service -Filter "Name='$service'"
    if (-not $ownedService -or $ownedService.ProcessId -eq 0) { return @() }
    $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $tree = @()
    $frontier = @($ownedService.ProcessId)
    while ($frontier.Count -gt 0) {
        $tree += $frontier
        $frontier = @($all |
            Where-Object { $frontier -contains $_.ParentProcessId -and $tree -notcontains $_.ProcessId } |
            ForEach-Object { $_.ProcessId })
    }
    return @($all | Where-Object { $tree -contains $_.ProcessId })
}

function Get-TreeProcessDetails() {
    return @(Get-ServiceProcessTree | Sort-Object CreationDate | ForEach-Object {
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

try {
    New-Item -ItemType Directory -Force $work | Out-Null
    New-Item -ItemType Directory -Force $agentState | Out-Null
    New-Item -ItemType Directory -Force (Join-Path $bundle 'bin') | Out-Null
    New-Item -ItemType Directory -Force (Join-Path $bundle 'config') | Out-Null
    New-Item -ItemType Directory -Force $fixtureState | Out-Null

    Push-Location $root
    try {
        & cargo build --release -p server -p agent -p windows-service -p sampleapp
        if ($LASTEXITCODE) { throw 'building SCM test binaries failed' }
        & cargo build --release -p e2e --bin lifecycle-fixture
        if ($LASTEXITCODE) { throw 'building the native reconciler fixture failed' }
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

    # Reuse the one native reconciler fixture exercised by the cross-platform E2E suite. The old
    # bespoke PowerShell implementation took 26 seconds merely to start under LocalSystem on a
    # hosted runner, then a second cold PowerShell process exhausted the health grace. That made an
    # SCM ownership test measure shell startup and duplicated the protocol implementation.
    Copy-Item (Join-Path $bin 'lifecycle-fixture.exe') (Join-Path $bundle 'bin\fixture.exe')

    & (Join-Path $bin 'server.exe') init --repo $routingRepo --keys $routingKeys
    if ($LASTEXITCODE) { throw 'routing repository initialization failed' }
    & (Join-Path $bin 'server.exe') init --repo $releaseRepo --keys $releaseKeys
    if ($LASTEXITCODE) { throw 'release repository initialization failed' }
    # One TLS hierarchy covers two origins with distinct duties: routing authenticates the node
    # before minting an exact bearer; the release origin never receives the node identity.
    & (Join-Path $bin 'server.exe') gen-certs --dir $certs --san 127.0.0.1 --san localhost
    if ($LASTEXITCODE) { throw 'minting the fleet mTLS material failed' }
    $procedure = @{argv=@('./bin/fixture.exe', '--lifecycle-fixture'); timeoutSeconds=10}
    $execution = @{schema=1; deploy=$procedure; health=$procedure; inspect=$procedure;
        replay=@{policy='safe'}; recovery=@{policy='command'; command=$procedure; replay=@{policy='safe'}}} | ConvertTo-Json -Depth 6 -Compress
    [IO.File]::WriteAllText((Join-Path $bundle '.updated-execution.json'), $execution, [Text.UTF8Encoding]::new($false))
    & (Join-Path $bin 'server.exe') publish-app --repo $releaseRepo --keys $releaseKeys --product app `
        --channel stable --version 1.0.0 --bundle "windows-x86_64=$bundle"
    if ($LASTEXITCODE) { throw 'publishing baseline bundle failed' }
    $appTarget = 'products/app/stable/1.0.0/windows-x86_64/app'
    $appSha = (& (Join-Path $bin 'server.exe') target-sha256 --repo $releaseRepo --name $appTarget).Trim()
    if ($LASTEXITCODE) { throw 'resolving the published application hash failed' }
    $runtimeJson = @{
        product = 'app'; channel = 'stable'; installRoot = $install
        repository = @{metadataLimit=1048576; targetLimit=536870912; transportTimeoutSeconds=30}
        storage = @{inactiveReleases=2; inactiveBytes=1073741824; inactiveRepositoryCaches=2}
        # `checkIntervalSeconds` is capped at MAX_CHECK_INTERVAL_SECONDS (16) — three of a node's
        # report gaps must fit inside the 60s freshness window every reader ages reports against, so
        # a signed assignment carrying a slower cadence is rejected at publish. The native fixture
        # answers immediately; ten seconds is a deadline for runner variance, not a sleep. A long
        # production soak window would only burn CI time here.
        timeouts = @{checkIntervalSeconds=16; healthGraceSeconds=10; healthSuccesses=1; healthIntervalSeconds=1; refreshRetrySeconds=5; confirmationWindowSeconds=2}
    } | ConvertTo-Json -Depth 5 -Compress
    [IO.File]::WriteAllText($runtime, $runtimeJson, [Text.UTF8Encoding]::new($false))
    & (Join-Path $bin 'server.exe') publish-assignment --repo $routingRepo --keys $routingKeys `
        --release-root (Join-Path $releaseRepo 'metadata\root.json') `
        --name assignments/agents/agent.json --metadata-url "https://127.0.0.1:$objectPort/metadata/" `
        --targets-url "https://127.0.0.1:$objectPort/targets/" --deployment initial `
        --application-path $appTarget --application-sha256 $appSha `
        --runtime $runtime
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
        --output (Join-Path $agentState 'enrollment.json')
    if ($LASTEXITCODE) { throw 'exporting enrollment bundle failed' }
    # Enrollment is preplaced (export-enrollment wrote enrollment.json above), so the agent never
    # calls /enroll — but only because its steady-state identity is preplaced too. A preplaced
    # bundle whose routing base URL is remote makes the node mint a per-node leaf at /enroll on
    # first boot unless agent.crt/agent.key already exist in the state dir, and that mint reads the
    # config's identity paths for real. Seed them with this fixture node's named client leaf,
    # exactly as an offline installer would; the repository verifies it against the same CA.
    Copy-Item (Join-Path $certs 'client.crt') (Join-Path $agentState 'agent.crt')
    Copy-Item (Join-Path $certs 'client.key') (Join-Path $agentState 'agent.key')
    # The node identity is presented only to the routing capability origin. Release bytes are
    # downloaded through the anonymous object client, which trusts the same local CA.
    $configText = @"
[enrollment]
url = 'https://127.0.0.1:$repoPort/enroll'
name = 'agent'
ca = '$(Join-Path $certs 'ca.crt')'
"@
    [IO.File]::WriteAllText($config, $configText, [Text.UTF8Encoding]::new($false))

    $wrapper = Join-Path $bin 'updated-agent-service.exe'
    $installerVariables = @{
        UPDATED_WINDOWS_SERVICE = $service
        UPDATED_WINDOWS_WRAPPER = $wrapper
        UPDATED_WINDOWS_STATE_DIR = $agentState
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
    # first boot's converge carries `install`. The authoritative completion barrier is installed.json:
    # it cannot become proven until the boot health gate has passed and the state transition has
    # committed. Do not maintain a second, receipt-derived definition of "healthy installation".
    $installed = Wait-ConfirmedInstall '1.0.0'
    # The installed record is the authoritative completion barrier. Keep the receipt assertion as
    # proof of the path taken, but check it only after completion so its narrower diagnostic cannot
    # hide the service/process/state evidence emitted by Wait-ConfirmedInstall on a failed boot.
    $null = Wait-Operation 'converge' 'install' 0 1

    $active = Get-Content (Join-Path $install 'active-release') -Raw | ConvertFrom-Json
    if ($active.version -ne $installed.release.version -or $active.manifest_sha256 -ne $installed.release.manifest_sha256) {
        throw 'active-release does not name the committed bundle'
    }

    # A clean stop must end the tree the service owns — wrapper and agent — with no
    # external reaper. Nothing else is in that tree: the agent holds no workload process.
    $tree = @(Get-ServiceProcessTree | ForEach-Object { $_.ProcessId })
    if (-not $tree) { throw 'the running service exposed no agent processes to stop' }
    & sc.exe stop $service | Out-Null
    Wait-ServiceState 'Stopped'
    Wait-ProcessExit $tree

    # A fresh launch re-converges the committed bundle through the same reconciler, this time as a
    # restart.
    $before = @(Read-Operations).Count
    & sc.exe start $service | Out-Null
    Wait-ServiceState 'Running'
    $restart = Wait-Operation 'converge' 'restart' $before
    Write-Host "SUCCESS: SCM stop ended the agent tree cleanly and a fresh start re-converged committed bundle 1.0.0 through its own reconciler" -ForegroundColor Green
}
finally {
    if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
        & sc.exe stop $service 2>$null | Out-Null
        try { Wait-ServiceState 'Stopped' 10 } catch { }
    }
    & sc.exe delete $service 2>$null | Out-Null
    # The service host appends the agent's output here. Always surface a bounded
    # tail so both CI and an operator can see the fatal boundary without flooding the job log.
    foreach ($name in @('agent.previous.log', 'agent.log')) {
        $agentLog = Join-Path $agentState $name
        if (Test-Path -LiteralPath $agentLog) {
            Write-Host "--- $name (last 200 agent lines) ---"
            Get-Content -LiteralPath $agentLog -Tail 200 |
                ForEach-Object { Write-Host $_ }
            Write-Host "--- end $name ---"
        }
    }
    if ($gatewayProcess) { Stop-Process -Id $gatewayProcess.Id -Force -ErrorAction SilentlyContinue }
    if ($objectProcess) { Stop-Process -Id $objectProcess.Id -Force -ErrorAction SilentlyContinue }
    Wait-ServiceDeleted
}
