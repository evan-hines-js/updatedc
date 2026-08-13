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
$service = 'SelfUpdateSupervisor'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$work = Join-Path $root 'target\scm-e2e'
$repo = Join-Path $work 'repo'
$keys = Join-Path $work 'keys'
$launcherState = Join-Path $work 'launcher-state'
$install = Join-Path $work 'install'
$bundle = Join-Path $work 'bundle-1.0.0'
$providerSource = Join-Path $work 'reconciler-source'
$receipt = Join-Path $work 'reconciler-operations.log'
$config = Join-Path $work 'bootstrap.toml'
$runtime = Join-Path $work 'runtime.json'
$repoPort = 21980
$serverProcess = $null

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

# The reconciler's recorded history: one line per invocation, `operation<TAB>attempt-id<TAB>reason`.
function Wait-Operation([string]$operation, [int]$seconds = 60) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        if (Test-Path $receipt) {
            $match = Get-Content $receipt | Where-Object { $_.StartsWith("$operation`t") }
            if ($match) { return $match }
        }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    throw "the agent never invoked the reconciler's $operation operation"
}

function Get-TreeProcessIds() {
    $ids = @()
    foreach ($name in @('bootstrap', 'supervisor', 'selfupdate-service')) {
        $ids += (Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
    }
    return $ids
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
    $pointer = Join-Path $launcherState 'desired-supervisor'
    $lines = [IO.File]::ReadAllLines($pointer)
    if ($lines.Count -ne 2 -or $lines[0] -ne 'supervisor-v1' -or -not $lines[1]) {
        throw "invalid desired-supervisor pointer: $($lines -join ' | ')"
    }
    return [IO.Path]::GetFullPath($lines[1])
}

try {
    & sc.exe stop $service 2>$null | Out-Null
    & sc.exe delete $service 2>$null | Out-Null
    Start-Sleep -Milliseconds 500
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $launcherState | Out-Null
    New-Item -ItemType Directory -Force (Join-Path $bundle 'bin') | Out-Null
    New-Item -ItemType Directory -Force (Join-Path $bundle 'config') | Out-Null
    New-Item -ItemType Directory -Force (Join-Path $providerSource 'bin') | Out-Null

    Push-Location $root
    try {
        & cargo build --release -p server -p bootstrap -p supervisor -p windows-service -p sampleapp
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
    $initialAgent = Join-Path $work 'supervisor.exe'
    Copy-Item (Join-Path $bin 'supervisor.exe') $initialAgent

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
Add-Content -LiteralPath '$receipt' -Value `$line
if (`$operation -eq 'inspect') { Write-Output "candidate-version=`$(Value '--candidate-version')" }
exit 0
"@
    [IO.File]::WriteAllText(
        (Join-Path $providerSource 'bin\reconciler.ps1'),
        $reconcilerText,
        [Text.UTF8Encoding]::new($false)
    )

    & (Join-Path $bin 'server.exe') init --repo $repo --keys $keys
    if ($LASTEXITCODE) { throw 'repository initialization failed' }
    & (Join-Path $bin 'server.exe') publish-app --repo $repo --keys $keys --product app `
        --channel stable --version 1.0.0 --bundle "windows-x86_64=$bundle" --entrypoint bin/app.exe
    if ($LASTEXITCODE) { throw 'publishing baseline bundle failed' }
    & (Join-Path $bin 'server.exe') publish-provider-artifact --repo $repo --keys $keys `
        --product app-lifecycle --version 1.0.0 --bundle "windows-x86_64=$providerSource" `
        --entrypoint bin/reconciler.ps1
    if ($LASTEXITCODE) { throw 'publishing the node reconciler failed' }
    $providerTarget = 'products/app-lifecycle/stable/1.0.0/windows-x86_64/app-lifecycle'
    $providerSha = (& (Join-Path $bin 'server.exe') target-sha256 --repo $repo --name $providerTarget).Trim()
    if ($LASTEXITCODE) { throw 'resolving the reconciler hash failed' }
    & (Join-Path $bin 'server.exe') publish-provider-set --repo $repo --keys $keys --id default `
        --provider-path $providerTarget --provider-sha256 $providerSha --provider-timeout-ms 30000
    if ($LASTEXITCODE) { throw 'publishing provider set failed' }
    $appTarget = 'products/app/stable/1.0.0/windows-x86_64/app'
    $setTarget = 'provider-sets/default.json'
    $appSha = (& (Join-Path $bin 'server.exe') target-sha256 --repo $repo --name $appTarget).Trim()
    if ($LASTEXITCODE) { throw 'resolving the published application hash failed' }
    $setSha = (& (Join-Path $bin 'server.exe') target-sha256 --repo $repo --name $setTarget).Trim()
    if ($LASTEXITCODE) { throw 'resolving the published provider-set hash failed' }
    $runtimeJson = @{
        product = 'app'; channel = 'stable'; install_root = $install
        repository = @{metadata_limit=1048576; target_limit=536870912; transport_timeout_seconds=30}
        storage = @{inactive_releases=2; inactive_providers=2; inactive_supervisors=1; inactive_bytes=1073741824; inactive_repository_caches=2}
        timeouts = @{check_interval_seconds=60; health_grace_seconds=10; health_successes=1; health_interval_seconds=1; refresh_retry_seconds=5; confirmation_window_seconds=120; supervisor_check_interval_seconds=3600}
    } | ConvertTo-Json -Depth 5 -Compress
    [IO.File]::WriteAllText($runtime, $runtimeJson, [Text.UTF8Encoding]::new($false))
    & (Join-Path $bin 'server.exe') publish-assignment --repo $repo --keys $keys `
        --name assignments/agents/agent.json --metadata-url "http://127.0.0.1:$repoPort/metadata/" `
        --targets-url "http://127.0.0.1:$repoPort/targets/" --deployment initial `
        --application-path $appTarget --application-sha256 $appSha `
        --provider-set-path $setTarget --provider-set-sha256 $setSha --runtime $runtime
    if ($LASTEXITCODE) { throw 'publishing routing assignment failed' }

    $serverProcess = Start-Process -PassThru -WindowStyle Hidden (Join-Path $bin 'server.exe') `
        -ArgumentList @('serve', '--repo', $repo, '--addr', "127.0.0.1:$repoPort")
    & (Join-Path $bin 'server.exe') export-enrollment --repo $repo `
        --assignment assignments/agents/agent.json --agent-id agent `
        --routing-base-url "http://127.0.0.1:$repoPort/" `
        --output (Join-Path $launcherState 'enrollment.json')
    if ($LASTEXITCODE) { throw 'exporting enrollment bundle failed' }
    # Enrollment is preplaced (export-enrollment wrote enrollment.json above), so the agent never
    # calls /enroll — but the bootstrap must still be a complete, valid EnrollmentBootstrap. The name
    # and cert paths are never read in this offline path; they only satisfy config validation.
    $configText = @"
[enrollment]
url = 'http://127.0.0.1:$repoPort/enroll'
name = 'agent'
client_cert = 'unused-preplaced.crt'
client_key = 'unused-preplaced.key'
ca = 'unused-preplaced-ca.crt'
"@
    [IO.File]::WriteAllText($config, $configText, [Text.UTF8Encoding]::new($false))

    $wrapper = Join-Path $bin 'selfupdate-service.exe'
    $launcher = Join-Path $bin 'bootstrap.exe'
    $binPath = "`"$wrapper`" --bootstrap `"$launcher`" --state-dir `"$launcherState`" --supervisor-config `"$config`" --supervisor `"$initialAgent`""
    & sc.exe create $service binPath= $binPath start= demand | Out-Null
    if ($LASTEXITCODE) { throw 'SCM service creation failed' }

    & sc.exe start $service | Out-Null
    Wait-ServiceState 'Running'

    # The agent converged the release the only way it can: through the release's own hooks. The
    # first boot's apply carries `install`, and the boot readiness gate runs under the reserved
    # `boot` identity.
    $apply = Wait-Operation 'apply'
    if (($apply -split "`t")[2] -ne 'install') { throw "the first converge was not an install: $apply" }
    $gate = Wait-Operation 'healthcheck'
    if (($gate -split "`t")[1] -ne 'boot') { throw "the boot readiness gate did not run under the boot identity: $gate" }

    $desired = Read-DesiredAgent
    if (-not $desired.Equals([IO.Path]::GetFullPath($initialAgent), [StringComparison]::OrdinalIgnoreCase)) {
        throw "the launcher pointer does not name the initial agent: $desired"
    }
    $installed = Get-Content (Join-Path $install 'state\installed.json') -Raw | ConvertFrom-Json
    $active = Get-Content (Join-Path $install 'active-release') -Raw | ConvertFrom-Json
    if ($installed.release.version -ne '1.0.0' -or $null -ne $installed.pending) {
        throw 'installed state does not commit the seeded bundle'
    }
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
    $before = (Get-Content $receipt).Count
    & sc.exe start $service | Out-Null
    Wait-ServiceState 'Running'
    $deadline = (Get-Date).AddSeconds(60)
    do {
        $restart = Get-Content $receipt | Select-Object -Skip $before |
            Where-Object { $_.StartsWith("apply`t") -and ($_ -split "`t")[2] -eq 'restart' }
        if ($restart) { break }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    if (-not $restart) { throw 'the relaunched agent never re-converged the committed release' }
    if ((Read-DesiredAgent) -ne $desired) { throw 'the SCM restart changed the agent pointer' }

    Write-Host "SUCCESS: SCM stop ended the launcher+agent tree cleanly and a fresh start re-converged committed bundle 1.0.0 through its own reconciler" -ForegroundColor Green
}
finally {
    if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
        & sc.exe stop $service 2>$null | Out-Null
        try { Wait-ServiceState 'Stopped' 10 } catch { }
    }
    & sc.exe delete $service 2>$null | Out-Null
    if ($serverProcess) { Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue }
}
