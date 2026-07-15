# Requires an elevated PowerShell. Exercises the real Windows SCM host end to end:
# installer-digested first install -> bootstrap -> supervisor -> app, durable pointer/state records,
# then clean application shutdown and a fresh launch across SCM stop/start.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$service = 'SelfUpdateSupervisor'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$work = Join-Path $root 'target\scm-e2e'
$repo = Join-Path $work 'repo'
$keys = Join-Path $work 'keys'
$state = Join-Path $work 'state'
$app = Join-Path $state 'app.exe'
$config = Join-Path $work 'config.toml'
$port = 21980
$appPort = 21990
$serverProcess = $null
$appPid = $null
$restartedPid = $null

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell; SCM service creation requires Administrator.'
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

function Wait-Http([string]$path, [int]$seconds = 30) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        try { return (Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$appPort$path").Content.Trim() }
        catch { Start-Sleep -Milliseconds 200 }
    } while ((Get-Date) -lt $deadline)
    throw "application endpoint $path did not become ready"
}

function Wait-ProcessExit([int]$id, [int]$seconds = 30) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        if (-not (Get-Process -Id $id -ErrorAction SilentlyContinue)) { return }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    throw "application process $id did not exit within ${seconds}s"
}

function Read-DesiredSupervisor() {
    $pointer = Join-Path $state 'desired-supervisor'
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
    New-Item -ItemType Directory -Force $state | Out-Null

    Push-Location $root
    try {
        & cargo build --release -p server -p bootstrap -p supervisor -p windows-service
        if ($LASTEXITCODE) { throw 'building updater binaries failed' }
        $env:APP_VERSION = '1.0.0'
        & cargo build --release -p sampleapp
        if ($LASTEXITCODE) { throw 'building sample application failed' }
        Remove-Item Env:APP_VERSION
    } finally { Pop-Location }

    $bin = Join-Path $root 'target\release'
    Copy-Item (Join-Path $bin 'sampleapp.exe') $app
    $initialSupervisor = Join-Path $work 'supervisor.exe'
    Copy-Item (Join-Path $bin 'supervisor.exe') $initialSupervisor
    & (Join-Path $bin 'server.exe') init --repo $repo --keys $keys
    if ($LASTEXITCODE) { throw 'repository initialization failed' }
    # Rust names x64 `x86_64`, while PROCESSOR_ARCHITECTURE reports AMD64.
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') { 'x86_64' } elseif ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64' } else { $env:PROCESSOR_ARCHITECTURE.ToLower() }
    & (Join-Path $bin 'server.exe') publish --repo $repo --keys $keys --product app --version 1.0.0 --component app --target "windows-$arch=$app"
    if ($LASTEXITCODE) { throw 'publishing baseline failed' }

    $serverProcess = Start-Process -PassThru -WindowStyle Hidden (Join-Path $bin 'server.exe') -ArgumentList @('serve', '--repo', $repo, '--addr', "127.0.0.1:$port")
    $rootJson = Join-Path $repo 'metadata\root.json'
    $baselineSha = (Get-FileHash -Algorithm SHA256 $app).Hash.ToLowerInvariant()
    $configText = @"
[repository]
root = '$($rootJson.Replace("'", "''"))'
metadata_url = 'http://127.0.0.1:$port/metadata/'
targets_url = 'http://127.0.0.1:$port/targets/'
[application]
product = 'app'
current_version = '1.0.0'
current_sha256 = '$baselineSha'
command = ['$($app.Replace("'", "''"))', '--addr', '127.0.0.1:$appPort']
health_url = 'http://127.0.0.1:$appPort/healthz'
[timeouts]
check_interval = '60s'
health_grace = '10s'
"@
    [IO.File]::WriteAllText($config, $configText, [Text.UTF8Encoding]::new($false))

    $wrapper = Join-Path $bin 'selfupdate-service.exe'
    $bootstrap = Join-Path $bin 'bootstrap.exe'
    $binPath = "`"$wrapper`" --bootstrap `"$bootstrap`" --state-dir `"$state`" --supervisor-config `"$config`" --supervisor `"$initialSupervisor`""
    & sc.exe create $service binPath= $binPath start= demand | Out-Null
    if ($LASTEXITCODE) { throw 'SCM service creation failed' }
    & sc.exe start $service | Out-Null
    Wait-ServiceState 'Running'
    $appPid = [int](Wait-Http '/pid')
    if ((Wait-Http '/version') -ne '1.0.0') { throw 'unexpected baseline version' }

    $desired = Read-DesiredSupervisor
    if (-not $desired.Equals([IO.Path]::GetFullPath($initialSupervisor), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "guardian pointer does not name the initial supervisor: $desired"
    }
    $installed = Get-Content ("$app.installed") -Raw | ConvertFrom-Json
    $appHash = (Get-FileHash -Algorithm SHA256 $app).Hash.ToLowerInvariant()
    if ($installed.version -ne '1.0.0' -or $installed.sha256 -ne $appHash -or $null -ne $installed.pending) {
        throw "installed state does not commit the exact baseline binary"
    }

    & sc.exe stop $service | Out-Null
    Wait-ServiceState 'Stopped'
    Wait-ProcessExit $appPid
    $reachable = $true
    try { Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:$appPort/pid" -TimeoutSec 2 | Out-Null }
    catch { $reachable = $false }
    if ($reachable) { throw 'application remained reachable after its permanent guardian stopped' }

    & sc.exe start $service | Out-Null
    Wait-ServiceState 'Running'
    $restartedPid = [int](Wait-Http '/pid')
    if ($restartedPid -eq $appPid) { throw "application PID unexpectedly survived guardian restart ($appPid)" }
    if ((Wait-Http '/version') -ne '1.0.0') { throw 'restarted application has an unexpected version' }
    if ((Read-DesiredSupervisor) -ne $desired) { throw 'SCM restart changed the committed supervisor pointer' }

    Write-Host "SUCCESS: native SCM stop/start cleanly relaunched the application ($appPid -> $restartedPid)" -ForegroundColor Green
}
finally {
    if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
        & sc.exe stop $service 2>$null | Out-Null
        try { Wait-ServiceState 'Stopped' 10 } catch { }
    }
    & sc.exe delete $service 2>$null | Out-Null
    if ($appPid) { Stop-Process -Id $appPid -Force -ErrorAction SilentlyContinue }
    if ($restartedPid) { Stop-Process -Id $restartedPid -Force -ErrorAction SilentlyContinue }
    if ($serverProcess) { Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue }
}
