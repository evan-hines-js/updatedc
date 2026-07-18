# Requires an elevated PowerShell. Exercises the native SCM host with the current
# bundle-only installation model: SCM -> wrapper -> bootstrap -> supervisor -> app,
# followed by a clean service stop and a fresh launch of the committed bundle.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$service = 'SelfUpdateSupervisor'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$work = Join-Path $root 'target\scm-e2e'
$repo = Join-Path $work 'repo'
$keys = Join-Path $work 'keys'
$guardianState = Join-Path $work 'guardian-state'
$install = Join-Path $work 'install'
$bundle = Join-Path $work 'bundle-1.0.0'
$config = Join-Path $work 'config.toml'
$repoPort = 21980
$appPort = 21990
$serverProcess = $null
$appPid = $null
$restartedPid = $null

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

function Wait-Http([string]$path, [int]$seconds = 30) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do {
        try {
            return (Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 "http://127.0.0.1:$appPort$path").Content.Trim()
        } catch {
            Start-Sleep -Milliseconds 200
        }
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
    $pointer = Join-Path $guardianState 'desired-supervisor'
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
    New-Item -ItemType Directory -Force $guardianState | Out-Null
    New-Item -ItemType Directory -Force (Join-Path $bundle 'bin') | Out-Null
    New-Item -ItemType Directory -Force (Join-Path $bundle 'config') | Out-Null

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
    $initialSupervisor = Join-Path $work 'supervisor.exe'
    Copy-Item (Join-Path $bin 'supervisor.exe') $initialSupervisor

    & (Join-Path $bin 'server.exe') init --repo $repo --keys $keys
    if ($LASTEXITCODE) { throw 'repository initialization failed' }
    & (Join-Path $bin 'server.exe') install-app --install-root $install --bundle $bundle `
        --product app --version 1.0.0 --platform windows-x86_64 --entrypoint bin/app.exe
    if ($LASTEXITCODE) { throw 'installer bundle seeding failed' }
    & (Join-Path $bin 'server.exe') publish-app --repo $repo --keys $keys --product app `
        --channel stable --version 1.0.0 --bundle "windows-x86_64=$bundle" --entrypoint bin/app.exe
    if ($LASTEXITCODE) { throw 'publishing baseline bundle failed' }
    & (Join-Path $bin 'server.exe') publish-provider-set --repo $repo --keys $keys --id default
    if ($LASTEXITCODE) { throw 'publishing provider set failed' }
    $appTarget = 'products/app/stable/1.0.0/windows-x86_64/app'
    $setTarget = 'provider-sets/default.json'
    $appSha = (Get-FileHash -Algorithm SHA256 (Join-Path $repo "targets/$appTarget")).Hash.ToLowerInvariant()
    $setSha = (Get-FileHash -Algorithm SHA256 (Join-Path $repo "targets/$setTarget")).Hash.ToLowerInvariant()
    & (Join-Path $bin 'server.exe') publish-assignment --repo $repo --keys $keys `
        --name assignments/nodes/node.json --metadata-url "http://127.0.0.1:$repoPort/metadata/" `
        --targets-url "http://127.0.0.1:$repoPort/targets/" --deployment initial `
        --application-path $appTarget --application-sha256 $appSha `
        --provider-set-path $setTarget --provider-set-sha256 $setSha
    if ($LASTEXITCODE) { throw 'publishing routing assignment failed' }

    $serverProcess = Start-Process -PassThru -WindowStyle Hidden (Join-Path $bin 'server.exe') `
        -ArgumentList @('serve', '--repo', $repo, '--addr', "127.0.0.1:$repoPort")
    $rootJson = Join-Path $repo 'metadata\root.json'
    $configText = @"
[routing]
root = '$($rootJson.Replace("'", "''"))'
base_url = 'http://127.0.0.1:$repoPort/'
assignment = 'assignments/nodes/node.json'

[repository]
root = '$($rootJson.Replace("'", "''"))'

[application]
product = 'app'
channel = 'stable'
install_root = '$($install.Replace("'", "''"))'
args = ['--addr', '127.0.0.1:$appPort']
health_url = 'http://127.0.0.1:$appPort/healthz'

[timeouts]
check_interval = '60s'
health_grace = '10s'
"@
    [IO.File]::WriteAllText($config, $configText, [Text.UTF8Encoding]::new($false))

    $wrapper = Join-Path $bin 'selfupdate-service.exe'
    $bootstrap = Join-Path $bin 'bootstrap.exe'
    $binPath = "`"$wrapper`" --bootstrap `"$bootstrap`" --state-dir `"$guardianState`" --supervisor-config `"$config`" --supervisor `"$initialSupervisor`""
    & sc.exe create $service binPath= $binPath start= demand | Out-Null
    if ($LASTEXITCODE) { throw 'SCM service creation failed' }

    & sc.exe start $service | Out-Null
    Wait-ServiceState 'Running'
    $appPid = [int](Wait-Http '/pid')
    if ((Wait-Http '/version') -ne '1.0.0') { throw 'unexpected baseline version' }

    $desired = Read-DesiredSupervisor
    if (-not $desired.Equals([IO.Path]::GetFullPath($initialSupervisor), [StringComparison]::OrdinalIgnoreCase)) {
        throw "guardian pointer does not name the initial supervisor: $desired"
    }
    $installed = Get-Content (Join-Path $install 'state\installed.json') -Raw | ConvertFrom-Json
    $active = Get-Content (Join-Path $install 'active-release') -Raw | ConvertFrom-Json
    if ($installed.release.version -ne '1.0.0' -or $null -ne $installed.pending) {
        throw 'installed state does not commit the seeded bundle'
    }
    if ($active.version -ne $installed.release.version -or $active.manifest_sha256 -ne $installed.release.manifest_sha256) {
        throw 'active-release does not name the committed bundle'
    }

    & sc.exe stop $service | Out-Null
    Wait-ServiceState 'Stopped'
    Wait-ProcessExit $appPid
    $reachable = $true
    try {
        Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 "http://127.0.0.1:$appPort/pid" | Out-Null
    } catch {
        $reachable = $false
    }
    if ($reachable) { throw 'application remained reachable after its guardian stopped' }

    & sc.exe start $service | Out-Null
    Wait-ServiceState 'Running'
    $restartedPid = [int](Wait-Http '/pid')
    if ($restartedPid -eq $appPid) { throw "application PID unexpectedly survived guardian restart ($appPid)" }
    if ((Wait-Http '/version') -ne '1.0.0') { throw 'restarted application has an unexpected version' }
    if ((Read-DesiredSupervisor) -ne $desired) { throw 'SCM restart changed the supervisor pointer' }

    Write-Host "SUCCESS: native SCM stop/start relaunched committed bundle 1.0.0 ($appPid -> $restartedPid)" -ForegroundColor Green
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
