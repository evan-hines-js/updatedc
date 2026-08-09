:: Native Windows SCM deployment for the self-update tower. Run from an elevated
:: Administrator command prompt after installing the bootstrap, supervisor, pinned
:: signed enrollment bundle, bootstrap config, and optional offline application bundle.
@echo off
setlocal

set "SERVICE=SelfUpdateSupervisor"
set "WRAPPER=C:\Program Files\updated\selfupdate-service.exe"
set "BOOTSTRAP=C:\Program Files\updated\bootstrap.exe"
:: No CONFIG: the bootstrap reads the canonical "C:\Program Files\updated\bootstrap.toml".
set "STATEDIR=C:\ProgramData\updated"
set "SUPERVISOR=C:\Program Files\updated\supervisor.exe"

:: The native wrapper registers directly with SCM, restarts the bootstrap after a
:: crash, and translates SERVICE_CONTROL_STOP into a targeted CTRL_BREAK event.
:: The launcher shuts the agent down cleanly on that event; workload processes
:: belong to each release's reconciler hooks and are never signalled here.
:: A later service start launches a fresh launcher and agent.
set "BINPATH=\"%WRAPPER%\" --bootstrap \"%BOOTSTRAP%\" --state-dir \"%STATEDIR%\" --supervisor \"%SUPERVISOR%\""
sc.exe create "%SERVICE%" binPath= "%BINPATH%" start= auto DisplayName= "Self-updating supervisor"
if errorlevel 1 exit /b %errorlevel%
sc.exe description "%SERVICE%" "Native SCM host for the installer-owned self-update bootstrap"
sc.exe failure "%SERVICE%" reset= 86400 actions= restart/2000/restart/5000/restart/30000
sc.exe failureflag "%SERVICE%" 1

:: Run with a restricted virtual service account. Only mutable state is writable;
:: the wrapper, bootstrap, config, and pinned TUF root remain Administrator-owned.
sc.exe config "%SERVICE%" obj= "NT SERVICE\%SERVICE%" password= ""
if not exist "%STATEDIR%" mkdir "%STATEDIR%"
icacls "%STATEDIR%" /grant "NT SERVICE\%SERVICE%:(OI)(CI)M"

sc.exe start "%SERVICE%"
endlocal
