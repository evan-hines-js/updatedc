:: Native Windows SCM deployment for the self-update tower. Run from an elevated
:: Administrator command prompt after replacing the paths/version tokens in the
:: installed config.toml.
@echo off
setlocal

set "SERVICE=SelfUpdateSupervisor"
set "WRAPPER=C:\Program Files\selfupdate\selfupdate-service.exe"
set "BOOTSTRAP=C:\Program Files\selfupdate\bootstrap.exe"
set "CONFIG=C:\Program Files\selfupdate\config.toml"
set "STATEDIR=C:\ProgramData\selfupdate"
set "SUPERVISOR=C:\Program Files\selfupdate\supervisor.exe"

:: The native wrapper registers directly with SCM, restarts the bootstrap after a
:: crash, and translates SERVICE_CONTROL_STOP into a targeted CTRL_BREAK event.
:: The bootstrap launches the application in a separate process group so it does not
:: receive that console event directly; the bootstrap then shuts it down cleanly.
:: A later service start launches a fresh guardian and application process.
set "BINPATH=\"%WRAPPER%\" --bootstrap \"%BOOTSTRAP%\" --state-dir \"%STATEDIR%\" --supervisor-config \"%CONFIG%\" --supervisor \"%SUPERVISOR%\""
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
