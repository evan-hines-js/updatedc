:: Native Windows SCM deployment for the self-update tower. Run from an elevated
:: Administrator command prompt after installing the launcher, agent, pinned
:: signed enrollment bundle, launcher config, and optional offline application bundle.
@echo off
setlocal

set "SERVICE=SelfUpdateAgent"
set "WRAPPER=C:\Program Files\updated\selfupdate-service.exe"
set "LAUNCHER=C:\Program Files\updated\updated-launcher.exe"
:: No CONFIG: the launcher reads the canonical "C:\Program Files\updated\config.toml".
set "STATEDIR=C:\ProgramData\updated"
set "AGENT=C:\Program Files\updated\updated-agent.exe"

:: The native wrapper registers directly with SCM, restarts the launcher after a
:: crash, and translates SERVICE_CONTROL_STOP into a targeted CTRL_BREAK event.
:: The launcher shuts the agent down cleanly on that event; workload processes
:: belong to each release's reconciler hooks and are never signalled here.
:: A later service start launches a fresh launcher and agent.
set "BINPATH=\"%WRAPPER%\" --launcher \"%LAUNCHER%\" --state-dir \"%STATEDIR%\" --agent \"%AGENT%\""
sc.exe create "%SERVICE%" binPath= "%BINPATH%" start= auto DisplayName= "Self-updating agent"
if errorlevel 1 exit /b %errorlevel%
sc.exe description "%SERVICE%" "Native SCM host for the installer-owned self-update launcher"
sc.exe failure "%SERVICE%" reset= 86400 actions= restart/2000/restart/5000/restart/30000
sc.exe failureflag "%SERVICE%" 1

:: Run with a restricted virtual service account. Only mutable state is writable;
:: the wrapper, launcher, config, and pinned TUF root remain Administrator-owned.
sc.exe config "%SERVICE%" obj= "NT SERVICE\%SERVICE%" password= ""
if not exist "%STATEDIR%" mkdir "%STATEDIR%"
icacls "%STATEDIR%" /grant "NT SERVICE\%SERVICE%:(OI)(CI)M"

sc.exe start "%SERVICE%"
endlocal
