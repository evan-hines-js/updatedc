:: Native Windows SCM deployment for the directly supervised agent. Run from an elevated
:: Administrator command prompt after installing the service host, agent, pinned
:: signed enrollment bundle, agent config, and optional offline application bundle.
@echo off
setlocal

:: The override names are for the SCM E2E harness and managed packaging. An ordinary elevated
:: install sets none of them and receives the canonical paths below.
if not defined UPDATED_WINDOWS_SERVICE set "UPDATED_WINDOWS_SERVICE=UpdatedAgent"
if not defined UPDATED_WINDOWS_WRAPPER set "UPDATED_WINDOWS_WRAPPER=C:\Program Files\updated\updated-agent-service.exe"
if not defined UPDATED_WINDOWS_STATE_DIR set "UPDATED_WINDOWS_STATE_DIR=C:\ProgramData\updated"
if not defined UPDATED_WINDOWS_AGENT set "UPDATED_WINDOWS_AGENT=C:\Program Files\updated\updated-agent.exe"
if not defined UPDATED_WINDOWS_START set "UPDATED_WINDOWS_START=auto"
set "SERVICE=%UPDATED_WINDOWS_SERVICE%"
set "WRAPPER=%UPDATED_WINDOWS_WRAPPER%"
set "STATEDIR=%UPDATED_WINDOWS_STATE_DIR%"
set "AGENT=%UPDATED_WINDOWS_AGENT%"

:: The native wrapper registers directly with SCM and translates SERVICE_CONTROL_STOP into a
:: targeted CTRL_BREAK event for the agent. SCM recovery restarts the service after a crash;
:: workload processes
:: belong to each release's reconciler hooks and are never signalled here.
:: A later service start launches a fresh agent.
set "CONFIGARG="
if defined UPDATED_WINDOWS_CONFIG set "CONFIGARG= --config \"%UPDATED_WINDOWS_CONFIG%\""
set "BINPATH=\"%WRAPPER%\" --state-dir \"%STATEDIR%\"%CONFIGARG% --agent \"%AGENT%\""

:: Configuration management is machine-wide: reconcilers may manage services, users, packages,
:: networking, and reboot the host. Create the service directly as LocalSystem so there is no
:: later account transition and no partially configured privilege boundary.
sc.exe create "%SERVICE%" binPath= "%BINPATH%" start= "%UPDATED_WINDOWS_START%" obj= LocalSystem DisplayName= "Updated agent"
if errorlevel 1 exit /b %errorlevel%
sc.exe description "%SERVICE%" "Native SCM host for the installer-owned updated agent"
if errorlevel 1 goto :failed
sc.exe failure "%SERVICE%" reset= 86400 actions= restart/2000/restart/5000/restart/30000
if errorlevel 1 goto :failed
sc.exe failureflag "%SERVICE%" 1
if errorlevel 1 goto :failed

if not exist "%STATEDIR%" mkdir "%STATEDIR%"
if errorlevel 1 goto :failed

:: Verify the security property from SCM rather than trusting command success.
sc.exe qc "%SERVICE%" | %SystemRoot%\System32\findstr.exe /I /L /C:"LocalSystem" >nul
if errorlevel 1 goto :failed

sc.exe start "%SERVICE%"
if errorlevel 1 goto :failed
endlocal & exit /b 0

:failed
set "INSTALL_ERROR=%errorlevel%"
:: This invocation created the service, so a partial configuration is ours to remove. Stop is best
:: effort; DELETE is the operation that prevents a later boot from running the incomplete service.
sc.exe stop "%SERVICE%" >nul 2>&1
sc.exe delete "%SERVICE%" >nul 2>&1
endlocal & exit /b %INSTALL_ERROR%
