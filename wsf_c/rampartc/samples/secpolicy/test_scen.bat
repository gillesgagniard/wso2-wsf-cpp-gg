@echo off
if "%1" == "" goto end
if "%2" == "" goto end

set _SMPL_DIR=%cd%
set _SLEEP=3

echo -------------------------------------------------------------------------
echo Deploying %1
echo -------------------------------------------------------------------------

call deploy.bat %1
@echo off

echo Killing server
taskkill /F /IM axis2_http_server.exe

echo Go to %AXIS2C_HOME%
cd %AXIS2C_HOME%/bin

echo Start server @ %2
start /min axis2_http_server.exe -p%2

rem echo Sleeping for %_SLEEP% seconds
echo waiting.......
pause %_SLEEP%

echo Go to client directory and run the sample
cd %AXIS2C_HOME%/samples/bin/rampartc
if not "%1" == "scenario14"  goto else
	call saml_update_n_run.bat
	goto endif
:else
	call update_n_run.bat
:endif

@echo off

echo Killing server
taskkill /F /IM axis2_http_server.exe

echo Jump back to samples dir :%_SMPL_DIR%
cd %_SMPL_DIR%

goto superend

:end
echo usage %0 scenarioxx server_port

:superend
if "%3" == "" @echo on
