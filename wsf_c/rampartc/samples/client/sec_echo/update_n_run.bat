@echo off
rem if your client repository is different, change the value.
set CLIENT_REPO=%AXIS2C_HOME%

%AXIS2C_HOME%\samples\bin\rampartc\sec_echo.exe http://localhost:9090/axis2/services/sec_echo %CLIENT_REPO%

@echo on
