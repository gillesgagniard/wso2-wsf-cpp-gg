@echo off
echo -------------------------------------------------------------------------
echo deploying rampart...
echo -------------------------------------------------------------------------

xcopy .\include %AXIS2C_HOME%\include /E /I /Y /S
xcopy .\lib %AXIS2C_HOME%\lib /E /I /Y /S
xcopy .\modules %AXIS2C_HOME%\modules /E /I /Y /S
xcopy .\samples %AXIS2C_HOME%\samples /E /I /Y /S
xcopy .\services %AXIS2C_HOME%\services /E /I /Y /S
copy .\samples\src\rampartc\data\server_axis2.xml %AXIS2C_HOME%\axis2.xml

echo -------------------------------------------------------------------------
echo Rampart deployed
echo -------------------------------------------------------------------------
@echo on
