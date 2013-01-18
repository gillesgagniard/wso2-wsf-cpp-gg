@echo off
::Here we have scenario 5 as the default 
SET scn=scenario5
IF NOT "%1" == "" SET scn=%1

echo Deploying %scn%
echo Copying %scn%\client policy file
deploy.js %scn%\client-policy.xml %AXIS2C_HOME%\policy.xml
echo Copying %scn%\services.xml
deploy.js %scn%\services.xml %AXIS2C_HOME%\services\sec_echo\services.xml

if not exist  %scn%\sts.xml goto no_sts_policy
echo Copying %scn%\sts.xml
deploy.js %scn%\sts.xml %AXIS2C_HOME%\services\secconv_echo\services.xml

:no_sts_policy
if not exist %scn%\rahas_module.xml goto no_rahas_policy
echo Copying %scn%\rahas_module.xml
deploy.js %scn%\rahas_module.xml %AXIS2C_HOME%\modules\rahas\module.xml

:no_rahas_policy
@echo on
