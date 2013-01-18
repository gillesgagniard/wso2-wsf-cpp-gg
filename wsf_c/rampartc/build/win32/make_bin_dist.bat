set BINDIST=..\rampartc-bin-1.3.0-win32
if exist %BINDIST% rd /s /q %BINDIST%
mkdir %BINDIST%
xcopy /E /I /Y ..\rampartc-1.3.0\* %BINDIST%\

