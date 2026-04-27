@echo off
REM Start the Fake RADIUS Server
REM Usage: start-server.bat [secret] [logfile]
REM Default secret is "testing123", logfile is "server.log"

set SECRET=%1
if "%SECRET%"=="" set SECRET=testing123

set LOGFILE=%2
if "%LOGFILE%"=="" set LOGFILE=server.log

echo Starting Fake RADIUS Server...
echo Secret: %SECRET%
echo Log file: %LOGFILE%
echo Listening on: UDP :1812
echo.

"%~dp0fakeradius-server.exe" --secret %SECRET% --log %LOGFILE%
