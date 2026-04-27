@echo off
REM Start the Fake RADIUS Server
REM Usage: start-server.bat [secret]
REM Default secret is "testing123" if not provided

set SECRET=%1
if "%SECRET%"=="" set SECRET=testing123

echo Starting Fake RADIUS Server...
echo Secret: %SECRET%
echo Listening on: UDP :1812
echo.

fakeradius-server.exe --secret %SECRET%
