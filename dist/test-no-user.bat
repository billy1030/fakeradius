@echo off
REM Test with a "no_" prefixed user (should get Access-Reject)
REM Usage: test-no-user.bat [username] [secret] [server]
REM Default: username="no_admin", secret="testing123", server="127.0.0.1:1812"

set USERNAME=%1
if "%USERNAME%"=="" set USERNAME=no_admin

set SECRET=%2
if "%SECRET%"=="" set SECRET=testing123

set SERVER=%3
if "%SERVER%"=="" set SERVER=127.0.0.1:1812

echo Testing RADIUS authentication with no_ prefix user...
echo Username: %USERNAME% (should be REJECTED)
echo Server: %SERVER%
echo.

"%~dp0radius-cli.exe" --username %USERNAME% --password testpass123 --secret %SECRET% --server %SERVER%
