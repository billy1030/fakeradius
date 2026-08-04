@echo off
REM Test TACACS+ authentication with a rejected user (no_ prefix, should get FAIL)
REM Usage: test-tacacs-no-user.bat [username] [secret] [server]
REM Default: username="no_admin", secret="testing123", server="127.0.0.1:4949"

set USERNAME=%1
if "%USERNAME%"=="" set USERNAME=no_admin

set SECRET=%2
if "%SECRET%"=="" set SECRET=testing123

set SERVER=%3
if "%SERVER%"=="" set SERVER=127.0.0.1:4949

echo Testing TACACS+ authentication with rejected user (no_ prefix)...
echo Username: %USERNAME%
echo Server: %SERVER%
echo Platform: windows-amd64
echo Protocol: TACACS+ (TCP)
echo.

"%~dp0multi\windows-amd64\radius-cli.exe" --username %USERNAME% --password testpass123 --secret %SECRET% --server %SERVER% --tacacs
