@echo off
REM Test TACACS+ authentication with a normal user (should get PASS)
REM Usage: test-tacacs-user.bat [username] [secret] [server]
REM Default: username="peter", secret="testing123", server="127.0.0.1:4949"

set USERNAME=%1
if "%USERNAME%"=="" set USERNAME=peter

set SECRET=%2
if "%SECRET%"=="" set SECRET=testing123

set SERVER=%3
if "%SERVER%"=="" set SERVER=127.0.0.1:4949

echo Testing TACACS+ authentication with normal user...
echo Username: %USERNAME%
echo Server: %SERVER%
echo Platform: windows-amd64
echo Protocol: TACACS+ (TCP)
echo.

"%~dp0multi\windows-amd64\radius-cli.exe" --username %USERNAME% --password testpass123 --secret %SECRET% --server %SERVER% --tacacs
