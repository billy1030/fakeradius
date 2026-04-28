@echo off
REM Test PAP authentication with a normal user (should get Access-Accept)
REM Usage: test-pap-user.bat [username] [secret] [server]
REM Default: username="alice", secret="testing123", server="127.0.0.1:1812"

set USERNAME=%1
if "%USERNAME%"=="" set USERNAME=alice

set SECRET=%2
if "%SECRET%"=="" set SECRET=testing123

set SERVER=%3
if "%SERVER%"=="" set SERVER=127.0.0.1:1812

echo Testing RADIUS PAP authentication with normal user...
echo Username: %USERNAME%
echo Server: %SERVER%
echo Platform: windows-amd64
echo Auth Mode: PAP
echo.

"%~dp0multi\windows-amd64\radius-cli.exe" --username %USERNAME% --password testpass123 --secret %SECRET% --server %SERVER%
