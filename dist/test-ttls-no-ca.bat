@echo off
REM Test EAP-TTLS authentication WITHOUT CA (Expect UNTRUSTED)
REM Usage: test-ttls-no-ca.bat [secret] [username] [password]

set SECRET=%1
if "%SECRET%"=="" set SECRET=testing123

set USERNAME=%2
if "%USERNAME%"=="" set USERNAME=test

set PASSWORD=%3
if "%PASSWORD%"=="" set PASSWORD=test

echo Testing EAP-TTLS without CA...
echo.

"%~dp0multi\windows-amd64\radius-cli.exe" --secret %SECRET% --username %USERNAME% --password %PASSWORD% --ttls

pause
