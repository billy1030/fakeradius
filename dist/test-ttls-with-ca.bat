@echo off
REM Test EAP-TTLS authentication WITH CA (Expect TRUSTED)
REM Usage: test-ttls-with-ca.bat [secret] [username] [password]

set SECRET=%1
if "%SECRET%"=="" set SECRET=testing123

set USERNAME=%2
if "%USERNAME%"=="" set USERNAME=test

set PASSWORD=%3
if "%PASSWORD%"=="" set PASSWORD=test

echo Testing EAP-TTLS WITH CA (ca.pem)...
echo.

"%~dp0multi\windows-amd64\radius-cli.exe" --secret %SECRET% --username %USERNAME% --password %PASSWORD% --ttls --ca ca.pem

pause
