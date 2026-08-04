@echo off
REM Start the Fake RADIUS Server
REM Usage: start-server.bat [secret] [logfile]
REM Default secret is "testing123", logfile is "server.log"

set SECRET=%1
if "%SECRET%"=="" set SECRET=testing123

set LOGFILE=%2
if "%LOGFILE%"=="" set LOGFILE=server.log

echo Starting Fake RADIUS & TACACS+ Server...
echo Secret: %SECRET%
echo Log file: %LOGFILE%
echo Platform: windows-amd64
echo RADIUS Listening:  UDP :1812
echo TACACS+ Listening: TCP :49
echo Auth Modes: PAP, CHAP, MS-CHAP v1/v2, EAP-TTLS, TACACS+
echo.

"%~dp0multi\windows-amd64\fakeradius-server.exe" --secret %SECRET% --log %LOGFILE% --tacacs-addr :4949
