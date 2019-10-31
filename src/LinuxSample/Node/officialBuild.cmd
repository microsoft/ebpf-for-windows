@echo off
call %~dp0build.cmd https://OFFICIAL_REDIRECT_URL OFFICIAL_CLIENT_ID OFFICIAL_APP_INSIGHTS_KEY || exit /b 1
exit /b %exit_code%y
