@echo off
call %~dp0build.cmd https://PPE_REDIRECT_URL PPE_CLIENT_ID PPE_APP_INSIGHTS_KEY || exit /b 1
exit /b %exit_code%
