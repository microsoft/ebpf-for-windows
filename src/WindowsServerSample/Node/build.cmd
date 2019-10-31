@echo off

:CHECKBUILDARGS
echo %1
echo %2
echo %3

:SETUP
set "BABEL_ENV=production"
set "NODE_ENV=production"

set "REACT_APP_CLIENT_ID=%1"
set "REACT_APP_TENANT=microsoft.onmicrosoft.com"
set "REACT_APP_APP_INSIGHTS_KEY=%3"
set "REACT_APP_AUTH=adal"
set "REACT_APP_ENVIRONMENT=production"
set "REACT_APP_REDIRECT_URI=%2"
set "EXPECTED_OUTPUT=build/static"

pushd "%~dp0oe-template"

:CLEANUP

:: Clean output directories if they exist
echo *********************************************************************************
echo *
echo * Clean out output directories
echo *
echo *********************************************************************************

if exist build rmdir build /s/q

:BUILD

echo *********************************************************************************
echo *
echo * Assemble with react-scripts
echo *
echo *********************************************************************************
dir

call npm run build

if errorlevel 1 goto FAIL

:CHECKRESULTS
echo in CHECKRESULTS
ECHO "Expected Output: %EXPECTED_OUTPUT%"

IF NOT EXIST %EXPECTED_OUTPUT% (
  ECHO NO static folder
  dir
  GOTO FAIL
)

:NORMALFINISH
echo Build SUCCEEDED.
dir
set exit_code=0
goto END

:FAIL
echo Build FAILED.
set exit_code=1

:END
popd
exit /b %exit_code%
