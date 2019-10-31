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

pushd %~dp0oe-template

:: // copy ourselvees IIF endor Build
if "%3"=="endorbuild" goto ENDORBUILD
goto SKIPENDOR

:ENDORBUILD

call robocopy oe-template %tmp%\infrabuild\ /s
pushd %tmp%\infrabuild

:SKIPENDOR

:: Clean output directories if they exist
echo *********************************************************************************
echo *
echo * Clean out output directories
echo *
echo *********************************************************************************

if exist build rmdir build /s/q

:: check to see if we have parameter indicating 'compile only'
if "%1"=="notest" goto SKIPTEST

:: errorlevel greater than 7 - is intentional. see
:: https://blogs.technet.microsoft.com/deploymentguys/2008/06/16/robocopy-exit-codes/
:: for more details
if errorlevel 7 goto FAIL

:SKIPTEST

echo *********************************************************************************
echo *
echo * Assemble with react-scripts
echo *
echo *********************************************************************************

goto ENDSCRIPTSELECT

:ENDSCRIPTSELECT

call node_modules\.bin\react-scripts build

if errorlevel 1 goto FAIL

echo *********************************************************************************
echo *
echo * Copy output files
echo *
echo *********************************************************************************

:COPY_FILES
call robocopy . .\build\ /s /xd "node_modules" "src" "build" "public" /xf  ".npmrc" "package.json" "package-lock.json" "README.md"

if "%3"=="endorbuild" goto ENDORBUILDDONE
goto NORMALFINISH

:ENDORBUILDDONE

popd

call robocopy %tmp%\infrabuild\build\ .\build\ /s /xd "node_modules" "src" "build" "public" /xf ".npmrc" "package.json" "package-lock.json" "README.md"

:NORMALFINISH

:: errorlevel greater than 7 - is intentional. see
:: https://blogs.technet.microsoft.com/deploymentguys/2008/06/16/robocopy-exit-codes/
:: for more details
if errorlevel 7 goto FAIL

echo Build SUCCEEDED.
set exit_code=0
goto END

:FAIL
echo Build FAILED.
set exit_code=1

:END
popd
exit /b %exit_code%
