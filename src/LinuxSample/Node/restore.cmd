cd /D "%~dp0oe-template"
echo "STARTING NPM INSTALL"
call npm install --force || exit /b 1
echo "FINISHED NPM INSTALL"
