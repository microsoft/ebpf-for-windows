@echo off

echo "Install Ruby"
powershell -file "%~dp0install-ruby.ps1" || exit \b 1


echo "C:\Ruby"
dir "C:\Ruby"
echo "C:\Ruby\bin"
dir "C:\Ruby\bin"

echo "Successfully installed Ruby"
