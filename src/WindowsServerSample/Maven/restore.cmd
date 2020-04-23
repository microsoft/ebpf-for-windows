@echo off

pushd "%~dp0"

echo "Install Maven"
powershell -file "%~dp0install-maven.ps1" || exit \b 1

echo "C:\Maven\bin"
dir "C:\Maven\bin"

echo "Successfully installed Maven"

popd
