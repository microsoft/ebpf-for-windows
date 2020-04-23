@echo off

echo "Install Java"
powershell -file "%~dp0install-java.ps1" || exit \b 1

echo "C:\Program Files\Java\jdk-14.0.1\bin"
dir "C:\Program Files\Java\jdk-14.0.1\bin"

echo "Successfully installed Java"
