@echo off

echo "Install Perl"
powershell -file "%~dp0install-perl.ps1" || exit \b 1

echo "C:\Strawberry\perl\bin"
dir "C:\Strawberry\perl\bin"

echo "Successfully installed Perl"
