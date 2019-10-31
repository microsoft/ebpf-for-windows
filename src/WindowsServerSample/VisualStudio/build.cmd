cd /D "%~dp0"
dotnet build --no-restore Various\Various.sln || exit /b 1
