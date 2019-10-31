cd /D "%~dp0"

dotnet restore Various\Various.sln || exit /b 1
