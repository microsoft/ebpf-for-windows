cd /D "%~dp0"

dotnet test Various/ClassLibrary.Tests/ClassLibrary.Tests.csproj --blame --logger trx;LogFileName=%~dp0TestResults/results.trx ||  exit /b 1
