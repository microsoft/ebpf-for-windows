cd /D "%~dp0"

call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\Common7\Tools\VsDevCmd.bat"

call msbuild MSBuildSample\HelloWorld.csproj /p:Configuration=Release || exit /b 1
