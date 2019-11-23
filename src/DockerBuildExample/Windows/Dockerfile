# escape=`
FROM cdpxwinrs5test.azurecr.io/global/windows/windows-servercore-base-winltsc2019:latest

RUN "DISM.EXE /Online /Cleanup-Image /CheckHealth"

COPY docker-build-common.ps1 C:\
COPY install*.* C:\

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
RUN C:\install-0.ps1 ; exit 0

SHELL ["cmd", "/S", "/C"]
RUN del C:\install*.* ; exit 0

ENV PATH="C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Users\ContainerAdministrator\AppData\Local\Microsoft\WindowsApps;C:\ProgramData\chocolatey\bin;C:\SysInternalsSuite;C:\7-Zip;C:\NuGet;C:\Program Files\Git\cmd;C:\NuGet;C:\Program Files\Git\bin;C:\Program Files\dotnet"