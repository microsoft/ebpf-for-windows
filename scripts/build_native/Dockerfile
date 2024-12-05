# escape=`
# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

# Use the latest Windows Server Core 2022 image.
FROM mcr.microsoft.com/windows/servercore:ltsc2022

# Restore the default Windows shell for correct batch processing.
SHELL ["cmd", "/S", "/C"]

RUN `
    # Download the Build Tools bootstrapper.
    curl -SL --output vs_community.exe https://aka.ms/vs/17/release/vs_community.exe `
    `
    # Install Build Tools with the Microsoft.VisualStudio.Workload.AzureBuildTools workload, excluding workloads and components with known issues.
    && (start /w vs_community.exe --quiet --wait --norestart --nocache `
        --installPath "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools" `
        # Add the Azure build tools workload.
        --add Microsoft.VisualStudio.Workload.AzureBuildTools `
        # Add the Windows 11 SDK.
        --add Microsoft.VisualStudio.Component.Windows11SDK.26100 `
        # Add the Visual C++ build tools workload.
        --add Microsoft.VisualStudio.Workload.VCTools `
        # Add Spectre libraries.
        --add Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre `
        --add Microsoft.VisualStudio.Component.VC.Runtimes.ARM64.Spectre `
        --add Component.Microsoft.Windows.DriverKit `
        || IF "%ERRORLEVEL%"=="3010" EXIT 0) `
    `
    # Cleanup
    && del /q vs_community.exe `
    # Install the NuGet CLI.
    && mkdir c:\packages `
    && cd c:\packages `
    && curl -o nuget.exe https://dist.nuget.org/win-x86-commandline/latest/nuget.exe `
    # Install the Windows 10 SDK and WDK.
    && .\nuget.exe install Microsoft.Windows.SDK.CPP -Version 10.0.26100.2161 `
    && .\nuget.exe install Microsoft.Windows.WDK.x64 -Version 10.0.26100.2161 `
    && .\nuget.exe install -ExcludeVersion eBPF-for-Windows.x64

RUN C:\packages\eBPF-for-Windows.x64\build\native\bin\export_program_info.exe

WORKDIR c:\data
COPY build.ps1 c:\build.ps1

# Define the entry point for the docker container.
# This entry point starts the developer command prompt and launches the PowerShell shell.
ENTRYPOINT ["C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\Common7\\Tools\\VsDevCmd.bat", "&&", "powershell.exe", "-NoLogo", "-ExecutionPolicy", "Bypass", "\\build.ps1" ]