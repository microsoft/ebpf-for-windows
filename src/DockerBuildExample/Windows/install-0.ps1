
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (Test-Path "C:\docker-build-common.ps1") {
  . "C:\docker-build-common.ps1"
} elseif (Test-Path "$PSScriptRoot\docker-build-common.ps1") {
  . "$PSScriptRoot\docker-build-common.ps1"
}

GlobalStart

try {
    DownloadInstaller -sourceUrl "https://nodejs.org/dist/v12.13.1/node-v12.13.1-x64.msi" -fileName "node-v12.13.1-x64.msi"
	  InstallMSI -fileName "node-v12.13.1-x64.msi"
    SetEnvironmentVariable -name "NODE" -value "C:\Program Files\nodejs"

    DownloadInstaller -sourceUrl "https://github.com/wixtoolset/wix3/releases/download/wix3112rtm/wix311.exe" -fileName "wix311.exe"
    InstallEXE -fileName "wix311.exe" -arguments "-s -norestart"
    SetEnvironmentVariable -name "WIX" -value "C:\Program Files (x86)\Wix Toolset v3.11"
    
    CleanupTempFolders
} finally {
	  GlobalEnd
}
