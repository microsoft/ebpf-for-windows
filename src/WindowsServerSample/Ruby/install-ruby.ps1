$url = "https://github.com/oneclick/rubyinstaller2/releases/download/RubyInstaller-2.7.1-1/rubyinstaller-2.7.1-1-x64.7z"
$fileName = "rubyinstaller-2.7.1-1-x64.7z"
$source = "C:\Downloads\$fileName"
$destination = "C:\Downloads"
$moveStart = "C:\Downloads\rubyinstaller-2.7.1-1-x64"
$moveDestination = "C:\Ruby"
$envVarKey = "RUBY"
$envVarValue = "C:\Ruby"
$pathUpdate = "C:\Ruby\bin"

$ErrorActionPreference = "Stop"

if (Test-Path "$PSScriptRoot\win-installer-helper.psm1") 
{
    Import-Module "$PSScriptRoot\win-installer-helper.psm1"
} elseif (Test-Path "$PSScriptRoot\..\..\Helpers\win-installer-helper.psm1") 
{
    Import-Module "$PSScriptRoot\..\..\Helpers\win-installer-helper.psm1"
}

Start-Setup
$PathNodes=@()
try 
{
    Get-File -Url $url -FileName $fileName
    Expand-ArchiveWith7Zip -Source $source -Destination $destination
    Move-Item -Path $moveStart -Destination $moveDestination -Force
    Add-EnvironmentVariable -Name $envVarKey -Value $envVarValue
    $PathNodes += $pathUpdate
} 
finally 
{
    if (!$PathNodes -eq "")
    {
      Update-Path -PathNodes $PathNodes                            
    }
    Stop-Setup
}