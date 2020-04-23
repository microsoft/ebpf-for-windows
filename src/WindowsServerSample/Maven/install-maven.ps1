$url = "https://downloads.apache.org/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.zip"
$fileName = "apache-maven-3.6.3-bin.zip"
$source = "C:\Downloads\$fileName"
$destination = "C:\Downloads"
$moveStart = "C:\Downloads\apache-maven-3.6.3"
$moveDestination = "C:\Maven"
$envVarKey = "MAVEN"
$envVarValue = "C:\Maven"
$pathUpdate = "C:\Maven\bin"

$ErrorActionPreference = "Stop"

if (Test-Path "$PSScriptRoot\win-installer-helper.psm1") 
{
    Import-Module "$PSScriptRoot\win-installer-helper.psm1" -DisableNameChecking
} elseif (Test-Path "$PSScriptRoot\..\..\Helpers\win-installer-helper.psm1") 
{
    Import-Module "$PSScriptRoot\..\..\Helpers\win-installer-helper.psm1" -DisableNameChecking
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