$url = "https://download.java.net/java/GA/jdk14.0.1/664493ef4a6946b186ff29eb326336a2/7/GPL/openjdk-14.0.1_windows-x64_bin.zip"
$fileName = "OpenJDK.zip"
$source = "C:\Downloads\$fileName"
$destination = "C:\Program Files\Java\"
$envVarKey = "JAVA_HOME"
$envVarValue = "C:\Program Files\Java\jdk-14.0.1"
$pathUpdate = "C:\Program Files\Java\jdk-14.0.1\bin"

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
