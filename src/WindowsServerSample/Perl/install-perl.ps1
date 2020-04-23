$url = "http://strawberryperl.com/download/5.30.2.1/strawberry-perl-5.30.2.1-64bit.zip"
$fileName = "strawberry-perl-5.30.2.1-64bit.zip"
$source = "C:\Downloads\$fileName"
$destination = "C:\Strawberry"
$envVarKey = "PERL"
$envVarValue = "C:\Strawberry"
$pathUpdate = "C:\Strawberry\perl\bin"

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