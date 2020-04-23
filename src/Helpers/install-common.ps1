param([string]$InstallType)
param([string]$Url)
param([string]$FileName)
param([string]$Destination)
param([string]$Arguments)
param([string]$EnvVarKey)
param([string]$EnvVarValue)
param([string]$PathUpdate)

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
    $InstallType = $InstallType.ToLower()

    Get-File -Url $Url -FileName $FileName

    if ($InstallType -eq "zip") {
      Write-Host "Expanding zip file"
      Expand-ArchiveWith7Zip -Source "C:\Downloads\"$FileName -Destination $Destination
    } elseif ($InstallType -eq "msi") {
      Write-Host "Installing from MSI"
      Install-FromMSI -Path "C:\Downloads\"$FileName -Arguments $Arguments
    } else {
      Write-Host "No type or type not recognized."
      Exit 1
    }

    Add-EnvironmentVariable -Name $EnvVarKey -Value $EnvVarValue
    $PathNodes += $PathUpdate
} 
finally 
{
    if (!$PathNodes -eq "")
    {
      Write-Host "Updating PATH"
      Update-Path -PathNodes $PathNodes                            
    }
    Stop-Setup
}