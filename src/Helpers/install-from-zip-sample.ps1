$url = "{url_for_zipped_tool}"
$fileName = "{zip_file}"
$source = "C:\Downloads\$fileName"
$destination = "C:\Downloads"
$moveStart = "C:\Downloads\{folder_name}"
$moveDestination = "C:\{folder_name}" # may be in Program Files, whatever you want
$envVarKey = "{tool_name}"
$envVarValue = "C:\{folder_name}"
$pathUpdate = "C:\{folder_name}\bin" # probably includes bin, but point to where your tool lives

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
    Move-Item -Path $moveStart -Destination $moveDestination -Force # may or may not need this
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