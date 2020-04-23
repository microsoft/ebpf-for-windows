$url = "{url_for_zipped_tool}"
$fileName = "{zip_file}"
$source = "C:\Downloads\$fileName"
$destination = "C:\Downloads"
$moveStart = "C:\Downloads\{folder_name}"
$moveDestination = "C:\{folder_name}" # may be in Program Files, whatever you want
$envVarKey = "{tool_name}"
$envVarValue = "C:\{folder_name}"
$pathUpdate = "C:\{folder_name}\bin" # probably includes bin, but point to where your tool lives
$arguments = "{your_tools_install_values_here}" 
# Arguements could be many things and depends on your tool.  It might look like this 
# "LicenseAccepted=1" 
# OR
# "/quiet InstallAllUsers=1 CompileAll=1 PrependPath=1" 
# OR
# "/InstallationType=JustMe /RegisterPython=0 /S /D=C:\Program Files\Miniconda3" 
# OR
# "/S" 
# OR
# "/SP- /VERYSILENT /SUPPRESSMSGBOXES /FORCECLOSEAPPLICATIONS /NORESTART"

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
    Install-FromMSI -Path "C:\Downloads\"$fileName -Arguments $arguments
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
