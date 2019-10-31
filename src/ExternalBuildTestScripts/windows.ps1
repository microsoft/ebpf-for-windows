Write-Host "You successfully launched a custom workflow on a Windows host from the parent build: $env:Parent_Build_BuildId"
Write-Host "Dumping env"
Get-Childitem env:
