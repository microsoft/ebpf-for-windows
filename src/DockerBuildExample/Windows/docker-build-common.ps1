$ErrorActionPreference = "Stop"
$Separator = "--------------------------------------------------------------------------------------------------------------------------------"
$global:GlobalStart = $null
$global:GlobalEnd = $null

function GlobalStart {

    $global:GlobalStart = [System.DateTime]::UtcNow
	Write-Host "$global:GlobalStart : Starting installation ..."

    Write-Host "Disk space -----------------------------"
    gwmi win32_logicaldisk | Format-Table DeviceId, MediaType, {$_.Size /1GB}, {$_.FreeSpace /1GB}

	Write-Host "Creating download location C:\Downloads"
	New-Item -Path "C:\Downloads" -ItemType Container -ErrorAction SilentlyContinue

}

function GlobalEnd {

	param(
		[Parameter(Mandatory=$false)]
		[switch]$cleanDownloads=$true,

		[Parameter(Mandatory=$false)]
		[switch]$cleanTemp=$true,

        [Parameter(Mandatory=$false)]
		[switch]$showInstalled
	)


    if ($cleanDownloads) {
	    Write-Host "Deleting download location C:\Downloads"
	    Remove-Item -Path "C:\Downloads" -Recurse -ErrorAction SilentlyContinue
    }

    if ($cleanTemp) {
        CleanupTempFolders
    }

    Write-Host "----------------------------- Disk space -------------------------------------------"
	gwmi win32_logicaldisk | Format-Table DeviceId, MediaType, {$_.Size /1GB}, {$_.FreeSpace /1GB}

    if ($showInstalled) {

        Write-Host "----------------------------- 32-Bit Sofware installed -----------------------------"
        Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate

        Write-Host "----------------------------- 64-Bit Sofware installed -----------------------------"
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate
    }

	$global:GlobalEnd = [System.DateTime]::UtcNow
	$elapsed = $global:GlobalEnd.Subtract($GlobalStart)
	Write-Host "$global:GlobalEnd : ... finished installation in $elapsed"

}

function DownloadInstaller {

	param(
		[Parameter(Mandatory=$true)]
		[string]$sourceUrl,

		[Parameter(Mandatory=$true)]
		[string]$fileName
	)

    $downloadStart = [System.DateTime]::Now

    Write-Host "Actually using the expected script"

    try {

	    $file = [System.IO.Path]::Combine("C:\Downloads", $fileName)
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	    Write-Host "$downloadStart : Downloading from $sourceUrl to file $file"
	    Invoke-WebRequest -Uri $sourceUrl -UseBasicParsing -OutFile $file -UserAgent "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.0.3705;)"

    } catch {
      Write-Host "Error downloading from $sourceUrl to file $file."
      $_
      Write-Host "That was the error caught trying to download from $sourceUrl to file $file."
    } finally {

        $downloadEnd = [System.DateTime]::Now
        $elapsed = $downloadEnd.Subtract($downloadStart)

        if((Get-ChildItem $file -force | Select-Object -First 1 | Measure-Object).Count -eq 0)
        {
          Write-Warning "Download failed from $sourceUrl. $file is empty."
        } else {
          Write-Host "Download succeeded from $sourceUrl to file $file."
        }

        Write-Host "$downloadEnd : Finished DownloadInstaller in $elapsed"
        Write-Host $Separator
    }
}

function InstallMSI {

	param(
        [Parameter()]
		[switch]$ignoreFailures,

		[Parameter(Mandatory=$true)]
		[string]$fileName,

        [Parameter(Mandatory=$false)]
        [int[]]$ignoreExitCodes,

		[string[]]$arguments
	)

    $msiStart = [System.DateTime]::Now

    try {

	    $file = [System.IO.Path]::Combine("C:\Downloads", $fileName)
        $log = [System.IO.Path]::Combine($env:TEMP, $fileName + ".log")

	    $args = "/quiet /qn /norestart /lv! `"$log`" /i $file $arguments"

	    Write-Host "$msiStart : Running msiexec.exe $args"

	    $process = Start-Process "msiexec.exe" -Wait -PassThru -Verbose -NoNewWindow -ArgumentList $args
        $ex = $process.ExitCode


	    if ($ex -ne 0)
		{
            if ($ex -eq 3010)
            {
		        Write-Host "Install from $file exited with code 3010. Ignoring since that is just indicating restart required."
                return
		    }

            foreach ($iex in $ignoreExitCodes)
            {
                if ($ex -eq $iex)
                {
                    Write-Host "Install from $file succeeded with exit code $ex"
                    return;
                }
            }

	    	Write-Host "Failed to install from $file. Process exited with code $ex"

            if (-not $ignoreFailures)
            {
	    	    exit $ex
            }
        }

    } finally {
        $msiEnd = [System.DateTime]::Now
        $elapsed = $msiEnd.Subtract($msiStart)

        Write-Host "$msiEnd : Finished install in $elapsed"
        Write-Host $Separator
    }
}

function InstallEXE {

	param(
        [Parameter()]
		[switch]$fullPath,

        [Parameter()]
		[switch]$ignoreFailures,

		[Parameter(Mandatory=$true)]
		[string]$fileName,

        [Parameter(Mandatory=$false)]
        [int[]]$ignoreExitCodes,

		[string[]]$arguments
	)

    $exeStart = [System.DateTime]::Now

    try {
		$file = $fileName

		if (-not $fullPath) {
			$file = [System.IO.Path]::Combine("C:\Downloads", $fileName)
		}

	    Write-Host "$exeStart : Running $file $arguments"

	    $process = Start-Process $file -Wait -PassThru -Verbose -NoNewWindow -ArgumentList $arguments
        $ex = $process.ExitCode

        if ($ex -ne 0)
	    {
            foreach ($iex in $ignoreExitCodes)
            {
                if ($ex -eq $iex)
                {
                    Write-Host "Install from $file succeeded with exit code $ex"
                    return;
                }
            }

		    Write-Host "Failed to install from $file. Process exited with code $ex"

            if (-not $ignoreFailures)
            {
		        exit $ex
            }
	    }

    } catch {
      Write-Host "Error installing $fileName."
      $_
      Write-Host "That was the error caught trying to install $fileName."
    } finally {

        $exeEnd = [System.DateTime]::Now
        $elapsed = $exeEnd.Subtract($exeStart)

        Write-Host "$exeEnd : Finished install in $elapsed"
        Write-Host $Separator

    }
}

function SetEnvironmentVariable {

    param(
        [Parameter(Mandatory=$true)]
        [string]$name,

        [Parameter(Mandatory=$true)]
        [string]$value
    )

    Write-Host "Setting environment variable $name := $value"
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Environment" -ItemType String -Force -Name $name -Value $value
    [System.Environment]::SetEnvironmentVariable($name, $value, [EnvironmentVariableTarget]::Machine)
    &setx.exe /m $name $value

}

function UpdatePath {

    param(
        [Parameter(Mandatory=$true)]
        [string]$update
    )

    $path = $env:Path

    Write-Host "Current value of PATH := $path"
    Write-Host "Appending $update to PATH"

    $path = $path + ";" + $update

    Write-Host "Updated PATH is $path"

    [System.Environment]::SetEnvironmentVariable("PATH", $path, [EnvironmentVariableTarget]::Machine)
    &setx.exe /m PATH "$path"
}

function VerifyFileHash {

    param(
        [Parameter(Mandatory=$true)]
        [string]$fileName,

        [Parameter(Mandatory=$true)]
        [string]$expectedHash,

        [Parameter(Mandatory=$false)]
        [switch]$fullPath,

        [Parameter(Mandatory=$false)]
        [string]$algorithm = "sha256"
    )

    $file = $fileName

    if (-not $fullPath) {
        $file = [System.IO.Path]::Combine("C:\Downloads", $fileName)
    }

    $exists = Test-Path -Path $file -PathType Leaf

    if (-not $exists) {
        throw "Failed to find file $file in order to verify hash."
    }

    $hash = Get-FileHash $file -Algorithm $algorithm

    if ($hash.Hash -ne $expectedHash) {
        throw "File $file hash $hash.Hash did not match expected hash $expectedHash"
    }
}

function InstallWindowsFeature {

    param(
        [Parameter(Mandatory=$true)]
        [string]$featureName
    )

    $installStart = [System.DateTime]::Now

    try {

	    Write-Host "$installStart; Installing Windows feature $featureName"
	    Install-WindowsFeature -Name $featureName -IncludeAllSubFeature -IncludeManagementTools -Verbose -Restart:$false -Confirm:$false

    } finally {

        $installEnd = [System.DateTime]::Now
        $elapsed = $installEnd.Subtract($installStart)

        Write-Host "$installEnd : Finished install in $elapsed"
        Write-Host $Separator

    }
}

function UninstallWindowsFeature {

    param(
        [Parameter(Mandatory=$true)]
        [string]$featureName
    )

    $installStart = [System.DateTime]::Now

    try {

	    Write-Host "$installStart; Removing Windows Feature $featureName"
	    Uninstall-WindowsFeature -Name $featureName -IncludeManagementTools -Verbose -Restart:$false -Confirm:$false

    } finally {

        $installEnd = [System.DateTime]::Now
        $elapsed = $installEnd.Subtract($installStart)

        Write-Host "$installEnd : Finished install in $elapsed"
        Write-Host $Separator

    }
}

function ExitOnErrorLogFile {

    param(
        [Parameter(Mandatory = $false)]
        [string]$folder = $Env:TEMP,

        [Parameter(Mandatory = $true)]
        [string]$filter,

        [Parameter(Mandatory = $false)]
        [switch]$exitIfExists = $false,

        [Parameter(Mandatory = $false)]
        [switch]$exitIfNotEmpty = $true
    )

    Get-ChildItem -Path $folder -Filter $filter | ForEach-Object {

        $file = $_.FullName
        $len = $_.Length

        Write-Host "Found error log file $file with size $len"

        if ($exitIfExists) {
            throw "At least one error log file $file matching $filter was found in $folder"
        }

        if ($exitIfNotEmpty -and ($len -gt 0)) {
            Write-Host $Separator
            Get-Content -Path $file | Write-Host
            Write-Host $Separator
            throw "At least one non-empty log file $file matching $filter was found in $folder"
        }
    }
}

function CleanupTempFolders {

    try {

        Get-ChildItem -Directory -Path $env:TEMP | ForEach-Object {
            Remove-Item -Recurse -Force -Path $_.FullName -Verbose -ErrorAction SilentlyContinue
        }

        Get-ChildItem -File -Path $env:TEMP | ForEach-Object {
            Remove-Item -Force -Path $_.FullName -Verbose -ErrorAction SilentlyContinue
        }

        Get-ChildItem -Directory -Path "C:\Windows\Temp" | ForEach-Object {
            Remove-Item -Recurse -Force -Path $_.FullName -Verbose -ErrorAction SilentlyContinue
        }

        Get-ChildItem -File -Path "C:\Windows\Temp" | ForEach-Object {
            Remove-Item -Force -Path $_.FullName -Verbose -ErrorAction SilentlyContinue
        }

    } catch {
        Write-Host "Errors occurred while trying to clean up temporary folders."
    } finally {
        Write-Host "Cleaned up temporary folders at $Env:TEMP and C:\Windows\Temp"
    }
}

function InstallEXEAsyncWithDevenvKill {

	param(
        [Parameter()]
		[switch]$fullPath,

        [Parameter()]
		[switch]$ignoreFailures,

		[Parameter(Mandatory=$true)]
		[string]$fileName,

        [Parameter(Mandatory=$false)]
        [int[]]$ignoreExitCodes,

        [Parameter(Mandatory=$true)]
        [string[]]$stuckProcessNames,

		[string[]]$arguments
	)

    $exeStart = [System.DateTime]::Now

    try {
		$file = $fileName

		if (-not $fullPath) {
			$file = [System.IO.Path]::Combine("C:\Downloads", $fileName)
		}

	    Write-Host "$exeStart : Running $file $arguments"

	    $process = Start-Process $file -PassThru -Verbose -NoNewWindow -ArgumentList $arguments
        $pn = [System.IO.Path]::GetFileNameWithoutExtension($file)

        SleepWithMessage -message "Waiting for process with ID $($process.Id) launched from $file to finish ..." -timeInMinutes 5

        foreach ($stuckProcessName in $stuckProcessNames) {
        	KillProcessByName -processName $stuckProcessName -preWaitMinutes 3 -postWaitMinutes 3
        }

        KillProcessByName -processName "msiexec" -preWaitMinutes 3 -postWaitMinutes 3

        SleepWithMessage -message "Waiting for process with ID $($process.Id) launched from $file to finish ..." -timeInMinutes 2

        KillProcessByName -processName $pn -preWaitMinutes 3 -postWaitMinutes 3

        $ex = $process.ExitCode;

        if ($ex -ne 0)
	    {
            foreach ($iex in $ignoreExitCodes)
            {
                if ($ex -eq $iex)
                {
                    Write-Host "Install from $file succeeded with exit code $ex"
                    return;
                }
            }

		    Write-Host "Failed to install from $file. Process exited with code $ex"

            if (-not $ignoreFailures)
            {
		        exit $ex
            }
	    }

    } finally {

        $exeEnd = [System.DateTime]::Now
        $elapsed = $exeEnd.Subtract($exeStart)

        Write-Host "$exeEnd : Finished install in $elapsed"
        Write-Host $Separator

    }
}

function KillProcessByName {
    param(
		[Parameter(Mandatory=$true)]
		[string]$processName,

        [Parameter(Mandatory=$false)]
        [int]$preWaitMinutes = 3,

        [Parameter(Mandatory=$false)]
        [int]$postWaitMinutes = 3
    )

    SleepWithMessage -message "Waiting for $preWaitMinutes before killing all processes named $processName" -timeInMinutes $preWaitMinutes
    &tasklist

    $count = 0

    Get-Process -Name $processName -ErrorAction SilentlyContinue | ForEach-Object {
        $process = $_
        Write-Host "Killing process with name $processName and ID $($process.Id)"
        $process.Kill()
        ++$count
    }

    Write-Host "Killed $count processes with name $processName"

    SleepWithMessage -message "Waiting for $postWaitMinutes after killing all processes named $processName" -timeInMinutes $postWaitMinutes

    &tasklist
}

function SleepWithMessage {
    param(

        [Parameter(Mandatory=$true)]
        [string]$message,

        [Parameter(Mandatory=$true)]
        [int]$timeInMinutes
    )

    $elapsed = 0

    while ($true) {

        if ($elapsed -ge $timeInMinutes) {
            Write-Host "Done waiting for $elapsed minutes"
            break
        }

        Write-Host $message
        Start-Sleep -Seconds 60
        ++$elapsed
    }
}
