' Copyright (c) Microsoft Corporation
' SPDX-License-Identifier: MIT

' Error/return codes
Const EBPF_DRIVER_INSTALL_SUCCEEDED				= 1
Const EBPF_DRIVER_ALREADY_INSTALLED				= 2
Const EBPF_DRIVER_INSTALL_FAILED				= 3
Const EBPF_DRIVER_START_SUCCEEDED				= 4
Const EBPF_DRIVER_START_FAILED					= 5
Const EBPF_DRIVER_STOP_SUCCEEDED				= 6
Const EBPF_DRIVER_STOP_FAILED					= 7
Const EBPF_DRIVER_DELETE_SUCCEEDED				= 8
Const EBPF_DRIVER_DELETE_FAILED					= 9
Const EBPF_NETSH_EXT_REGISTRATION_SUCCEEDED		= 10
Const EBPF_NETSH_EXT_REGISTRATION_FAILED		= 11
Const EBPF_NETSH_EXT_REGISTRATION_PATH_FAILED	= 12
Const EBPF_NETSH_EXT_DEREGISTRATION_SUCCEEDED	= 13
Const EBPF_NETSH_EXT_DEREGISTRATION_FAILED		= 14
Const EBPF_TRACING_SETUP_FAILED					= 15
Const EBPF_TRACING_SETUP_SUCCEEDED				= 16

' String constants
Const EBPF_EBPFCORE_DRIVER_NAME				= "eBPFCore"
Const EBPF_EXTENSION_DRIVER_NAME			= "NetEbpfExt"
Const EBPF_NETSH_EXTENSION_NAME				= "ebpfnetsh.dll"
Const EBPF_TRACING_STARTUP_TASK_NAME		= "eBpfTracingStartupTask"
Const EBPF_TRACING_PERIODIC_TASK_NAME		= "eBpfTracingPeriodicTask"
Const EBPF_TRACING_TASK_CMD					= "ebpf_tracing.cmd"
Const EBPF_TRACING_PERIODIC_TASK_MINUTES	= 35

' Logging constants
Const EBPF_LOG_BLANK		= 0
Const EBPF_LOG_INFO			= 1
Const EBPF_LOG_WARNING		= 2
Const EBPF_LOG_ERROR		= 3
Const EBPF_LOG_SOURCE		= "eBpfForWindows"
Const EBPF_LOG_FILE_NAME	= "eBpfForWindows"
Const EBPF_LOG_MAX_AGE_DAYS	= 30 'Files older than this (in days) will be deleted
Const EBPF_LOG_MIN_FILES	= 10 'Minimum number of log files to keep
Dim EBPF_LOG_VERBOSITY: EBPF_LOG_VERBOSITY = EBPF_LOG_INFO

' Global variables
Dim g_LogFile
Dim g_PackageName
Const g_RunTests			= True													' Set to 'False' to skip tests
Dim WshShell : Set WshShell = WScript.CreateObject("WScript.Shell")
Dim FsObject : Set FsObject = WScript.CreateObject("Scripting.FileSystemObject")

' Test code
If g_RunTests Then
	Dim packagePath: packagePath =  FsObject.BuildPath(WshShell.ExpandEnvironmentStrings("%SYSTEMDRIVE%"), "\_ebpf\redist-package")
	Dim installPath: installPath =  FsObject.BuildPath(WshShell.ExpandEnvironmentStrings("%SYSTEMDRIVE%"), "\Program Files\ebpf-for-windows")
	Dim tracingPath: tracingPath =  FsObject.BuildPath(WshShell.ExpandEnvironmentStrings("%SYSTEMDRIVE%"), "\_ebpf\logs")

	InstallEbpf packagePath, installPath, tracingPath
	UninstallEbpf installPath, tracingPath
End If


Function DeleteOldLogs(tracePath)
	On Error Resume Next

	Set oFolder = FsObject.GetFolder(tracePath)
	Set aFiles = oFolder.Files
	Set aSubFolders = oFolder.SubFolders
	today = Date

	' Delete files older than EBPF_LOG_MAX_AGE_DAYS days in the 'tracePath' folder (and leave no less than EBPF_LOG_MIN_FILES files)
	If aFiles.Count > EBPF_LOG_MIN_FILES Then
		maxDeletions = aFiles.Count - EBPF_LOG_MIN_FILES
		For Each file in aFiles
			If maxDeletions > 0 And Instr(file.name, EBPF_LOG_FILE_NAME) And file.Extension = "log" Then
				dFileCreated = FormatDateTime(file.DateCreated, "2")
				If DateDiff("d", dFileCreated, today) > EBPF_LOG_MAX_AGE_DAYS Then
					file.Delete(True)
					maxDeletions = maxDeletions - 1
				End If
			End If
		Next
	End If
End Function

' This function initializes the local log file
Function InitializeTracing(tracePath)
	On Error Resume Next
	
	InitializeTracing = True

	' Empty path means no logging
	If Len(tracePath) > 0 Then
		' Create the logging folder if it doesn't exist
		If Not FsObject.FolderExists(tracePath) Then
			FsObject.CreateFolder(tracePath)
			If Err.number <> 0 Then
				InitializeTracing = False
				Exit Function
			End If
		End If
		
		' Cleanup the log directory
		DeleteOldLogs tracePath
	
		' Create the log file
		Set g_LogFile = FsObject.CreateTextFile(FsObject.BuildPath(tracePath, EBPF_LOG_FILE_NAME + "_" + CurrentDateTimeText() + ".log"), True)
	End If
End Function

' This function stops the tracing task and closes the local log file
Sub StopTracing
	g_LogFile.Close
End Sub

Function CurrentDateTimeText()	
	Dim dt : dt = Now
	t = Timer
	Milliseconds = Int((t-Int(t)) * 1000)
	CurrentDateTimeText = CStr(Year(dt)) + "-" + _
						Right("0"+CStr(Month(dt)),2) + "-" + _
						Right("0"+CStr(Day(dt)),2) + "_" + _
						Right("0"+CStr(Hour(dt)),2) + "." + _
						Right("0"+CStr(Minute(dt)),2) + "." + _
						Right("0"+CStr(Second(dt)),2) + "." + _
						String(3-Len(Milliseconds),"0") & Milliseconds					
End Function

' This function logs a message to the local log file
Sub LogEvent(level, method, logStatement, errReturnCode)
	On Error Resume Next
	
	If EBPF_LOG_VERBOSITY <= level Then
		Dim logTxt
		Select Case level
		Case EBPF_LOG_INFO
			logTxt = CurrentDateTimeText + ": " + EBPF_LOG_SOURCE + "." + method + "[INFO] - " + logStatement + " returnCode(" + CStr(errReturnCode) + ")"
		Case EBPF_LOG_WARNING
			logTxt = CurrentDateTimeText + ": " + EBPF_LOG_SOURCE + "." + method + "[WARNING] - " + logStatement + " errorCode(" + CStr(errReturnCode) + ")"
		Case EBPF_LOG_ERROR
			logTxt = CurrentDateTimeText + ": " + EBPF_LOG_SOURCE + "." + method + "[ERROR] - " + logStatement + " errorCode(" + CStr(errReturnCode) + ")"
		End Select
	
		g_LogFile.WriteLine(logTxt)
	End If
End Sub

' This function creates tasks to start eBPF tracing at boot, and execute periodic rundowns
Function CreateEbpfTracingTasks(installPath, tracePath)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "CreateEbpfTracingTasks"
	
	' Delete the tasks if it already exists
	DeleteEbpfTracingTasks tracePath

	Dim scriptPath : scriptPath = FsObject.BuildPath(installPath, EBPF_TRACING_TASK_CMD)

	' Create the task to start eBPF tracing at boot
	Dim exec: Set exec = WshShell.Exec("schtasks /create /f /sc onstart /ru system /rl highest /tn " + EBPF_TRACING_STARTUP_TASK_NAME + " /tr """ + scriptPath + " start '" + tracePath + "'""")
	While exec.Status = WshRunning
		WScript.Sleep 1
	Wend
	If exec.Status = WshFailed Then
		CreateEbpfTracingTasks = EBPF_TRACING_SETUP_FAILED
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED setting up the '" + EBPF_TRACING_STARTUP_TASK_NAME + "' task.", exec.Status
	Else
		CreateEbpfTracingTasks = EBPF_TRACING_SETUP_SUCCEEDED
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "SUCCESS setting up the '" + EBPF_TRACING_STARTUP_TASK_NAME + "' task.", exec.Status
	End If

    ' Execute the script to start eBPF tracing
	If FsObject.FileExists(scriptPath) Then
		Set exec = WshShell.Exec("""" + scriptPath + """ start """ + tracePath + """")
		While exec.Status = WshRunning
			WScript.Sleep 1
		Wend
		If exec.Status = WshFailed Then
			CreateEbpfTracingTasks = EBPF_TRACING_SETUP_FAILED
			LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED executing '" + cmd + "'.", exec.Status
		Else
			CreateEbpfTracingTasks = EBPF_TRACING_SETUP_SUCCEEDED
			LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "SUCCESS executing '" + cmd + "'.", exec.Status
		End If
	Else
		CreateEbpfTracingTasks = EBPF_TRACING_SETUP_FAILED
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "Tracing script not found '" + scriptPath + "'.", 1
	End If

	' Create the task to execute periodic rundowns (differ from the startup task so that it's not executed right after it)
	Set exec = WshShell.Exec("schtasks /create /f /sc minute /mo " + CStr(EBPF_TRACING_PERIODIC_TASK_MINUTES + 2) + " /ru system /rl highest /tn " + EBPF_TRACING_PERIODIC_TASK_NAME + " /tr """ + scriptPath + " periodic '" + tracePath + "'""")
	While exec.Status = WshRunning
		WScript.Sleep 1
	Wend
	If exec.Status = WshFailed Then
		CreateEbpfTracingTasks = EBPF_TRACING_SETUP_FAILED
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED setting up the '" + EBPF_TRACING_PERIODIC_TASK_NAME + "' task.", exec.Status
	Else
		CreateEbpfTracingTasks = EBPF_TRACING_SETUP_SUCCEEDED
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "SUCCESS setting up the '" + EBPF_TRACING_PERIODIC_TASK_NAME + "' task.", exec.Status
	End If
End Function

' This function deletes the tasks to start eBPF tracing at boot, and execute periodic rundowns, and deletes the tracePath directory and its contents
Function DeleteEbpfTracingTasks(installPath, tracePath)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "DeleteEbpfTracingTasks"

    ' Execute the script to stop eBPF tracing
	Dim scriptPath : scriptPath = FsObject.BuildPath(installPath, EBPF_TRACING_TASK_CMD)
	If FsObject.FileExists(scriptPath) Then
		Dim exec: Set exec = WshShell.Exec("""" + scriptPath + """ stop """ + tracePath + """")
		While exec.Status = WshRunning
			WScript.Sleep 1
		Wend
		If exec.Status = WshFailed Then
			CreateEbpfTracingTasks = EBPF_TRACING_SETUP_FAILED
			LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED executing '" + cmd + "'.", exec.Status
		Else
			CreateEbpfTracingTasks = EBPF_TRACING_SETUP_SUCCEEDED
			LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "SUCCESS executing '" + cmd + "'.", exec.Status
		End If
	Else
		CreateEbpfTracingTasks = EBPF_TRACING_SETUP_FAILED
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "Tracing script not found '" + scriptPath + "'.", 1
	End If

	' Delete the startup task if it already exists
	Set exec = WshShell.Exec("schtasks /delete /f /tn " + EBPF_TRACING_STARTUP_TASK_NAME)
	While exec.Status = WshRunning
		WScript.Sleep 1
	Wend
	If exec.Status = WshFailed Then
		DeleteEbpfTracingTasks = EBPF_TRACING_SETUP_FAILED
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "eBPF tracing task '" + EBPF_TRACING_STARTUP_TASK_NAME + "' does not exist, no action taken.", exec.Status
	Else
		DeleteEbpfTracingTasks = EBPF_TRACING_SETUP_SUCCEEDED
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "SUCCESS deleting the '" + EBPF_TRACING_STARTUP_TASK_NAME + "' task.", exec.Status
	End If

	' Delete the periodic task if it already exists
	Set exec = WshShell.Exec("schtasks /delete /f /tn " + EBPF_TRACING_PERIODIC_TASK_NAME)
	While exec.Status = WshRunning
		WScript.Sleep 1
	Wend
	If exec.Status = WshFailed Then
		DeleteEbpfTracingTasks = EBPF_TRACING_SETUP_FAILED
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "eBPF tracing task '" + EBPF_TRACING_PERIODIC_TASK_NAME + "' does not exist, no action taken.", exec.Status
	Else
		DeleteEbpfTracingTasks = EBPF_TRACING_SETUP_SUCCEEDED
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "SUCCESS deleting the '" + EBPF_TRACING_PERIODIC_TASK_NAME + "' task.", exec.Status
	End If
End Function

' This function copies the files from the source folder to the destination folder
Function CopyFilesToPath(sourcePath, destPath)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "CopyFilesToPath"
	Dim errReturnCode
			
	CopyFilesToPath = True	
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Copying files from " + sourcePath + " to " + destPath, 0
	
	' Create the destination folder if it doesn't exist
	If Not FsObject.FolderExists(destPath) Then		
		FsObject.CreateFolder(destPath)
		If Err.number <> 0 Then
			LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "Failed to create folder " + destPath, Err.number
			CopyFilesToPath = False
			Exit Function
		End If
	End If

	' Copy the files to the destination folder
	FsObject.CopyFolder sourcePath, destPath, True
	If Err.number <> 0 Then
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "Failed to copy files from " + sourcePath + " to " + destPath, Err.number
		CopyFilesToPath = False
	End If
End Function

Function ExecuteShellCmd(cmd)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "ExecuteShellCmd"
	
	Dim exec : Set exec = WshShell.Exec("%comspec% /c " & cmd & " >nul 2>&1")
	While exec.Status = WshRunning
		WScript.Sleep 1
	Wend
	If exec.Status = WshFailed Then
		ExecuteShellCmd = exec.Status
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED executing '" + cmd + "'", exec.Status
	Else
		ExecuteShellCmd = exec.ExitCode
		'LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "SUCCESS executing '" + cmd + "'", exec.ExitCode
	End If
End Function

' This function installs eBPF for Windows on the machine and returns true successful, false otherwise
Function InstallEbpf(sourcePath, installPath, tracePath)
	On Error Resume Next
	
	Const THIS_FUNCTION_NAME = "InstallEbpf"
	Dim eBpfCoreAlreadyInstalled, eBpfNetExtAlreadyInstalled
	Dim errReturnCode
	
	InstallEbpf = True

	InitializeTracing tracePath
	LogEvent EBPF_LOG_INFO, "InstallEbpf", "Installing eBPF for Windows to " + installPath, 0

	' Check if eBPF for Windows is already installed
	eBpfCoreAlreadyInstalled = CheckDriverInstalled(EBPF_EBPFCORE_DRIVER_NAME)
	eBpfNetExtAlreadyInstalled = CheckDriverInstalled(EBPF_EXTENSION_DRIVER_NAME)
	If eBpfCoreAlreadyInstalled = True And eBpfNetExtAlreadyInstalled = True Then
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "eBPF for Windows already installed.", 0
		Exit Function
	Else
		If eBpfCoreAlreadyInstalled <> eBpfNetExtAlreadyInstalled Then
			InstallEbpf = False
			LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "ERROR! eBPF for Windows installation is corrupt!", 0
			Exit Function
		End If
	End If

	' Copy the files to the install path
    If Len(sourcePath) > 0 Then
    	if Not CopyFilesToPath(sourcePath, installPath) Then
		    InstallEbpf = False
		    Exit Function
        End If
    End If
	
	' Create the tracing task
	if CreateeBPFTracingTasks(installPath, tracePath) = EBPF_TRACING_SETUP_FAILED Then
		InstallEbpf = False
	End If
		
	' Install the drivers and the netsh extension
	driversPath = FsObject.BuildPath(installPath, "drivers")	
	Do While True
	
		errReturnCode = InstallEbpfDriver(EBPF_EXTENSION_DRIVER_NAME, driversPath, "auto")
		Select Case errReturnCode
		Case EBPF_DRIVER_INSTALL_FAILED	  	  
			errReturnCode = UninstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME)
			InstallEbpf = False
			Exit Do
		Case EBPF_DRIVER_START_FAILED
			errReturnCode = UninstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME)
			errReturnCode = UninstallEbpfDriver(EBPF_EXTENSION_DRIVER_NAME)
			InstallEbpf = False
			Exit Do
		End Select
		errReturnCode = InstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME, driversPath, "auto")
		Select Case errReturnCode
		Case EBPF_DRIVER_INSTALL_FAILED
			InstallEbpf = False
			Exit Do
		Case EBPF_DRIVER_START_FAILED
			errReturnCode = UninstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME)
			InstallEbpf = False
			Exit Do
		End Select
		
		errReturnCode = RegisterNetshHelper(EBPF_NETSH_EXTENSION_NAME, installPath)
		Select Case errReturnCode
		Case EBPF_NETSH_EXT_REGISTRATION_FAILED	  	  
			errReturnCode = UninstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME)
			errReturnCode = UninstallEbpfDriver(EBPF_EXTENSION_DRIVER_NAME)
			InstallEbpf = False
			Exit Do
		Case EBPF_NETSH_EXT_REGISTRATION_PATH_FAILED
			errReturnCode = UninstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME)
			errReturnCode = UninstallEbpfDriver(EBPF_EXTENSION_DRIVER_NAME)
			errReturnCode = UnregisterNetshHelper(EBPF_NETSH_EXTENSION_NAME, installPath)
			InstallEbpf = False
			Exit Do
		End Select
		
		Exit Do
	Loop
	
	If InstallEbpf = True Then
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "eBPF for Windows was successfully installed!", 0
	Else
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "eBPF for Windows was NOT successfully installed.", 0
	End If
End Function

' This function uninstalls eBPF for Windows on the machine and returns true successful, false otherwise
Function UninstallEbpf(installPath, tracePath)
	On Error Resume Next
	
	Const THIS_FUNCTION_NAME = "UninstallEbpf"
	Dim errReturnCode
	
	UninstallEbpf = True

	InitializeTracing tracePath

	if Not FsObject.FolderExists(installPath) Then
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "Install path not found " + installPath, 0
		UninstallEbpf = False
		' Not exiting: we still want to try to remove the drivers and tracing tasks, in case they were installed in a different location
	End If

	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Uninstalling eBPF for Windows from " + installPath, 0
	
	errReturnCode = UninstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME)
	If errReturnCode <> EBPF_DRIVER_DELETE_SUCCEEDED Then
		UninstallEbpf = False
	End If
	
	errReturnCode = UninstallEbpfDriver(EBPF_EXTENSION_DRIVER_NAME)
	If errReturnCode <> EBPF_DRIVER_DELETE_SUCCEEDED Then
		UninstallEbpf = False
	End If
	
	errReturnCode = UnregisterNetshHelper(EBPF_NETSH_EXTENSION_NAME, installPath)
	If errReturnCode <> EBPF_NETSH_EXT_DEREGISTRATION_SUCCEEDED Then
		UninstallEbpf = False
	End If
	
	DeleteEbpfTracingTasks installPath, tracePath
	
	FsObject.DeleteFolder installPath, True
	If Err.number <> 0 Then
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "Failed to delete folder " + installPath, Err.number
	End If

	If UninstallEbpf = True Then
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "eBPF for Windows was successfully uninstalled!", 0
	Else
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "eBPF for Windows was NOT successfully uninstalled!", 0
	End If
	
	StopTracing
End Function

' This function installs the given kernel driver.
Function InstallEbpfDriver(driverName, driverPath, startMode)
	On Error Resume Next
	Const THIS_FUNCTION_NAME = "InstallEbpfDriver"
	Dim errReturnCode
	
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Installing driver '" + driverName + ".sys'...", 0

	driverFullPath = FsObject.BuildPath(driverPath, driverName + ".sys")
	If CheckDriverInstalled(driverName) = False Then		
		' Create the driver service
		errReturnCode = ExecuteShellCmd("sc.exe create " + driverName + " type=kernel start=" + startMode + " binpath=""" + driverFullPath + """") 
		If errReturnCode <> 0 Then
			InstallEbpfDriver = EBPF_DRIVER_INSTALL_FAILED
			LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED installing '" + driverName + ".sys'", errReturnCode
		Else			
			LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully installed '" + driverName + ".sys'", errReturnCode
			
			' Start the driver service
			errReturnCode = ExecuteShellCmd("net start " + driverName)
			If errReturnCode = 0 Then			
				InstallEbpfDriver = EBPF_DRIVER_START_SUCCEEDED
				LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully started '" + driverName + ".sys'", errReturnCode
			Else If errReturnCode = 1 Then			
					InstallEbpfDriver = EBPF_DRIVER_START_SUCCEEDED
					LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "'" + driverName + ".sys' already started", errReturnCode
				Else
					InstallEbpfDriver = EBPF_DRIVER_START_FAILED
					LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED starting '" + driverName + ".sys'", errReturnCode
				End If	
			End If		
		End If		
	Else
		InstallEbpfDriver = EBPF_DRIVER_ALREADY_INSTALLED
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "Driver '" + driverName + ".sys' already installed.", 1
	End If            
End Function

' This function uninstalls the given kernel driver.
Function UninstallEbpfDriver(driverName)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "UninstallEbpfDriver"
	Dim errReturnCode
	
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Unnstalling driver '" + driverName + ".sys'...", 0
	
	If CheckDriverInstalled(driverName) = False Then
		UninstallEbpfDriver = EBPF_DRIVER_NOT_INSTALLED
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "Driver '" + driverName + ".sys' not installed.", 1
		Exit Function
	Else
		errReturnCode = ExecuteShellCmd("net stop " + driverName)
		If errReturnCode <> 0 Then
			UninstallEbpfDriver = EBPF_DRIVER_STOP_FAILED
			LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED stopping '" + driverName + ".sys'", errReturnCode
			Exit Function
		Else
			LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully stopped '" + driverName + ".sys'", errReturnCode
			errReturnCode = ExecuteShellCmd("sc.exe delete " + driverName)
			If errReturnCode <> 0 Then
				UninstallEbpfDriver = EBPF_DRIVER_DELETE_FAILED
				LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED deleting '" + driverName + ".sys'", errReturnCode
			Else
				UninstallEbpfDriver = EBPF_DRIVER_DELETE_SUCCEEDED
				LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully deleted '" + driverName + ".sys'", errReturnCode
			End If
		End If
	End If
End Function

' This function checks if the given driver is already installed.
Function CheckDriverInstalled(driverName)
	On Error Resume Next
	
	Const THIS_FUNCTION_NAME = "CheckDriverInstalled"

	CheckDriverInstalled = False

	errReturnCode = ExecuteShellCmd("sc.exe query " + driverName)
	If errReturnCode = 0 Then	
		CheckDriverInstalled = True
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Driver '" + driverName + ".sys' is installed.", errReturnCode
	Else		
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Driver '" + driverName + ".sys' not installed.", errReturnCode
	End If
End Function

' This function registers the given netsh extension.
Function RegisterNetshHelper(extensionName, extensionPath)
	On Error Resume Next
	
	Const THIS_FUNCTION_NAME = "RegisterNetshHelper"
	Dim errReturnCode
	
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Registering netsh.exe helper '" + extensionName + "'...", 0
	
	WshShell.CurrentDirectory = extensionPath
	errReturnCode = ExecuteShellCmd	("netsh.exe add helper " + extensionName)
	If errReturnCode <> 0 Then		
		RegisterNetshHelper = EBPF_NETSH_EXT_REGISTRATION_FAILED
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED registering '" + extensionName + "'", errReturnCode
	Else
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully registered '" + extensionName + "'", errReturnCode
		
		If AddSystemPath(extensionPath) = False	Then
			RegisterNetshHelper = EBPF_NETSH_EXT_REGISTRATION_PATH_FAILED
		Else
			RegisterNetshHelper = EBPF_NETSH_EXT_REGISTRATION_SUCCEEDED
		End if
	End If
End Function

' This function unregisters the given netsh extension.
Function UnregisterNetshHelper(extensionName, extensionPath)
	On Error Resume Next
	
	Const THIS_FUNCTION_NAME = "UnregisterNetshHelper"
	Dim errReturnCode
	
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Unregistering netsh.exe helper '" + extensionName + "'...", 0
	
	WshShell.CurrentDirectory = extensionPath
	errReturnCode = ExecuteShellCmd	("netsh.exe delete helper " + extensionName)
	If errReturnCode <> 0 Then	
		UnregisterNetshHelper = EBPF_NETSH_EXT_DEREGISTRATION_FAILED
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED unregistering '" + extensionName + "'", errReturnCode
	Else
		UnregisterNetshHelper = EBPF_NETSH_EXT_DEREGISTRATION_SUCCEEDED
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully unregistered '" + extensionName + "'", errReturnCode
	End If
	
	RemoveSystemPath(extensionPath)	
End Function

' Adds a new path to the System path, unless the path is already present in the system path.
Function AddSystemPath(pathToAdd)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "AddSystemPath"
	Dim sysENV, systemPath, pathElement, pathExists, oldPath

	AddSystemPath = False
	
	' Remove "\\" due to system drives in the path
	pathToAdd = Replace(pathToAdd, "\\", "\")
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Adding path '" + pathToAdd + "' to System path...", 0
	
	Set sysENV = WshShell.Environment("System")
	systemPath = sysENV("path")

	' Check if path already exists
	oldPath = Split(sysENV("path"), ";", -1, vbTextCompare)
	pathExists = False
	For Each pathElement In oldPath
		If StrComp(pathElement, pathToAdd, vbTextCompare) = 0 Then
			pathExists = True
			AddSystemPath = True
			LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "System path '" + pathToAdd + "' was already present - no action taken.", 0
			Exit For
		End If
	Next

	' If path does not already exist
	If Not pathExists Then
		' Strip off trailing semicolons if present
		Do While Right(systemPath, 1) = ";"
			systemPath = Left(systemPath, Len(systemPath) - 1)
		Loop

		' Add new path to current path
		If systemPath = "" Then
			systemPath = pathToAdd
		Else
			systemPath = systemPath & ";" & pathToAdd
		End If

		' Set the new path into environment:
		sysENV("path") = systemPath
		AddSystemPath = True
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully added System path '" + pathToAdd + "'", 0
	End If
End Function

' Removes the given path from the System path, unless the path isn't present.
Function RemoveSystemPath(pathToRemove)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "RemoveSystemPath"
	Dim sysENV, systemPath, pathElement, pathExists, oldPath
	
	RemoveSystemPath =  True
	
	' Remove "\\" due to system drives in the path
	pathToRemove = Replace(pathToRemove, "\\", "\")
	
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Removing System path '" + pathToRemove + "'...", 0
	
	Set sysENV = WshShell.Environment("System")
	systemPath = sysENV("path")
	
	' Check if path already exists
	oldPath = Split(sysENV("path"), ";", -1, vbTextCompare)
	pathExists = False	
	For Each pathElement In oldPath
		If StrComp(pathElement, pathToRemove, vbTextCompare) = 0 Then
			pathExists = True
			Exit For
		End If
	Next
	
	' Only do if path already exists
	If pathExists Then
		Dim arrPathEntries, n, pathEentry
		
		arrPathEntries = Split(systemPath,";")
		For n = 0 To UBound(arrPathEntries)
			entry = arrPathEntries(n)
			If LCase(entry) = LCase(pathToRemove) Then
				arrPathEntries(n) = ""
			ElseIf Trim(entry) <> "" Then
				arrPathEntries(n) = entry & ";"
			Else
				arrPathEntries(n) = ""
			End If
		Next
		
		' Set the new path into environment
		sysENV("path") = Join(arrPathEntries,"")		
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully removed System path '" + pathToRemove + "'", 0
	Else
		RemoveSystemPath = False
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "System path '" + pathToRemove + "' was not found - no action taken.", 0
	End If
End Function