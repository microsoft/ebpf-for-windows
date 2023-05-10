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
Const EBPF_TRACING_SETUP_FAILED					= 15
Const EBPF_TRACING_SETUP_SUCCEEDED				= 16

' String constants
Const EBPF_EBPFCORE_DRIVER_NAME				= "eBPFCore"
Const EBPF_EXTENSION_DRIVER_NAME			= "NetEbpfExt"
Const EBPF_NETSH_EXTENSION_NAME				= "ebpfnetsh.dll"
Const EBPF_TRACING_STARTUP_TASK_NAME		= "eBpfTracingStartupTask"
Const EBPF_TRACING_STARTUP_TASK_FILENAME	= "ebpf_tracing_startup_task.xml"
Const EBPF_TRACING_PERIODIC_TASK_NAME		= "eBpfTracingPeriodicTask"
Const EBPF_TRACING_PERIODIC_TASK_FILENAME	= "ebpf_tracing_periodic_task.xml"
Const EBPF_TRACING_TASK_CMD					= "ebpf_tracing.cmd"

' Logging constants
Const EBPF_LOG_BLANK		= 0
Const EBPF_LOG_INFO			= 1
Const EBPF_LOG_WARNING		= 2
Const EBPF_LOG_ERROR		= 3
Const EBPF_LOG_SOURCE		= "eBpfForWindows"
Const EBPF_LOG_FILE_NAME	= "eBpfForWindows"
Const EBPF_LOG_MAX_AGE_DAYS	= 30 'Files older than this (in days) will be deleted
Const EBPF_LOG_MAX_AGE_DAYS	= 30 'Files older than this (in days) will be deleted
Const EBPF_LOG_MIN_FILES	= 10 'Minimum number of log files to keep
Dim EBPF_LOG_VERBOSITY: EBPF_LOG_VERBOSITY = EBPF_LOG_INFO
Dim EBPF_LOG_VERBOSITY: EBPF_LOG_VERBOSITY = EBPF_LOG_INFO

' Global variables
Dim g_LogFile
Dim g_PackageName
Const g_RunTests			= True ' Set to 'False' to skip tests
Dim WshShell : Set WshShell = WScript.CreateObject("WScript.Shell")
Dim FsObject : Set FsObject = WScript.CreateObject("Scripting.FileSystemObject")
Dim WmiService : Set WmiService = GetObject("winmgmts:\\.\root\cimv2")
Dim g_tracingPath: g_tracingPath = FsObject.BuildPath(WshShell.ExpandEnvironmentStrings("%SystemRoot%"), "\Logs\eBPF")
Dim g_installPath: g_installPath = FsObject.BuildPath(WshShell.ExpandEnvironmentStrings("%ProgramFiles%"), "\ebpf-for-windows")

' Initialize the global variables and the local log file
If InitializeTracing Then
	' Test code
	If g_RunTests Then
		InstallEbpf "D:\work\_scratch\imds\redist-package"
		UninstallEbpf
	End If
End If


' This function initializes the global vars and the local log file
Function InitializeTracing()
	On Error Resume Next
	
	InitializeTracing = True

	' Create the logging folder if it doesn't exist
	If Not FsObject.FolderExists(g_tracingPath) Then
		FsObject.CreateFolder(g_tracingPath)
		If Err.number <> 0 Then
			InitializeTracing = False
			Exit Function
		End If
	End If
	
	' Create the log file
	Set g_LogFile = FsObject.CreateTextFile(FsObject.BuildPath(g_tracingPath, EBPF_LOG_FILE_NAME + "_" + CurrentDateTimeText() + ".log"), True)
End Function

' This function closes the local log file
Sub StopTracing()
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
	
	Dim logTxt
	Select Case level
	Case EBPF_LOG_INFO
		logTxt = CurrentDateTimeText + ": " + EBPF_LOG_SOURCE + "." + method + "(INFO) - " + logStatement + " returnCode(" + CStr(errReturnCode) + ")"
	Case EBPF_LOG_WARNING
		logTxt = CurrentDateTimeText + ": " + EBPF_LOG_SOURCE + "." + method + "(WARNING) - " + logStatement + " errorCode(" + CStr(errReturnCode) + ")"
	Case EBPF_LOG_ERROR
		logTxt = CurrentDateTimeText + ": " + EBPF_LOG_SOURCE + "." + method + "(ERROR) - " + logStatement + " errorCode(" + CStr(errReturnCode) + ")"
	End Select
	
	g_LogFile.WriteLine(logTxt)
End Sub

' Adds a new path to the System path, unless the path is already present in the system path.
Function AddSystemPath(pathToAdd)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "AddSystemPath"

	AddSystemPath = True
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Adding path '" + pathToAdd + "' to System path...", 0

	Dim sysENV : Set sysENV = WshShell.Environment("System")
	systemPath = sysENV("PATH")
	If InStr(systemPath, pathToAdd) = 0 Then
		sysENV("PATH") = systemPath + ";" + pathToAdd
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully added System path '" + pathToAdd + "'", 0
	Else
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "System path '" + pathToAdd + "' was already present - no action taken.", 0
	End If
End Function

' Removes the given path from the System path, unless the path isn't present.
Function RemoveSystemPath(pathToRemove)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "RemoveSystemPath"
	
	RemoveSystemPath =  True
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Removing System path '" + pathToRemove + "'...", 0
	
	Dim sysENV : Set sysENV = WshShell.Environment("System")
	systemPath = sysENV("PATH")
	If InStr(systemPath, pathToRemove) <> 0 Then
		systemPath = Replace(systemPath, pathToRemove, "")
		systemPath = Replace(systemPath, ";;", ";")
		sysENV("PATH") = systemPath
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully removed System path '" + pathToRemove + "'", 0
	Else
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "System path '" + pathToRemove + "' was not present - no action taken.", 0
	End If
End Function

' This function executes a shell command and returns the exit code
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

' This function creates a scheduled task from a given XML file.
Function CreateScheduledTask(taskName, taskFile)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "CreateScheduledTask"
	Dim errReturnCode

	' Create the scheduled task
	Dim taskFilePath : taskFilePath = FsObject.BuildPath(g_installPath, taskFile)
	errReturnCode = ExecuteShellCmd("schtasks.exe /create /f /tn " + taskName + " /xml """ + taskFilePath + """")
	If errReturnCode <> 0 Then
		CreateScheduledTask = EBPF_TRACING_SETUP_FAILED
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED setting up the '" + taskName + "' task.", exec.Status
	Else
		CreateScheduledTask = EBPF_TRACING_SETUP_SUCCEEDED
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "SUCCESS setting up the '" + taskName + "' task.", exec.Status
	End If
End Function

' This function creates tasks to start eBPF tracing at boot, and execute periodic rundowns
Function CreateEbpfTracingTasks()
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "CreateEbpfTracingTasks"

	CreateEbpfTracingTasks = true

	' Delete the tasks if they already exist
	call DeleteEbpfTracingTasks()

	if CreateScheduledTask(EBPF_TRACING_STARTUP_TASK_NAME, EBPF_TRACING_STARTUP_TASK_FILENAME) = EBPF_TRACING_SETUP_FAILED Then
		CreateEbpfTracingTasks = False
	End If
	if CreateScheduledTask(EBPF_TRACING_PERIODIC_TASK_NAME, EBPF_TRACING_PERIODIC_TASK_FILENAME) = EBPF_TRACING_SETUP_FAILED Then
		DeleteEbpfTracingTasks()
		CreateEbpfTracingTasks = False
	End If
End Function

' This function deletes the tasks to start eBPF tracing at boot, and execute periodic rundowns, and deletes the g_tracingPath
Function DeleteEbpfTracingTasks()
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "DeleteEbpfTracingTasks"
	Dim errReturnCode

	' Execute the script to stop eBPF tracing
	Dim scriptPath : scriptPath = FsObject.BuildPath(g_installPath, EBPF_TRACING_TASK_CMD)
	If FsObject.FileExists(scriptPath) Then
		errReturnCode = ExecuteShellCmd("cmd.exe /c """"" + scriptPath + """ stop """ + g_tracingPath + """""")
		If errReturnCode <> 0 Then
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
	errReturnCode = ExecuteShellCmd("schtasks /delete /f /tn " + EBPF_TRACING_STARTUP_TASK_NAME)
	If errReturnCode <> 0 Then
		DeleteEbpfTracingTasks = EBPF_TRACING_SETUP_FAILED
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "eBPF tracing task '" + EBPF_TRACING_STARTUP_TASK_NAME + "' does not exist, no action taken.", exec.Status
	Else
		DeleteEbpfTracingTasks = EBPF_TRACING_SETUP_SUCCEEDED
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "SUCCESS deleting the '" + EBPF_TRACING_STARTUP_TASK_NAME + "' task.", exec.Status
	End If

	' Delete the periodic task if it already exists
	errReturnCode = ExecuteShellCmd("schtasks /delete /f /tn " + EBPF_TRACING_PERIODIC_TASK_NAME)
	If errReturnCode <> 0 Then
		DeleteEbpfTracingTasks = EBPF_TRACING_SETUP_FAILED
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "eBPF tracing task '" + EBPF_TRACING_PERIODIC_TASK_NAME + "' does not exist, no action taken.", exec.Status
	Else
		DeleteEbpfTracingTasks = EBPF_TRACING_SETUP_SUCCEEDED
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "SUCCESS deleting the '" + EBPF_TRACING_PERIODIC_TASK_NAME + "' task.", exec.Status
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

' This function installs the given kernel driver.
Function InstallEbpfDriver(driverName, driverPath)
	On Error Resume Next
	Const THIS_FUNCTION_NAME = "InstallEbpfDriver"
	Dim objService, driverFullPath, errReturnCode
	
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Installing driver '" + driverName + ".sys'...", 0

	driverFullPath = FsObject.BuildPath(driverPath, driverName + ".sys")
		
	oServiceAlreadyInstalled = CheckDriverInstalled(driverName)
	If oServiceAlreadyInstalled = False Then
		
		' Create the driver service
		Dim exec : Set exec = WshShell.Exec("sc.exe create " + driverName + " type=kernel start=auto binpath=""" + driverFullPath + """")				
		While exec.Status = WshRunning
			WScript.Sleep 1
		Wend
		If exec.Status = WshFailed Then
			InstallEbpfDriver = EBPF_DRIVER_INSTALL_FAILED
			LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED installing '" + driverName + ".sys'", exec.Status
		Else
			InstallEbpfDriver = EBPF_DRIVER_INSTALL_SUCCEEDED
			LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully installed '" + driverName + ".sys'", exec.Status
			
			serviceQuery = "Select * from Win32_BaseService where Name='" + driverName + "'"
			Set colServices = WmiService.ExecQuery(serviceQuery)		
			For Each objService in colServices
				errReturnCode = objService.StartService()
				If errReturnCode = 0 Then
					InstallEbpfDriver = EBPF_DRIVER_START_SUCCEEDED
					LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully started '" + driverName + ".sys'", errReturnCode
				Else
					InstallEbpfDriver = EBPF_DRIVER_START_FAILED
					LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED starting '" + driverName + ".sys'", errReturnCode
				End If
			Next			
		End If		
	Else
		InstallEbpfDriver = EBPF_DRIVER_ALREADY_INSTALLED
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "Driver '" + driverName + ".sys' already installed.", 0
	End If            
End Function

' This function stops then uninstalls the given kernel driver.
Function UninstallEbpfDriver(driverName)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "UninstallEbpfDriver"
	Dim colServices, serviceQuery, errReturnCode

	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Unnstalling driver '" + driverName + ".sys'...", 0

	serviceQuery = "Select * from Win32_BaseService where Name='" + driverName + "'"
	Set colServices = WmiService.ExecQuery(serviceQuery)

	For Each objService in colServices
		errReturnCode = objService.StopService()
		If errReturnCode = 0 Then
			UninstallEbpfDriver = EBPF_DRIVER_STOP_SUCCEEDED
			LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully stopped '" + driverName + ".sys'", errReturnCode
		Else 
			UninstallEbpfDriver = EBPF_DRIVER_STOP_FAILED
			LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED stopping '" + driverName + ".sys'", errReturnCode
			Exit For
		End If

		errReturnCode = objService.Delete()
		If errReturnCode = 0 Then
			UninstallEbpfDriver = EBPF_DRIVER_DELETE_SUCCEEDED
			LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully uninstalled '" + driverName + ".sys'", errReturnCode
		Else 
			UninstallEbpfDriver = EBPF_DRIVER_DELETE_FAILED
			LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED uninstalling '" + driverName + ".sys'", errReturnCode
			Exit For
		End If
	Next
End Function

' This function checks if the given driver is already installed.
Function CheckDriverInstalled(driverName)
	On Error Resume Next
	
	Dim colServices, serviceQuery

	CheckDriverInstalled = False
	
	serviceQuery = "Select * from Win32_BaseService where Name='" + driverName + "'"
	Set colServices = WmiService.ExecQuery(serviceQuery)
	For Each objService in colServices
		CheckDriverInstalled = True
	Next
End Function

' This function registers the given netsh extension.
Function RegisterNetshHelper(extensionName, extensionPath)
	On Error Resume Next
	
	Const THIS_FUNCTION_NAME = "RegisterNetshHelper"
	Dim errReturnCode
	
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Registering netsh.exe helper '" + extensionName + "'...", 0
	
	WshShell.CurrentDirectory = extensionPath	
	errReturnCode = ExecuteShellCmd("netsh.exe add helper " + extensionName)
	If errReturnCode <> 0 Then	
		RegisterNetshHelper = EBPF_NETSH_EXT_REGISTRATION_FAILED
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED registering '" + extensionName + "'", exec.Status
	Else
		RegisterNetshHelper = EBPF_NETSH_EXT_REGISTRATION_SUCCEEDED
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully registered '" + extensionName + "'", exec.Status
	End If
End Function

' This function unregisters the given netsh extension.
Function UnregisterNetshHelper(extensionName, extensionPath)
	On Error Resume Next
	
	Const THIS_FUNCTION_NAME = "UnregisterNetshHelper"
	Dim errReturnCode
	
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Unregistering netsh.exe helper '" + extensionName + "'...", 0
		
	WshShell.CurrentDirectory = extensionPath	
	errReturnCode = ExecuteShellCmd("netsh.exe delete helper " + extensionName)
	If errReturnCode <> 0 Then
		UnregisterNetshHelper = EBPF_NETSH_EXT_DEREGISTRATION_FAILED
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED unregistering '" + extensionName + "'", exec.Status
	Else
		UnregisterNetshHelper = EBPF_NETSH_EXT_DEREGISTRATION_SUCCEEDED
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully unregistered '" + extensionName + "'", exec.Status
	End If
End Function

' This function installs eBPF for Windows on the machine and returns true successful, false otherwise
Function InstallEbpf(sourcePath)
	On Error Resume Next
	
	Const THIS_FUNCTION_NAME = "InstallEbpf"
	Dim eBpfCoreAlreadyInstalled, eBpfNetExtAlreadyInstalled
	Dim errReturnCode
	
	InstallEbpf = True

	LogEvent EBPF_LOG_INFO, "InstallEbpf", "Installing eBPF for Windows to " + g_installPath, 0

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
    	if Not CopyFilesToPath(sourcePath, g_installPath) Then
		    InstallEbpf = False
		    Exit Function
        End If
    End If
	
	' Create the tracing tasks
	if CreateEbpfTracingTasks() = EBPF_TRACING_SETUP_FAILED Then
		InstallEbpf = False
	End If
		
	' Install the drivers and the netsh extension
	Do While True
		errReturnCode = InstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME)
		Select Case errReturnCode
		Case EBPF_DRIVER_INSTALL_FAILED
			InstallEbpf = False
			Exit Do
		Case EBPF_DRIVER_START_FAILED
			errReturnCode = UninstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME)
			InstallEbpf = False
			Exit Do
		End Select
	
		errReturnCode = InstallEbpfDriver(EBPF_EXTENSION_DRIVER_NAME)
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
		
		' errReturnCode = RegisterNetshHelper(EBPF_NETSH_EXTENSION_NAME, g_installPath)
		' Select Case errReturnCode
		' Case EBPF_NETSH_EXT_REGISTRATION_FAILED	  	  
		' 	errReturnCode = UninstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME)
		' 	errReturnCode = UninstallEbpfDriver(EBPF_EXTENSION_DRIVER_NAME)
		' 	InstallEbpf = False
		' 	Exit Do
		' Case EBPF_NETSH_EXT_REGISTRATION_PATH_FAILED
		' 	errReturnCode = UninstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME)
		' 	errReturnCode = UninstallEbpfDriver(EBPF_EXTENSION_DRIVER_NAME)
		' 	errReturnCode = UnregisterNetshHelper(EBPF_NETSH_EXTENSION_NAME, g_installPath)
		' 	InstallEbpf = False
		' 	Exit Do
		' End Select
		
		if AddSystemPath(g_installPath) = False Then
            InstallEbpf = False
        End If

		Exit Do
	Loop
	
	If InstallEbpf = True Then
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "eBPF for Windows was successfully installed!", 0
	Else
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "eBPF for Windows was NOT successfully installed.", 0
	End If
End Function

' This function uninstalls eBPF for Windows on the machine and returns true successful, false otherwise
Function UninstallEbpf()
	On Error Resume Next
	
	Const THIS_FUNCTION_NAME = "UninstallEbpf"
	Dim errReturnCode
	
	UninstallEbpf = True

	if Not FsObject.FolderExists(g_installPath) Then
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "Install path not found " + g_installPath, 0
		UninstallEbpf = False
		' Not exiting: we still want to try to remove the drivers and tracing tasks, in case they were installed in a different location
	End If

	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Uninstalling eBPF for Windows from " + g_installPath, 0
	
	errReturnCode = UninstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME)
	If errReturnCode <> EBPF_DRIVER_DELETE_SUCCEEDED Then
		UninstallEbpf = False
	End If
	
	errReturnCode = UninstallEbpfDriver(EBPF_EXTENSION_DRIVER_NAME)
	If errReturnCode <> EBPF_DRIVER_DELETE_SUCCEEDED Then
		UninstallEbpf = False
	End If
	
	' errReturnCode = UnregisterNetshHelper(EBPF_NETSH_EXTENSION_NAME, g_installPath)
	' If errReturnCode <> EBPF_NETSH_EXT_DEREGISTRATION_SUCCEEDED Then
	' 	UninstallEbpf = False
	' End If
	
	DeleteEbpfTracingTasks

	if RemoveSystemPath(g_installPath) = False Then
        UninstallEbpf = False
    End If
	
	FsObject.DeleteFolder g_installPath, True
	If Err.number <> 0 Then
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "Failed to delete folder " + g_installPath, Err.number
	End If

	If UninstallEbpf = True Then
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "eBPF for Windows was successfully uninstalled!", 0
	Else
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "eBPF for Windows was NOT successfully uninstalled!", 0
	End If
End Function