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
Const EBPF_WPR_TRACING_SETUP_FAILED				= 15
Const EBPF_WPR_TRACING_SETUP_SUCCEEDED			= 16

' String constants
Const EBPF_EBPFCORE_DRIVER_NAME				= "eBPFCore"
Const EBPF_EXTENSION_DRIVER_NAME			= "NetEbpfExt"
Const EBPF_NETSH_EXTENSION_NAME				= "ebpfnetsh.dll"
Const EBPF_WPRP_FILE_NAME					= "ebpfforwindows.wprp"
Const EBPF_WPR_TRACING_TASK_NAME			= "eBpfTracingTask"

' Logging constants
Const EBPF_LOG_BLANK		= 0
Const EBPF_LOG_INFO			= 1
Const EBPF_LOG_WARNING		= 2
Const EBPF_LOG_ERROR		= 3
Const EBPF_LOG_SOURCE		= "eBpfForWindows"
Const EBPF_LOG_FILE_NAME	= "eBpfForWindows"
Const EBPF_LOG_MAX_AGE		= 30 'Files older than this (in days) will be deleted
Const EBPF_LOG_MIN_FILES	= 10 'Minimum number of log files to keep

' Global variables
Dim g_fso
Dim g_LogFile
Dim g_PackageName
' Set to false to skip tests
Const g_RunTests			= True
Dim WshShell : Set WshShell = WScript.CreateObject("WScript.Shell") ' Comment out for WSF embedding

' Test code
If g_RunTests Then
	InstallEbpf "C:\\_ebpf\redist-package", "C:\\Program Files\ebpf-for-windows", "C:\\_ebpf\logs"
	UninstallEbpf "C:\\Program Files\ebpf-for-windows", "C:\\_ebpf\logs"
End If


Function DeleteOldLogs(logPath)
	On Error Resume Next
	
	Set fso = CreateObject("Scripting.FileSystemObject")
	Set oFolder = fso.GetFolder(logPath)
	Set aFiles = oFolder.Files
	Set aSubFolders = oFolder.SubFolders
	today = Date

	' Delete files older than EBPF_LOG_MAX_AGE days in the 'logPath' folder (and leave no less than EBPF_LOG_MIN_FILES files)
	If aFiles.Count > EBPF_LOG_MIN_FILES Then
		maxDeletions = aFiles.Count - EBPF_LOG_MIN_FILES
		For Each file in aFiles
			If maxDeletions > 0 And Instr(file.name, EBPF_LOG_FILE_NAME) And file.Extension = "log" Then
				dFileCreated = FormatDateTime(file.DateCreated, "2")
				If DateDiff("d", dFileCreated, today) > EBPF_LOG_MAX_AGE Then
					file.Delete(True)
					maxDeletions = maxDeletions - 1
				End If
			End If
		Next
	End If
End Function

' This function initializes the local log file
Function InitializeTracing(logPath)
	On Error Resume Next
	
	InitializeTracing = True

	Set g_fso = CreateObject("Scripting.FileSystemObject")
	
	' Empty path means no logging
	If Len(logPath) > 0 Then
		' Create the logging folder if it doesn't exist
		If Not g_fso.FolderExists(logPath) Then
			g_fso.CreateFolder(logPath)
			If Err.number <> 0 Then
				InitializeTracing = False
				Exit Function
			End If
		End If
		
		' Cleanup the log directory
		DeleteOldLogs logPath
	
		' Create the log file
		Set g_LogFile = g_fso.CreateTextFile(g_fso.BuildPath(logPath, EBPF_LOG_FILE_NAME + "_" + CurrentDateTimeText() + ".log"), True)
	End If
End Function

' This function stops the WPR tracing task and closes the local log file
Sub StopTracing
	g_LogFile.Close
End Sub

Function CurrentDateTimeText()	
	CurrentDateTimeText = CStr(Year(Now))+ _
						Right("0"+CStr(Month(Now)),2)+ "" + _
						Right("0"+CStr(Day(Now)),2) + "-" + _
						Right("0"+CStr(Hour(Now)),2) + _
						Right("0"+CStr(Minute(Now)),2) + _
						Right("0"+CStr(Second(Now)),2)
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

' This function creates a task to start WPR tracing at boot
Function CreateWprTracingTask(wprpPath)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "CreateWprTracingTask"
	Dim exec

	' Remove "\\" due to system drives in the path
	wprpPath = Replace(wprpPath, "\\", "\")

	' Delete the task if it already exists
	DeleteWprTracingTask wprpPath

	' Create the task
	Set exec = WshShell.Exec("schtasks /create /f /sc onstart /ru system /rl highest /tn " + EBPF_WPR_TRACING_TASK_NAME + " /tr ""wpr.exe -start '" + wprpPath + "\" + EBPF_WPRP_FILE_NAME + "' -filemode""")
	While exec.Status = WshRunning
		WScript.Sleep 1
	Wend
	If exec.Status = WshFailed Then
		CreateWprTracingTask = EBPF_WPR_TRACING_SETUP_FAILED
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED setting up WPR tracing!", exec.Status
	Else
		CreateWprTracingTask = EBPF_WPR_TRACING_SETUP_SUCCEEDED
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "WPR tracing successfully set up.", exec.Status
	End If
End Function

' This function creates a task to start WPR tracing at boot
Function DeleteWprTracingTask
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "DeleteWprTracingTask"
	Dim exec

	' Delete the task if it already exists
	Set exec = WshShell.Exec("schtasks /delete /f /tn " + EBPF_WPR_TRACING_TASK_NAME)
	While exec.Status = WshRunning
		WScript.Sleep 1
	Wend
	If exec.Status = WshFailed Then
		DeleteWprTracingTask = EBPF_WPR_TRACING_SETUP_FAILED
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "eBPF WPR tracing not removed or not present.", exec.Status
	Else
		DeleteWprTracingTask = EBPF_WPR_TRACING_SETUP_SUCCEEDED
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "WPR tracing task successfully removed.", exec.Status
	End If
End Function

' This function copies the files from the source folder to the destination folder
Function CopyFilesToPath(sourcePath, destPath)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "CopyFilesToPath"
	Dim fso, errReturnCodeDim, destinationPath
			
	CopyFilesToPath = True	
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Copying files from " + sourcePath + " to " + destPath, 0

	Set fso = CreateObject("Scripting.FileSystemObject")
	
	' Create the destination folder if it doesn't exist
	If Not fso.FolderExists(destPath) Then		
		fso.CreateFolder(destPath)
		If Err.number <> 0 Then
			LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "Failed to create folder " + destPath, Err.number
			CopyFilesToPath = False
			Exit Function
		End If
	End If

	' Copy the files to the destination folder
	fso.CopyFolder sourcePath, destPath, True
	If Err.number <> 0 Then
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "Failed to copy files from " + sourcePath + " to " + destPath, Err.number
		CopyFilesToPath = False
	End If
End Function

' This function installs eBPF for Windows on the machine and returns true successful, false otherwise
Function InstallEbpf(sourcePath, installPath, logPath)
	On Error Resume Next
	
	Const THIS_FUNCTION_NAME = "InstallEbpf"
	Dim eBpfCoreAlreadyInstalled, eBpfNetExtAlreadyInstalled
	Dim fso, errReturnCode
	
	InstallEbpf = True

	InitializeTracing logPath
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
			LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "ERROR!! eBPF for Windows installation is corrupt!", 0
			Exit Function
		End If
	End If

	' Copy the files to the install path
	if Not CopyFilesToPath(sourcePath, installPath) Then
		InstallEbpf = False
		Exit Function
	End If
	
	' Create the WPR tracing task
	if CreateWprTracingTask(installPath) = EBPF_WPR_TRACING_SETUP_FAILED Then
		InstallEbpf = False
	End If
		
	' Install the drivers and the netsh extension
	Set fso = CreateObject("Scripting.FileSystemObject")
	driversPath = fso.BuildPath(installPath, "drivers")	
	Do While True
		errReturnCode = InstallDriver(EBPF_EBPFCORE_DRIVER_NAME, driversPath, "auto")
		Select Case errReturnCode
		Case EBPF_DRIVER_INSTALL_FAILED
			InstallEbpf = False
			Exit Do
		Case EBPF_DRIVER_START_FAILED
			errReturnCode = UninstallDriver(EBPF_EBPFCORE_DRIVER_NAME)
			InstallEbpf = False
			Exit Do
		End Select
	
		errReturnCode = InstallDriver(EBPF_EXTENSION_DRIVER_NAME, driversPath, "auto")
		Select Case errReturnCode
		Case EBPF_DRIVER_INSTALL_FAILED	  	  
			errReturnCode = UninstallDriver(EBPF_EBPFCORE_DRIVER_NAME)
			InstallEbpf = False
			Exit Do
		Case EBPF_DRIVER_START_FAILED
			errReturnCode = UninstallDriver(EBPF_EBPFCORE_DRIVER_NAME)
			errReturnCode = UninstallDriver(EBPF_EXTENSION_DRIVER_NAME)
			InstallEbpf = False
			Exit Do
		End Select
		
		errReturnCode = RegisterNetshHelper(EBPF_NETSH_EXTENSION_NAME, installPath)
		Select Case errReturnCode
		Case EBPF_NETSH_EXT_REGISTRATION_FAILED	  	  
			errReturnCode = UninstallDriver(EBPF_EBPFCORE_DRIVER_NAME)
			errReturnCode = UninstallDriver(EBPF_EXTENSION_DRIVER_NAME)
			InstallEbpf = False
			Exit Do
		Case EBPF_NETSH_EXT_REGISTRATION_PATH_FAILED
			errReturnCode = UninstallDriver(EBPF_EBPFCORE_DRIVER_NAME)
			errReturnCode = UninstallDriver(EBPF_EXTENSION_DRIVER_NAME)
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
Function UninstallEbpf(installPath, logPath)
	On Error Resume Next
	
	Const THIS_FUNCTION_NAME = "UninstallEbpf"
	Dim fso, errReturnCode
	
	UninstallEbpf = True

	InitializeTracing logPath

	Set fso = CreateObject("Scripting.FileSystemObject")
	if Not fso.FolderExists(installPath) Then
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "Install path not found " + installPath, 0
		UninstallEbpf = False
		Exit Function
	End If

	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Uninstalling eBPF for Windows from " + installPath, 0
	
	errReturnCode = UninstallDriver(EBPF_EBPFCORE_DRIVER_NAME)
	If errReturnCode <> EBPF_DRIVER_DELETE_SUCCEEDED Then
		UninstallEbpf = False
	End If
	
	errReturnCode = UninstallDriver(EBPF_EXTENSION_DRIVER_NAME)
	If errReturnCode <> EBPF_DRIVER_DELETE_SUCCEEDED Then
		UninstallEbpf = False
	End If
	
	errReturnCode = UnregisterNetshHelper(EBPF_NETSH_EXTENSION_NAME, installPath)
	If errReturnCode <> EBPF_NETSH_EXT_DEREGISTRATION_SUCCEEDED Then
		UninstallEbpf = False
	End If
	
	DeleteWprTracingTask
	
	fso.DeleteFolder installPath, True
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
Function InstallDriver(driverName, driverPath, startMode)
	On Error Resume Next
	Const THIS_FUNCTION_NAME = "InstallDriver"
	Dim fso, objWMIService, objService, driverFullPath, errReturnCode
	
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Installing driver '" + driverName + ".sys'...", 0

	Set fso = CreateObject("Scripting.FileSystemObject")
	driverFullPath = fso.BuildPath(driverPath, driverName + ".sys")
		
	oServiceAlreadyInstalled = CheckDriverInstalled(driverName)
	If oServiceAlreadyInstalled = False Then
		
		' Create the driver service
		Dim exec : Set exec = WshShell.Exec("sc.exe create " + driverName + " type=kernel start=" + startMode + " binpath=""" + driverFullPath + """")				
		While exec.Status = WshRunning
			WScript.Sleep 1
		Wend
		If exec.Status = WshFailed Then
			InstallDriver = EBPF_DRIVER_INSTALL_FAILED
			LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED installing '" + driverName + ".sys'", exec.Status
		Else
			InstallDriver = EBPF_DRIVER_INSTALL_SUCCEEDED
			LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully installed '" + driverName + ".sys'", exec.Status
			
			Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
			serviceQuery = "Select * from Win32_BaseService where Name='" + driverName + "'"
			Set colServices = objWMIService.ExecQuery(serviceQuery)		
			For Each objService in colServices
				errReturnCode = objService.StartService()
				If errReturnCode = 0 Then
					InstallDriver = EBPF_DRIVER_START_SUCCEEDED
					LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully started '" + driverName + ".sys'", errReturnCode
				Else
					InstallDriver = EBPF_DRIVER_START_FAILED
					LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED starting '" + driverName + ".sys'", errReturnCode
				End If
			Next			
		End If		
	Else
		InstallDriver = EBPF_DRIVER_ALREADY_INSTALLED
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "Driver '" + driverName + ".sys' already installed.", 0
	End If            
End Function

' This function uninstalls the given kernel driver.
Function UninstallDriver(driverName)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "UninstallDriver"
	Dim objWMIService, colServices, serviceQuery, errReturnCode
	
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Unnstalling driver '" + driverName + ".sys'...", 0
	
	Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
	serviceQuery = "Select * from Win32_BaseService where Name='" + driverName + "'"
	Set colServices = objWMIService.ExecQuery(serviceQuery)

	For Each objService in colServices
		errReturnCode = objService.StopService()
		If errReturnCode = 0 Then
			UninstallDriver = EBPF_DRIVER_STOP_SUCCEEDED
			LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully stopped '" + driverName + ".sys'", errReturnCode
		Else 
			UninstallDriver = EBPF_DRIVER_STOP_FAILED
			LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED stopping '" + driverName + ".sys'", errReturnCode
			Exit For
		End If

		errReturnCode = objService.Delete()
		If errReturnCode = 0 Then
			UninstallDriver = EBPF_DRIVER_DELETE_SUCCEEDED
			LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully uninstalled '" + driverName + ".sys'", errReturnCode
		Else 
			UninstallDriver = EBPF_DRIVER_DELETE_FAILED
			LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED uninstalling '" + driverName + ".sys'", errReturnCode
			Exit For
		End If
	Next
End Function

' This function checks if the given driver is already installed.
Function CheckDriverInstalled(driverName)
	On Error Resume Next
	
	Dim objWMIService, colServices, serviceQuery

	CheckDriverInstalled = False
	
	Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
	serviceQuery = "Select * from Win32_BaseService where Name='" + driverName + "'"
	Set colServices = objWMIService.ExecQuery(serviceQuery)
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
	Dim exec : Set exec = WshShell.Exec("netsh.exe add helper " + extensionName)
	While exec.Status = WshRunning
		WScript.Sleep 1
	Wend
	If exec.Status = WshFailed Then		
		RegisterNetshHelper = EBPF_NETSH_EXT_REGISTRATION_FAILED
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED registering '" + extensionName + "'", exec.Status
	Else
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully registered '" + extensionName + "'", exec.Status
		
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
	Dim exec : Set exec = WshShell.Exec("netsh.exe delete helper " + extensionName)
	While exec.Status = WshRunning
		WScript.Sleep 1
	Wend
	If exec.Status = WshFailed Then		
		UnregisterNetshHelper = EBPF_NETSH_EXT_DEREGISTRATION_FAILED
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "FAILED unregistering '" + extensionName + "'", exec.Status
	Else
		UnregisterNetshHelper = EBPF_NETSH_EXT_DEREGISTRATION_SUCCEEDED
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Successfully unregistered '" + extensionName + "'", exec.Status
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