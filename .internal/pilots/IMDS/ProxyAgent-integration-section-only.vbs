'-------------------------------------------------------------------
'------------- EBPF Install/Uninstall Functions --------------------
'-------------------------------------------------------------------
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
Const EBPF_TRACING_SETUP_FAILED				    = 15
Const EBPF_TRACING_SETUP_SUCCEEDED			    = 16

' String constants
Const EBPF_EBPFCORE_DRIVER_NAME				= "eBPFCore"
Const EBPF_EXTENSION_DRIVER_NAME			= "NetEbpfExt"
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
Dim EBPF_LOG_VERBOSITY: EBPF_LOG_VERBOSITY = EBPF_LOG_INFO

' Global variables
Dim WmiService : Set WmiService = GetObject("winmgmts:\\.\root\cimv2")

' This function logs a message to the g_Trace log object
Sub LogEvent(level, method, logStatement, errReturnCode)
	On Error Resume Next
	  
	If EBPF_LOG_VERBOSITY <= level Then
		Select Case level
		Case EBPF_LOG_INFO
			Set oTraceEvent = g_Trace.CreateEvent("INFO")
		Case EBPF_LOG_WARNING
            Set oTraceEvent = g_Trace.CreateEvent("WARNING")
		Case Else
            Set oTraceEvent = g_Trace.CreateEvent("ERROR")
		End Select	
		
        With oTraceEvent.appendChild(oTraceEvent.ownerDocument.createElement(method))
            .setAttribute "Source", EBPF_LOG_SOURCE
            .setAttribute "Description", logStatement
            .setAttribute "RerutnCode", CStr(errReturnCode)
        End With
        g_Trace.TraceEvent oTraceEvent
	End If
End Sub

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

' This function installs the given kernel driver.
Function InstallEbpfDriver(installPath, driverName)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "InstallEbpfDriver"
	Dim driverFullPath, errReturnCode
    	
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Installing driver '" + driverName + ".sys'...", 0

    driverFullPath = FsObject.BuildPath(installPath, "drivers\" + driverName + ".sys")
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
    End If		
End Function

' This function starts the given kernel driver (for delayed start).
Function StartEbpfDriver(driverName)
	On Error Resume Next
	Const THIS_FUNCTION_NAME = "StartEbpfDriver"
	Dim objService, serviceQuery, errReturnCode
    	
	LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "Starting driver '" + driverName + ".sys'...", 0

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

' Adds a new path to the System PATH, unless the path is already present in the system path.
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

' Removes the given path from the System PATH, unless the path isn't present.
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

' This function installs eBPF for Windows on the machine and returns true successful, false otherwise
Function InstallEbpf(sourcePath, installPath, tracePath)
	On Error Resume Next
	
	Const THIS_FUNCTION_NAME = "InstallEbpf"
	Dim eBpfCoreAlreadyInstalled, eBpfNetExtAlreadyInstalled
	Dim errReturnCode
	
	InstallEbpf = True

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
	
	' Will be done out of the critical path
	' if CreateeBPFTracingTasks(installPath, tracePath) <> EBPF_TRACING_SETUP_SUCCEEDED  Then
	' 	InstallEbpf = False
	' End If
		
	' Install the drivers and add the install path to the system path
	driversPath = FsObject.BuildPath(installPath, "drivers")	
	Do While True

		errReturnCode = InstallEbpfDriver(EBPF_EXTENSION_DRIVER_NAME, driversPath, "auto")
		Select Case errReturnCode
		Case EBPF_DRIVER_INSTALL_FAILED	  	  
			errReturnCode = UninstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME)
			InstallEbpf = False
			Exit Do
		End Select

		errReturnCode = InstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME, driversPath, "auto")
		Select Case errReturnCode
		Case EBPF_DRIVER_INSTALL_FAILED
			InstallEbpf = False
			Exit Do
		End Select

		if AddSystemPath(installPath) = False Then
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
Function UninstallEbpf(installPath, tracePath)
	On Error Resume Next
	
	Const THIS_FUNCTION_NAME = "UninstallEbpf"
	Dim errReturnCode
	
	UninstallEbpf = True

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

	' Will be done out of the critical path
	' if DeleteEbpfTracingTasks(installPath, tracePath) <> EBPF_TRACING_SETUP_SUCCEEDED Then
    '     UninstallEbpf = False
    ' End If

    if RemoveSystemPath(installPath) = False Then
        UninstallEbpf = False
    End If

	FsObject.DeleteFolder installPath, True
	If Err.number <> 0 Then
		LogEvent EBPF_LOG_WARNING, THIS_FUNCTION_NAME, "Failed to delete folder " + installPath, Err.number
	End If

	If UninstallEbpf = True Then
		LogEvent EBPF_LOG_INFO, THIS_FUNCTION_NAME, "eBPF for Windows was successfully uninstalled!", 0
	Else
		LogEvent EBPF_LOG_ERROR, THIS_FUNCTION_NAME, "eBPF for Windows was NOT successfully uninstalled!", 0
	End If
End Function