'-------------------------------------------------------------------
'------------- EBPF Install/Uninstall Functions --------------------
'-------------------------------------------------------------------
' String constants
Const EBPF_EBPFCORE_DRIVER_NAME             = "eBPFCore"
Const EBPF_EXTENSION_DRIVER_NAME            = "NetEbpfExt"
Const EBPF_TRACING_STARTUP_TASK_NAME        = "eBpfTracingStartupTask"
Const EBPF_TRACING_STARTUP_TASK_FILENAME    = "ebpf_tracing_startup_task.xml"
Const EBPF_TRACING_PERIODIC_TASK_NAME       = "eBpfTracingPeriodicTask"
Const EBPF_TRACING_PERIODIC_TASK_FILENAME   = "ebpf_tracing_periodic_task.xml"
Const EBPF_TRACING_TASK_CMD                 = "ebpf_tracing.cmd"

' Global variables
Dim WmiService : Set WmiService = GetObject("winmgmts:\\.\root\cimv2")
Dim g_tracingPath: g_tracingPath = FsObject.BuildPath(WshShell.ExpandEnvironmentStrings("%SystemRoot%"), "\Logs\eBPF")
Dim g_installPath: g_installPath = FsObject.BuildPath(WshShell.ExpandEnvironmentStrings("%ProgramFiles%"), "\ebpf-for-windows")


' Adds a new path to the System path, unless the path is already present in the system path.
Function AddSystemPath(pathToAdd)
	On Error Resume Next

	AddSystemPath = True
	
	Dim sysENV : Set sysENV = WshShell.Environment("System")
	systemPath = sysENV("PATH")
	If InStr(systemPath, pathToAdd) = 0 Then
		sysENV("PATH") = systemPath + ";" + pathToAdd
	End If

	Set oTraceEvent = g_Trace.CreateEvent("INFO")		
	With oTraceEvent.appendChild(oTraceEvent.ownerDocument.createElement("AddSystemPath"))
		.setAttribute "pathToAdd", pathToAdd
	End With
	g_Trace.TraceEvent oTraceEvent
End Function

' Removes the given path from the System path, unless the path isn't present.
Function RemoveSystemPath(pathToRemove)
	On Error Resume Next

	RemoveSystemPath =  True

	Dim sysENV : Set sysENV = WshShell.Environment("System")
	systemPath = sysENV("PATH")
	If InStr(systemPath, pathToRemove) <> 0 Then
		systemPath = Replace(systemPath, pathToRemove, "")
		systemPath = Replace(systemPath, ";;", ";")
		sysENV("PATH") = systemPath
	End If

	Set oTraceEvent = g_Trace.CreateEvent("INFO")		
	With oTraceEvent.appendChild(oTraceEvent.ownerDocument.createElement("RemoveSystemPath"))
		.setAttribute "pathToRemove", pathToRemove
	End With
	g_Trace.TraceEvent oTraceEvent
End Function

' This function moves the files from the source folder to the destination folder
Function MoveFilesToPath(sourcePath, destPath)
	On Error Resume Next

	MoveFilesToPath = True	

	' Create the destination folder if it doesn't exist
	If Not FsObject.FolderExists(destPath) Then		
		call FsObject.CreateFolder(destPath)
		If TraceError(g_Trace, "Failed to create folder " + destPath) <> 0 Then
			MoveFilesToPath = False
		End If
	End If

	If MoveFilesToPath = True Then
		' Move all files and subfolders from the source folder to the destination folder
		call FsObject.MoveFile(sourcePath & "\*.*", destPath & "\")		
		If TraceError(g_Trace, "Failed to move files from " + sourcePath + " to " + destPath) <> 0 Then
			MoveFilesToPath = False
		End If

		call FsObject.MoveFolder(sourcePath & "\*", destPath & "\")
		If TraceError(g_Trace, "Failed to move subfolders from " + sourcePath + " to " + destPath) <> 0 Then
			MoveFilesToPath = False
		End If
	End If
End Function

' Creates a scheduled task using the given task file returns the exitcode of schtasks
Function CreateScheduledTask(taskName, taskFile)
	On Error Resume Next

	Dim oResults, oTraceEvent, taskCommand

	taskCommand = "%SystemRoot%\System32\schtasks.exe /create /tn " & taskName & " /xml """ & taskFile & """"
	Set oResults = ExecuteAndTraceWithResults(taskCommand, g_Trace)

	If oResults.ExitCode = 0 Then
		Set oTraceEvent = g_Trace.CreateEvent("INFO")
		With oTraceEvent.appendChild(oTraceEvent.ownerDocument.createElement("CreateScheduledTask"))
			.setAttribute "task", CStr(taskName)
		End With
		g_Trace.TraceEvent oTraceEvent
	End If

	CreateScheduledTask = oResults.ExitCode
End Function

' Delete a scheduled task returns the exitcode of schtasks
Function DeleteScheduledTask(taskName)
	On Error Resume Next

	Dim oResults, oTraceEvent, taskCommand

	taskCommand = "%SystemRoot%\System32\schtasks.exe /delete /tn " & taskName & " /f"
	Set oResults = ExecuteAndTraceWithResults(taskCommand, g_Trace)

	If oResults.ExitCode = 0 Then
		Set oTraceEvent = g_Trace.CreateEvent("INFO")
		With oTraceEvent.appendChild(oTraceEvent.ownerDocument.createElement("DeleteScheduledTask"))
			.setAttribute "task", CStr(taskName)
		End With
		g_Trace.TraceEvent oTraceEvent
	End If

	DeleteScheduledTask = oResults.ExitCode
End Function

' This function creates tasks to start eBPF tracing at boot, and execute periodic rundowns
Function CreateEbpfTracingTasks()
	On Error Resume Next

	CreateEbpfTracingTasks = true
	Dim taskFilePath

	' Delete the tasks if they already exist
	call DeleteEbpfTracingTasks()

	' Create the scheduled tasks
	taskFilePath = FsObject.BuildPath(g_installPath, EBPF_TRACING_STARTUP_TASK_FILENAME)
	if CreateScheduledTask(EBPF_TRACING_STARTUP_TASK_NAME, taskFilePath) <> 0 Then
		CreateEbpfTracingTasks = False
		Exit Function
	End If
	
	taskFilePath = FsObject.BuildPath(g_installPath, EBPF_TRACING_PERIODIC_TASK_FILENAME)
	if CreateScheduledTask(EBPF_TRACING_PERIODIC_TASK_NAME, taskFilePath) <> 0 Then
		call DeleteEbpfTracingTasks()
		CreateEbpfTracingTasks = False
	End If
End Function

' This function deletes the tasks to start eBPF tracing at boot, and execute periodic rundowns, and deletes the g_tracingPath
Function DeleteEbpfTracingTasks()
	On Error Resume Next
	Const THIS_FUNCTION_NAME = "DeleteEbpfTracingTasks"

	DeleteEbpfTracingTasks = True

	' Execute the script to stop eBPF tracing
	Dim scriptPath : scriptPath = FsObject.BuildPath(g_installPath, EBPF_TRACING_TASK_CMD)
	If FsObject.FileExists(scriptPath) Then
		Set oTraceEvent = g_Trace.CreateEvent("INFO")
		With oTraceEvent.appendChild(oTraceEvent.ownerDocument.createElement(THIS_FUNCTION_NAME))
			.setAttribute "StopEbpfTracing", scriptPath
		End With
		g_Trace.TraceEvent oTraceEvent
		
		If ExecuteAndTraceWithResults("""" + scriptPath + """ stop /trace_path """ + g_tracingPath + """", g_trace).ExitCode <> 0 Then
			DeleteEbpfTracingTasks = False
		End If
	Else
		Set oTraceEvent = g_Trace.CreateEvent("ERROR")
		With oTraceEvent.appendChild(oTraceEvent.ownerDocument.createElement(THIS_FUNCTION_NAME))
			.setAttribute "EbpfTaskScriptNotFound", scriptPath
		End With
		g_Trace.TraceEvent oTraceEvent
	End If

	' Delete the startup task. if it already exists
	if DeleteScheduledTask(EBPF_TRACING_STARTUP_TASK_NAME) <> 0 Then
		DeleteEbpfTracingTasks = False
	End If

	' Delete the periodic task. if it already exists
	if DeleteScheduledTask(EBPF_TRACING_PERIODIC_TASK_NAME) <> 0 Then
		DeleteEbpfTracingTasks = False
	End If
End Function

' This function checks if the given driver is already installed.
Function CheckDriverInstalled(driverName)
	On Error Resume Next

	CheckDriverInstalled = False

	Dim colServices, serviceQuery
	serviceQuery = "Select * from Win32_BaseService where Name='" + driverName + "'"
	Set colServices = WmiService.ExecQuery(serviceQuery)
	For Each objService in colServices
		CheckDriverInstalled = True
		Exit For
	Next
End Function

' This function installs the given kernel driver.
Function InstallEbpfDriver(driverName)
	On Error Resume Next

	InstallEbpfDriver = True
	Dim driverFullPath: driverFullPath = FsObject.BuildPath(g_installPath, "\drivers\" + driverName + ".sys")
	
	Set oTraceEvent = g_Trace.CreateEvent("INFO")
	With oTraceEvent.appendChild(oTraceEvent.ownerDocument.createElement("InstallEbpfDriver"))
		.setAttribute "driverFullPath", driverFullPath
	End With
	g_Trace.TraceEvent oTraceEvent

	Dim oResults: Set oResults = ExecuteAndTraceWithResults("sc.exe create " + driverName + " type=kernel start=auto binpath=""" + driverFullPath + """", g_trace)
	if oResults.ExitCode <> 0 Then
		InstallEbpfDriver = False
	End If
End Function

' This function stops then uninstalls the given kernel driver.
Function UninstallEbpfDriver(driverName)
	On Error Resume Next

	Const THIS_FUNCTION_NAME = "UninstallEbpfDriver"
	Dim colServices, serviceQuery, errReturnCode

	UninstallEbpfDriver = True
	Dim driverFullPath: driverFullPath = FsObject.BuildPath(g_installPath, "\drivers\" + driverName + ".sys")

	serviceQuery = "Select * from Win32_BaseService where Name='" + driverName + "'"
	Set colServices = WmiService.ExecQuery(serviceQuery)
	For Each objService in colServices

		Set oTraceEvent = g_Trace.CreateEvent("INFO")
		With oTraceEvent.appendChild(oTraceEvent.ownerDocument.createElement(THIS_FUNCTION_NAME))
			.setAttribute "driverFullPath", driverFullPath
		End With		
		g_Trace.TraceEvent oTraceEvent

		errReturnCode = objService.StopService()
		If errReturnCode <> 0 Then
			UninstallEbpfDriver = False
			Set oTraceEvent = g_Trace.CreateEvent("ERROR")
			With oTraceEvent.appendChild(oTraceEvent.ownerDocument.createElement(THIS_FUNCTION_NAME))
				.setAttribute "StopDriver", "False"
				.setAttribute "driverFullPath", driverFullPath
			End With		
			g_Trace.TraceEvent oTraceEvent
		End If

		errReturnCode = objService.Delete()
		If errReturnCode <> 0 Then
			UninstallEbpfDriver = False
			Set oTraceEvent = g_Trace.CreateEvent("ERROR")
			With oTraceEvent.appendChild(oTraceEvent.ownerDocument.createElement(THIS_FUNCTION_NAME))
				.setAttribute "deleteDriver", "False"
				.setAttribute "driverFullPath", driverFullPath
			End With		
			g_Trace.TraceEvent oTraceEvent
		End If
	Next
End Function

' This function uninstalls eBPF for Windows on the machine and returns true successful, false otherwise
Function UninstallEbpf(shouldDeleteEbpfTracingTasks)
	On Error Resume Next
	
	UninstallEbpf = True

	Set oTraceEvent = g_Trace.CreateEvent("INFO")
	With oTraceEvent.appendChild(oTraceEvent.ownerDocument.createElement("UninstallEbpf"))
		.setAttribute "g_installPath", g_installPath
		.setAttribute "installationPathPresent", FsObject.FolderExists(g_installPath)
	End With
	g_Trace.TraceEvent oTraceEvent

	If UninstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME) = False Then
		UninstallEbpf = False
	End If

	If UninstallEbpfDriver(EBPF_EXTENSION_DRIVER_NAME) = False Then
		UninstallEbpf = False
	End If

	If shouldDeleteEbpfTracingTasks = True Then
		If DeleteEbpfTracingTasks() = False Then
			UninstallEbpf = False
		End If
	End If

	if RemoveSystemPath(g_installPath) = False Then
		UninstallEbpf = False
	End If

	call DeleteFolder(g_installPath)
End Function

' This function installs eBPF for Windows on the machine and returns true successful, false otherwise
Function CleanInstallEbpf(sourcePath)
	On Error Resume Next

	CleanInstallEbpf = True

	Set oTraceEvent = g_Trace.CreateEvent("INFO")
	With oTraceEvent.appendChild(oTraceEvent.ownerDocument.createElement("CleanInstallEbpf"))
		.setAttribute "sourcePath", sourcePath
		.setAttribute "g_installPath", g_installPath
		.setAttribute "installationPathPresent", FsObject.FolderExists(g_installPath)
	End With
	g_Trace.TraceEvent oTraceEvent

	CleanInstallEbpf = UninstallEbpf(False)

	' Move the files to the install path
	if Not MoveFilesToPath(sourcePath, g_installPath) Then
		CleanInstallEbpf = False
		Exit Function
	End If

	' Install the drivers and add the install path to the system path
	If InstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME) = False Then
		CleanInstallEbpf = False
		Exit Function
	End If

	If InstallEbpfDriver(EBPF_EXTENSION_DRIVER_NAME) = False Then
		CleanInstallEbpf = False
		call UninstallEbpfDriver(EBPF_EBPFCORE_DRIVER_NAME)
		Exit Function
	End If
	
	if AddSystemPath(g_installPath) = False Then
		CleanInstallEbpf = False
	End If
End Function