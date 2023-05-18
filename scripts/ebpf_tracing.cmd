@rem Copyright (c) Microsoft Corporation
@rem SPDX-License-Identifier: MIT

@rem Script behavior:
@rem - When called with 'start', it will:
@rem 	- Setup the logman session named as defined in 'trace_name', capping circular-log file size to 'max_file_size_mb', and generating every 'rundown_period'.
@rem    - Configure the WFP/eBPF events to be monitored
@rem    - Start the session within the given 'trace_path' directory.
@rem - When called with 'stop', it will:
@rem 	- Stop then delete the logman session, and finally deletes the 'trace_path' directory.
@rem - When called with 'periodic', it will:
@rem 	- Run 'netsh wfp show state' into the 'trace_path' directory, and if the file is under 'max_file_size_mb', it will move it into the '.\committed' subfolder, adding a timestamp to its name.
@rem 	- Iterate over all the '.etl' files in the 'trace_path' directory, sorted in descending order by "date modified", skip the first 'num_etl_files_to_keep' files and move the others into the '.\committed' subfolder.
@rem 	- Iterate over all the '.etl' and '.xml' files in the '.\committed' subfolder and delete files older than 'files_max_age_days' days.

@echo off
setlocal enabledelayedexpansion

@rem Define the default parameters values for the tracing session and the periodic cleanup job.
set "command="
set "trace_path="
set "trace_name=ebpf_diag"
set "rundown_period=0:35:00"
set "max_file_size_mb=20"
set "max_committed_folder_size_mb=200"
set "max_committed_rundown_state_files=1"

:parse_args
if "%~1" == "" goto :validate_args
if /i "%~1" == "start" set "command=%~1" & shift & goto :parse_args
if /i "%~1" == "stop" set "command=%~1" & shift & goto :parse_args
if /i "%~1" == "periodic" set "command=%~1" & shift & goto :parse_args
if "%~1" == "/trace_path" set "trace_path=%~2" & shift & shift & goto :parse_args
if "%~1" == "/trace_name" set "trace_name=%~2" & shift & shift & goto :parse_args
if "%~1" == "/rundown_period" set rundown_period=%~2 & shift & shift & goto :parse_args
if "%~1" == "/max_file_size_mb" set max_file_size_mb=%~2 & shift & shift & goto :parse_args
if "%~1" == "/max_committed_folder_size_mb" set max_committed_folder_size_mb=%~2 & shift & shift & goto :parse_args
if "%~1" == "/max_committed_rundown_state_files" set max_committed_rundown_state_files=%~2 & shift & shift & goto :parse_args
echo Unknown parameter: "%~1"
goto :usage

:validate_args
if "%command%" == "" (
    echo Mandatory parameter 'command' is missing.
    goto :usage
)
if not "%command%" == "start" if not "%command%" == "stop" if not "%command%" == "periodic" (
    echo Error: Invalid command specified: '%command%'. Valid values are start, stop, and periodic.
    goto :usage
)
if "%trace_path%" == "" (
    echo Error: Mandatory parameter 'trace_path' is missing.
    goto :usage
)

:run_command
@rem Uncomment ECHOs below for debugging purposes.
@rem ----------------------------------------------
@rem echo Running with the following parameter values:
@rem echo command=%command%
@rem echo trace_path=%trace_path%
@rem echo trace_name=%trace_name%
@rem echo rundown_period=%rundown_period%
@rem echo max_file_size_mb=%max_file_size_mb%
@rem echo max_committed_folder_size_mb=%max_committed_folder_size_mb%
@rem echo max_committed_rundown_state_files=%max_committed_rundown_state_files%

@rem Internal constants
set /a num_etl_files_to_keep=1
set /a max_file_size_bytes=!max_file_size_mb!*1000000

if not exist "!trace_path!" (
	echo Creating trace_path "!trace_path!"
	mkdir "!trace_path!"
)

if "%command%"=="periodic" (

    @rem Create a subdirectory for the committed files (if not already present).
	set "traceCommittedPath=!trace_path!\committed"
	if not exist "!traceCommittedPath!" (
		mkdir "!traceCommittedPath!"
	)

	@rem Obtain rundown state
	@rem Get the current date and time in a format suitable for file names.
	for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do (
		set "dt=%%a"
		set "YYYY=!dt:~0,4!" & set "MM=!dt:~4,2!" & set "DD=!dt:~6,2!"
		set "HH=!dt:~8,2!" & set "Min=!dt:~10,2!" & set "Sec=!dt:~12,2!"
		set "timestamp=!YYYY!!MM!!DD!_!HH!!Min!!Sec!"
	)

    @rem Run down the WFP state.
    pushd "!trace_path!"
    netsh wfp show state
    popd
    set "wfp_state_file_cab=!trace_path!\wfpstate.cab"
	makecab "!trace_path!\wfpstate.xml" "!wfp_state_file_cab!"
	if exist "!wfp_state_file_cab!" (

		@rem If the file size is less or equal than 'max_file_size_mb', then move it to the 'traceCommittedPath' directory.
		for %%F in ("!wfp_state_file_cab!") do (
			if %%~zF LEQ %max_file_size_bytes% (
				@rem Move the .CAB file to the 'traceCommittedPath' directory.
				move /y "!wfp_state_file_cab!" "!traceCommittedPath!\wfpstate_!timestamp!.cab" >nul
			) else (
				@rem If the .CAB file size is greater than 'max_file_size_mb', then delete it.
				del "!wfp_state_file_cab!"
			)
		)
	)

	@rem Run down the program state using bpftool
	pushd "!trace_path!"
	@rem Capture program output
	echo bpftool.exe -p prog >> bpf_state.txt
	bpftool.exe -p prog >> bpf_state.txt

	@rem Capture link output
	echo bpftool.exe -p link >> bpf_state.txt
	bpftool.exe -p link >> bpf_state.txt

	@rem Capture map output
	echo bpftool.exe -p map >> bpf_state.txt
	bpftool.exe -p map >> bpf_state.txt

	@rem Capture map content output. This requires the map id value to be passed in.
	@rem This script parses the 'Bpftool.exe map' output to extract the map ids to be passed into the 'bpftool.exe map dump' command
	@rem Store 'bpftool.exe -j map' output
	for /F "usebackq" %%A in (`bpftool.exe -j map`) do set "jsonString=%%A"

	@rem Clean the output to parse it.
	@rem Remove the outer brackets '[' and ']'
	set "jsonString=!jsonString:~1,-1!"
	@rem Remove other characters from the output: '{', '}', and '"'
	set "jsonString=!jsonString:{=%!"
	set "jsonString=!jsonString:}=%!"
	set "jsonString=!jsonString:"=%!"

	@rem Split the string into key,value pairs
	@REM for %%A in ("%jsonString:,=" "%") do (
	for %%A in ("!jsonString:,=" "!") do (
		set "jsonKeyValue=%%~A"

		@rem Split each pair into separate key and value variables
		for /F "tokens=1,2 delims=:" %%B in ("!jsonKeyValue!") do (
			set "key=%%B"
			set "value=%%C"
		)

		@rem If the 'key' is 'id', then use the 'value' (id value) to capture the output of 'bpftool.exe map dump'
		if "!key!"=="id" (
			echo bpftool.exe map dump id !value! >> bpf_state.txt
			bpftool.exe map dump id !value! >> bpf_state.txt
		)
	)
	set "bpf_state_file=!trace_path!\bpf_state.txt"
	if exist "!bpf_state_file!" (
		@rem If the file size is less or equal than 'max_file_size_mb', then move it to the 'traceCommittedPath' directory.
		for %%F in ("!bpf_state_file!") do (
			if %%~zF LEQ %max_file_size_bytes% (
				@rem Move the file to the 'traceCommittedPath' directory.
				move /y "!bpf_state_file!" "!traceCommittedPath!\bpfstate_!timestamp!.txt" >nul
			) else (
				@rem If the file size is greater than 'max_file_size_mb', then delete it.
				del "!bpf_state_file!"
			)
		)
	)
	popd

	@rem Iterate over all the .etl files in the 'trace_path' directory, sorted in descending order by name,
	@rem and skip the first 'num_etl_files_to_keep' files (i.e., the newest 'num_etl_files_to_keep' files).
	for /f "skip=%num_etl_files_to_keep% delims=" %%f in ('dir /b /o-n "!trace_path!\*.etl"') do (
		move /y "!trace_path!\%%f" "!traceCommittedPath!" >nul
	)

	@rem Iterate over all the WFP-state files in the 'traceCommittedPath' directory, and delete files overflowing `max_committed_rundown_state_files`.
	for /f "skip=%max_committed_rundown_state_files% delims=" %%f in ('dir /b /o-d "!traceCommittedPath!\wfpstate*.cab"') do ( del "!traceCommittedPath!\%%f" )

	@rem Iterate over all the bpf state files in the 'traceCommittedPath' directory, and delete files overflowing `max_committed_rundown_state_files`.
	for /f "skip=%max_committed_rundown_state_files% delims=" %%f in ('dir /b /o-d "!traceCommittedPath!\bpfstate*.txt"') do ( del "!traceCommittedPath!\%%f" )

	@rem Iterate over all the .ETL files in the 'traceCommittedPath' directory, and delete the older files overflowing `max_committed_folder_size_mb`.
	set size=0
	set /a max_committed_folder_size_kb=!max_committed_folder_size_mb! * 1024
	for /f "skip=1 delims=" %%f in ('dir /b /o-d "!traceCommittedPath!\*.etl"') do (
		for /f "skip=1 tokens=2 delims==; " %%g in ('wmic datafile where "name='!traceCommittedPath:\=\\!\\%%f'" get filesize /value') do (
			set "file_size=%%g"
			set /a size=!size! + !file_size! / 1024
			if !size! gtr !max_committed_folder_size_kb! (
				del "!traceCommittedPath!\%%f"
			)
		)
	)

) else if "%command%"=="start" (

	@rem Set up the tracing session.
	logman create trace !trace_name! -o "!trace_path!\ebpf_trace" -f bincirc -max %max_file_size_mb% -cnf %rundown_period% -v mmddhhmm

	@rem Define the WFP events to be traced.
	logman update trace !trace_name! -p "{00e7ee66-5b24-5c41-22cb-af98f63e2f90}" 0x7 0x4

	@rem Define the eBPF events to be traced.
	logman update trace !trace_name! -p "{394f321c-5cf4-404c-aa34-4df1428a7f9c}" 0xffffffffffffffff 0x4
	logman update trace !trace_name! -p "{f2f2ca01-ad02-4a07-9e90-95a2334f3692}" 0xffffffffffffffff 0x4

	@rem Start the tracing session.
	logman start !trace_name!

) else if "%command%"=="stop" (

	@rem Stop and delete the tracing session.
	logman stop !trace_name!
	logman delete !trace_name!

	@rem Delete the tracing directory.
	rmdir /s /q "!trace_path!"

) else (

	goto :usage
)
endlocal
exit /b 0

:usage
echo Usage: ebpf_tracing.cmd command /trace_path path [/trace_name name] [/rundown_period period] [/max_file_size_mb size] [/max_committed_folder_size_mb count] [/max_committed_rundown_state_files count]
echo:
echo Valid parameters:
echo:
echo   <command>                            - (mandatory) Valid values are: [start, stop, periodic]
echo   /trace_path path                     - (mandatory) Path into which the tracing will be located (creates it if it does not exist).
echo   /trace_name name                     - Name of the logman trace (Default: "ebpf_diag")
echo   /rundown_period period               - Period, expressed as (H:mm:ss), for saving and generating a new ETL log, and for generating a WFP state snapshot (Default: 0:35:00).
echo   /max_file_size_mb size               - Maximum size set for an ETL log (Default: 20).
echo   /max_committed_folder_size_mb count  - Maximum overall size for (most recent) .ETL files to keep in the main 'trace_path\committed' (Default: 200)
echo   /max_committed_rundown_state_files count - Number (most recent) of each type of rundown state file to keep in the main 'trace_path\committed' (Default: 1).
echo:
echo Examples (overriding defaults):
echo:
echo        ebpf_tracing.cmd start /trace_name ebpf_diag /trace_path "%SystemRoot%\Logs\eBPF" /rundown_period 0:35:00 /max_file_size_mb 20
echo        ebpf_tracing.cmd stop /trace_name ebpf_diag /trace_path "%SystemRoot%\Logs\eBPF"
echo        ebpf_tracing.cmd periodic /trace_path "%SystemRoot%\Logs\eBPF" /max_file_size_mb 20 /max_committed_folder_size_mb 30 /max_committed_rundown_state_files 1
endlocal
exit /b 1
