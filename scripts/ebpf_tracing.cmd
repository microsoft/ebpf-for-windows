@rem Copyright (c) Microsoft Corporation
@rem SPDX-License-Identifier: MIT

@rem Script behavior:
@rem - When called with 'start', it will:
@rem 	- Setup the logman session named as defined in 'trace_name', capping circular-log file size to 'max_size_mb', and generating every 'logman_period'.
@rem    - Configure the WFP/eBPF events to be monitored
@rem    - Start the session within the given 'tracePath' directory.
@rem - When called with 'stop', it will:
@rem 	- Stop then delete the logman session, and finally deletes the 'tracePath' directory.
@rem - When called with 'periodic', it will:
@rem 	- Run 'netsh wfp show state' into the 'tracePath' directory, and if the file is under 'max_size_mb', it will move it into the '.\committed' subfolder, adding a timestamp to its name.
@rem 	- Iterate over all the '.etl' files in the 'tracePath' directory, sorted in descending order by "date modified", skip the first 'num_etl_files_to_keep' files and move the others into the '.\committed' subfolder.
@rem 	- Iterate over all the '.etl' and '.xml' files in the '.\committed' subfolder and delete files older than 'files_max_age_days' days.

@echo off
setlocal enabledelayedexpansion

@rem Check the number of arguments and their validity.
if "%~1"=="" goto usage
if "%~2"=="" goto usage
set option=%1
set tracePath=%~2
if not exist "!tracePath!" (
	mkdir "!tracePath!"
)

@rem Define the parameters for the tracing session and the periodic cleanup job.
set trace_name="ebpf_diag"
set logman_period=0:35:00
set /a max_size_mb=20
set /a max_committed_files=41

@rem Internal constants
set /a num_etl_files_to_keep=1
set /a max_size_bytes=max_size_mb*1000000

if "%option%"=="periodic" (

    @rem Create a subdirectory for the committed files (if not already present).
	set "traceCommittedPath=!tracePath!\committed"
	if not exist "!traceCommittedPath!" (
		mkdir "!traceCommittedPath!"
	)

    @rem Run down the WFP state.
    pushd "!tracePath!"
    netsh wfp show state
    popd
    set "wfp_state_file=!tracePath!\wfpstate.xml"
    set "wfp_state_file_zip=!tracePath!\wfpstate.zip"
	makecab "!wfp_state_file!" "!wfp_state_file_zip!"
	if exist "!wfp_state_file_zip!" (
		del "!wfp_state_file!"
		@rem If the file size is less or equal than 'max_size_mb', then move it to the 'traceCommittedPath' directory (otherwise it'll just be overwritten by the next run down).
		for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
		set "YYYY=!dt:~0,4!" & set "MM=!dt:~4,2!" & set "DD=!dt:~6,2!"
		set "HH=!dt:~8,2!" & set "Min=!dt:~10,2!" & set "Sec=!dt:~12,2!"
		set "timestamp=!YYYY!!MM!!DD!_!HH!!Min!!Sec!"
		for %%F in ("!wfp_state_file_zip!") do (
			if %%~zF LEQ %max_size_bytes% (
				move /y "!wfp_state_file_zip!" "!traceCommittedPath!\wfpstate_!timestamp!.zip" >nul
			)
		)
	)

	@rem Iterate over all the .etl files in the 'tracePath' directory, sorted in descending order by name,
	@rem and skip the first 'num_etl_files_to_keep' files (i.e., the newest 'num_etl_files_to_keep' files).
	for /f "skip=%num_etl_files_to_keep% delims=" %%f in ('dir /b /o-n "!tracePath!\*.etl"') do (
		move /y "!tracePath!\%%f" "!traceCommittedPath!" >nul
	)

	@rem Iterate over all the files in the 'traceCommittedPath' directory, and delete files older files than `max_committed_files`.
	for /f "skip=%max_committed_files% delims=" %%f in ('dir /b /o-d "!traceCommittedPath!\*.*"') do ( del "!traceCommittedPath!\%%f" )

) else if "%option%"=="start" (

	@rem Set up the tracing session.
	logman create trace !trace_name! -o "!tracePath!\ebpf_trace" -f bincirc -max %max_size_mb% -cnf %logman_period% -v mmddhhmm

	@rem Define the WFP events to be traced.
	logman update trace !trace_name! -p "{00e7ee66-5b24-5c41-22cb-af98f63e2f90}" 0x7 0x4

	@rem Define the eBPF events to be traced.
	logman update trace !trace_name! -p "{394f321c-5cf4-404c-aa34-4df1428a7f9c}" 0xffffffffffffffff 0x4
	logman update trace !trace_name! -p "{f2f2ca01-ad02-4a07-9e90-95a2334f3692}" 0xffffffffffffffff 0x4

	@rem Start the tracing session.
	logman start !trace_name!

) else if "%option%"=="stop" (

	logman stop !trace_name!
	logman delete !trace_name!
	rmdir /s /q "!tracePath!"

) else (

	goto usage
)
goto done

:usage
    echo Usage: ebpf_tracing.cmd ^<start, stop, periodic^> ^<tracePath^>
    echo Examples:
    echo        ebpf_tracing.cmd start "C:\_ebpf\logs"
    echo        ebpf_tracing.cmd stop "C:\_ebpf\logs"
    echo        ebpf_tracing.cmd periodic "C:\_ebpf\logs"
:done