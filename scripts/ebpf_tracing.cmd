@rem Copyright (c) Microsoft Corporation
@rem SPDX-License-Identifier: MIT

@echo off
setlocal enabledelayedexpansion

@rem Check the number of arguments and their validity
if "%~1"=="" goto usage
if "%~2"=="" goto usage
set option=%1
set tracePath=%~2
if not exist %tracePath% (
	echo Path %tracePath% does not exist
	goto usage
)

@rem Define the parameters for the tracing session and the periodic cleanup job
set trace_name="ebpf_diag"
set /a max_size_mb=20
set /a max_size_bytes=max_size_mb*1000000
set /a files_max_age_days=7
set /a num_etl_files_to_keep=1

if "%option%"=="periodic" (

    @rem Create a subdirectory for the committed files (if not already present), the external job will zip from there to the final destination.
	set "traceCommittedPath=!tracePath!\committed"
	if not exist "!traceCommittedPath!" (
		mkdir !traceCommittedPath!
	)

    @rem Rundown the WFP state
    pushd "!tracePath!"
    netsh wfp show state
    popd
    set "wfp_state_file=!tracePath!\wfpstate.xml"
	if exist "!wfp_state_file!" (
		@rem If the  file size is under 30Mb, then move it to the 'traceCommittedPath' directory (otherwise it'll be overwritten by the next rundown).
		for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
		set "YYYY=!dt:~0,4!" & set "MM=!dt:~4,2!" & set "DD=!dt:~6,2!"
		set "HH=!dt:~8,2!" & set "Min=!dt:~10,2!" & set "Sec=!dt:~12,2!"
		set "timestamp=!YYYY!!MM!!DD!_!HH!!Min!!Sec!"
		for %%F in ("!wfp_state_file!") do (
			if %%~zF LEQ %max_size_bytes% (
				move /y "!wfp_state_file!" "!traceCommittedPath!\wfpstate_!timestamp!.xml" >nul
			)
		)
	)

	@rem Iterate over all the .etl files in the 'tracePath' directory, sorted in descending order by "date modified",
	@rem and skip the first 'num_etl_files_to_keep' files (i.e., the newest files).
	for /f "skip=%num_etl_files_to_keep% delims=" %%f in ('dir /b /o-d "!tracePath!\*.etl"') do (
		move /y "!tracePath!\%%f" "!traceCommittedPath!" >nul
	)

	@rem Iterate over all the .etl/.xml files in the 'traceCommittedPath' directory, and delete files older than 'files_max_age_days' days.
	forfiles /p "!traceCommittedPath!" /s /m *.etl /d -%files_max_age_days% /c "cmd /c del @path" >nul
	forfiles /p "!traceCommittedPath!" /s /m *.xml /d -%files_max_age_days% /c "cmd /c del @path" >nul

) else if "%option%"=="start" (

	@rem Setup the tracing session
	logman create trace !trace_name! -o !tracePath! -f bincirc -max %max_size_mb% -cnf 0:35:00 -v mmddhhmm

	@rem Define the WFP events to be traced
	logman update trace !trace_name! -p "{00e7ee66-5b24-5c41-22cb-af98f63e2f90}" 0x7 4

	@rem Define the eBPF events to be traced -- TBD - need to get the event masks
	logman update trace !trace_name! -p "{394f321c-5cf4-404c-aa34-4df1428a7f9c}" 0xffffffffffffffff 0x4
	logman update trace !trace_name! -p "{f2f2ca01-ad02-4a07-9e90-95a2334f3692}" 0xffffffffffffffff 0x4

	@rem Start the tracing session
	logman start !trace_name!

) else if "%option%"=="stop" (

	logman stop !trace_name!
	logman delete !trace_name!
	rmdir /s /q !tracePath!

) else (

	goto usage
)
goto done

:usage
    echo Usage: ebpf_tracing.cmd ^<start, stop, periodic^> ^<tracePath^>
    echo Examples:
    echo        ebpf_tracing.cmd start ^"C:\My Trace Path^"
    echo        ebpf_tracing.cmd stop ^"C:\My Trace Path^"
    echo        ebpf_tracing.cmd periodic ^"C:\My Trace Path^"
:done