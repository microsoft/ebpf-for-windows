# Updating the Sample Profile Database

## Sample-Driven Profile-Guided Optimization

Sample-Driven Profile-Guided Optimization (SPGO) is a process that utilizes profiling data to guide the optimization of
release builds. SPGO is an iterative process in which sample data is employed to enhance code generation. Updated
samples are then collected from the improved code and utilized to further optimize the code.

SPGO maintains a collection of profiling data in a .spd file (Sample Profile Database) that the linker subsequently
utilizes to perform binary optimization. The current SPD file is generated as part of the build process.

## Collecting SPGO Traces

Note: To perform this process, the test machine must have a
[Performance Counter Monitor](https://www.intel.com/content/www/us/en/developer/articles/tool/performance-counter-monitor.html).
If the target is a virtual machine (VM), enable the processor option as follows:

```powershell
Set-VMProcessor MyVMName -Perfmon @("pmu", "lbr")
```

Follow these steps to collect SPGO traces:

1. Download the [ADK Installer](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install).

2. Append "perf_spt.dll" and "perf_lbr.dll" to
"%ProgramFiles(x86)%\Windows Kits\10\Windows Performance Toolkit\perfcore.ini".

3. Begin gathering traces:

```powershell
xperf.exe -on LOADER+PROC_THREAD+PMC_PROFILE -MinBuffers 4096 -MaxBuffers 4096 -BufferSize 4096 -pmcprofile
BranchInstructionRetired -LastBranch PmcInterrupt -setProfInt BranchInstructionRetired 65537
```

4. Run your scenario.

5. Stop gathering traces:

```powershell
xperf -stop -d workload.etl
```

## Downloading SPGO Tools

Please note that SPGO tools are currently in private preview and restricted to Microsoft internal use. For the most
up-to-date tool location, refer to [spgo](https://aka.ms/spgo).

## Updating the Sample Profile Database

Note: The existing SPD and target binary must be from the same build.

Updating the SPD involves two steps:

1. Aggregate the ETL files into a Sample Profile Trace (.spt file):

```powershell
sptaggregate.exe /etl workload1.etl,workload2.etl,...,workloadN.etl /binary ebpfcore.sys ebpfcore.spt
```

2. Apply the Sample Profile Trace file to the Sample Profile Database:

```powershell
spdconvert.exe /mode:LBR ebpfcore.spd ebpfcore.spt
```

3. Create a pull request (PR) with the updated SPD file. SPD files are stored in the spd_data folder.