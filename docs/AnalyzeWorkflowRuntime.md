# Analyzing Workflow Duration

## Overview
This Markdown file provides instructions for analyzing the duration of a CI/CD pipeline workflow. The goal is to understand the time taken to execute each stage of the workflow, as it directly affects the code velocity.

## Tools Needed
To perform the analysis, you'll need the following tools:
1. [GitHub CLI](https://github.com/cli/cli#installation)
2. [PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell?view=powershell-7.3)

## Steps to Analyze Workflow Duration
1. Obtain the run ID for the workflow from the [actions](https://github.com/Alan-Jowett/ebpf-for-windows/actions) section on GitHub.
   - Select the action you want to analyze.
   - Copy the run ID from the URL (the number that appears after the `/runs/` part of the URL).

2. Execute the following commands in PowerShell:
   ```powershell
   # Replace "<run id from first step>" with the run ID you obtained earlier
   $run_id = <run id from first step>

   # Retrieve JSON data for the jobs of the specified run ID
   $json_text = gh api  -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" /repos/microsoft/ebpf-for-windows/actions/runs/$run_id/jobs

   # Convert JSON data to PowerShell objects
   $jobs = (ConvertFrom-Json $json_text).jobs

   # Select and format the relevant information for each job
   $output = $jobs | Select-Object name, @{
       name="started_at";expression={[datetime]::parse($_.started_at)}
   }, @{
       name="completed_at";expression={[datetime]::parse($_.completed_at)}
   } | Select-Object name, started_at, completed_at, @{
       name="duration";expression={$_.completed_at-$_.started_at}
   }

   # Display the output in a table format
   ft $output
   ```
   This will produce a table showing the name, start time, end time, and duration for each job in the workflow.

## Example Output
Here's an example of the output you can expect from running the above commands:
```
PS D:\ebpf-for-windows> $output | ft

name                                                     started_at           completed_at         duration
----                                                     ----------           ------------         --------
codeql                                                   7/29/2023 5:49:01 PM 7/29/2023 5:49:01 PM 00:00:00
cmake / build (Debug)                                    7/29/2023 5:49:13 PM 7/29/2023 6:10:20 PM 00:21:07
cmake / build (Release)                                  7/29/2023 5:49:11 PM 7/29/2023 6:11:35 PM 00:22:24
...
```

By following these steps, you'll be able to easily analyze and comprehend the duration of each stage in the CI/CD pipeline workflow.