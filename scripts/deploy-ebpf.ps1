# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

##
## Initialize parameters
##
$build_directory=".\x64\Debug"
[System.Collections.ArrayList]$built_files=@( "EbpfCore.sys", "EbpfApi.dll", "ebpfnetsh.dll", "ebpfsvc.exe", "NetEbpfExt.sys", "sample_ebpf_ext.sys", "sample_ext_app.exe", "ucrtbased.dll", "MSVCP140D.dll", "VCRUNTIME140D.dll", "VCRUNTIME140_1D.dll", "bpftool.exe", "bindmonitor.o", "bpf.o", "bpf_call.o", "divide_by_zero.o", "droppacket.o", "droppacket_unsafe.o", "map_in_map.o", "reflect_packet.o", "tail_call.o", "tail_call_bad.o", "tail_call_map.o", "test_sample_ebpf.o", "test_utility_helpers.o")
$destination_directory="C:\Temp"
$error.clear()
$vm="Windows 10 dev environment"

##
## Process command-line options
##
foreach ($arg in $args) {
    switch -regex ($arg) {
    { @("-h", "--help") -contains $_ }
        {
            Write-Host @'

OVERVIEW:

Copies eBPF framework files into a temp directory on the local machine or into a VM

    $ deploy-ebpf [-h] [-l] [--vm="..."]

OPTIONS:
    -h, --help     Print this help message.
    -l, --local    Copies files to the local temp directory instead of into a VM
    --vm           Specifies the VM name, which defaults to "Windows 10 dev environment"

'@
            exit 0
        }
    "--vm=*"
        {
            $vm=($arg -split "=")[1];
            break
        }
    { @("-l", "--local") -contains $_ }
        {
            Clear-Variable -name vm
            break
        }
    default
        {
            Write-Error "unknown option: $arg"
            exit 1
        }
    }
}

if ($vm -eq $null) {
   Write-Host "Copying files from `"$build_directory`" to `"$destination_directory`""

   foreach ( $file in $built_files ) {
      $source_path = "$build_directory\$file"
      $destination_path = "$destination_directory\$file"
      Write-Host " $file"
      Copy-Item "$source_path" -Destination "$destination_path"
      if (! $?) {
         exit 1
      }
   }
   Write-Host " install-ebpf.bat"
   Copy-Item ".\scripts\install-ebpf.bat" -Destination "$destination_directory\install-ebpf.bat"
   if (! $?) {
      exit 1
   }
   exit 0
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
if (! $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
   Write-Host "This command must be run as Administrator to deploy files into a VM"
   exit 1
}

Enable-VMIntegrationService -VMName "Windows 10 dev environment" -Name "Guest Service Interface"
if (! $?) {
    exit 1
}

Write-Host "Copying files from `"$build_directory`" to `"$destination_directory`" in VM `"$vm`"..."

foreach ( $file in $built_files ) {
   $source_path = "$build_directory\$file"
   $destination_path = "$destination_directory\$file"
   Write-Host " $file"
   Copy-VMFile "$vm" -SourcePath "$source_path" -DestinationPath "$destination_path" -CreateFullPath -FileSource Host -Force
   if (! $?) {
       exit 1
   }
}

Write-Host " install-ebpf.bat"
Copy-VMFile "$vm" -SourcePath ".\scripts\install-ebpf.bat" -DestinationPath "$destination_directory\install-ebpf.bat" -CreateFullPath -FileSource Host -Force
if (! $?) {
   exit 1
}
