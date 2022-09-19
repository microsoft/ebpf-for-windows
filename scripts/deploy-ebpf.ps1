# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

##
## Initialize parameters
##
$source_directory="."

# The following files should be installed on all platforms.
[System.Collections.ArrayList]$built_runtime_files=@(
    "bpftool.exe",
    "ebpf-all.guid",
    "ebpf-printk.guid",
    "EbpfApi.dll",
    "EbpfCore.sys",
    "ebpfforwindows.wprp",
    "ebpfnetsh.dll",
    "ebpfsvc.exe",
    "export_program_info.exe",
    "MSVCP140D.dll",
    "NetEbpfExt.sys",
    "net-ebpf-ext.guid",
    "ucrtbased.dll",
    "VCRUNTIME140_1D.dll",
    "VCRUNTIME140D.dll")

[System.Collections.ArrayList]$source_msi_files=@(
    "ebpf-for-windows-0.4.0.msi")

[System.Collections.ArrayList]$source_script_files=@(
    "scripts\common.psm1",
    "scripts\install_ebpf.psm1",
    "scripts\setup-ebpf.ps1")

# The following files are only needed for testing and debugging.
[System.Collections.ArrayList]$built_test_files=@(
    "api_test.exe",
    "api_test.pdb",
    "bindmonitor.o",
    "bindmonitor_ringbuf.o",
    "bindmonitor_ringbuf_um.dll",
    "bindmonitor_ringbuf_um.pdb",
    "bindmonitor_ringbuf.sys",
    "bindmonitor_tailcall.o",
    "bindmonitor_tailcall_um.dll",
    "bindmonitor_tailcall_um.pdb",
    "bindmonitor_tailcall.sys",
    "bindmonitor_um.dll",
    "bindmonitor_um.pdb",
    "bindmonitor.sys",
    "bpf.o",
    "bpf_call.o",
    "bpf_call_um.dll",
    "bpf_call_um.pdb",
    "bpf_call.sys",
    "bpf_um.dll",
    "bpf_um.pdb",
    "bpf.sys",
    "bpftool.pdb",
    "bpftool_tests.exe",
    "bpftool_tests.pdb",
    "cgroup_sock_addr.o",
    "cgroup_sock_addr_um.dll",
    "cgroup_sock_addr_um.pdb",
    "cgroup_sock_addr.sys",
    "decap_permit_packet.o",
    "decap_permit_packet_um.dll",
    "decap_permit_packet_um.pdb",
    "decap_permit_packet.sys",
    "divide_by_zero.o",
    "divide_by_zero_um.dll",
    "divide_by_zero_um.pdb",
    "divide_by_zero.sys",
    "droppacket.o",
    "droppacket_um.dll",
    "droppacket_um.pdb",
    "droppacket.sys",
    "droppacket_unsafe.o",
    "EbpfApi.pdb",
    "ebpfnetsh.pdb",
    "ebpfsvc.pdb",
    "encap_reflect_packet.o",
    "encap_reflect_packet_um.dll",
    "encap_reflect_packet_um.pdb",
    "encap_reflect_packet.sys",
    "export_program_info.pdb",
    "map.o",
    "map_in_map.o",
    "map_in_map_um.dll",
    "map_in_map_um.pdb",
    "map_in_map.sys",
    "map_in_map_v2.o",
    "map_in_map_v2_um.dll",
    "map_in_map_v2_um.pdb",
    "map_in_map_v2.sys",
    "map_reuse.o",
    "map_reuse_2.o",
    "map_reuse_2_um.dll",
    "map_reuse_2_um.pdb",
    "map_reuse_2.sys",
    "map_reuse_um.dll",
    "map_reuse_um.pdb",
    "map_reuse.sys",
    "map_um.dll",
    "map_um.pdb",
    "map.sys",
    "pidtgid.o",
    "pidtgid.sys",
    "port_quota.exe",
    "port_quota.pdb",
    "printk.o",
    "printk_legacy.o",
    "printk_legacy_um.dll",
    "printk_legacy_um.pdb",
    "printk_legacy.sys",
    "printk_um.dll",
    "printk_um.pdb",
    "printk.sys",
    "printk_unsafe.o",
    "reflect_packet.o",
    "reflect_packet_um.dll",
    "reflect_packet_um.pdb",
    "reflect_packet.sys",
    "run_tests.bat",
    "sample_ebpf_ext.sys",
    "sample_ext_app.exe",
    "sample_ext_app.pdb",
    "socket_tests.exe",
    "socket_tests.pdb",
    "sockops.o",
    "sockops_um.dll",
    "sockops_um.pdb",
    "sockops.sys",
    "tail_call.o",
    "tail_call_bad.o",
    "tail_call_bad_um.dll",
    "tail_call_bad_um.pdb",
    "tail_call_bad.sys",
    "tail_call_map.o",
    "tail_call_map_um.dll",
    "tail_call_map_um.pdb",
    "tail_call_map.sys",
    "tail_call_multiple.o",
    "tail_call_multiple_um.dll",
    "tail_call_multiple_um.pdb",
    "tail_call_multiple.sys",
    "tail_call_um.dll",
    "tail_call_um.pdb",
    "tail_call.sys",
    "test_sample_ebpf.o",
    "test_sample_ebpf_um.dll",
    "test_sample_ebpf_um.pdb",
    "test_sample_ebpf.sys",
    "test_utility_helpers.o",
    "test_utility_helpers_um.dll",
    "test_utility_helpers_um.pdb",
    "test_utility_helpers.sys",
    "unit_tests.exe",
    "unit_tests.pdb",
    "xdp_tests.exe",
    "xdp_tests.pdb")

[System.Collections.ArrayList]$built_files= $built_runtime_files
[System.Collections.ArrayList]$source_files= $source_script_files
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

    $ deploy-ebpf [--dir="..."] [-h] [-l] [-m] [-t] [--vm="..."]

OPTIONS:
    --dir          Specifies the source directory path, which defaults to "."
    -h, --help     Print this help message.
    -m, --msi      Copies MSI instead of individual files
    -l, --local    Copies files to the local temp directory instead of into a VM
    -t, --test     Includes files needed only for testing and debugging
    --vm           Specifies the VM name, which defaults to "Windows 10 dev environment"

'@
            exit 0
        }
    "--dir=*"
        {
            $source_directory=($arg -split "=")[1];
            break
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
    { @("-m", "--msi") -contains $_ }
        {
            $built_files= @()
            $source_directory= "build\setup"
            $source_files= $source_msi_files
            break
        }
    { @("-t", "--test") -contains $_ }
        {
            $built_files= $built_runtime_files + $built_test_files
            break
        }
    default
        {
            Write-Error "unknown option: $arg"
            exit 1
        }
    }
}

$build_directory="$source_directory\x64\Debug"
if ($vm -eq $null) {
   Write-Host "Copying files from `"$build_directory`" to `"$destination_directory`""

   foreach ( $file in $built_files ) {
      $source_path = "$build_directory\$file"
      $destination_path = "$destination_directory\$file"
      Write-Host " $source_path -> $destination_path"
      Copy-Item "$source_path" -Destination "$destination_path"
      if (! $?) {
         exit 1
      }
   }

   Write-Host "Copying files from `"$source_directory`" to `"$destination_directory`""
   foreach ( $file in $source_files ) {
      $source_path = "$source_directory\$file"
      $destination_path = "$destination_directory\$file"
      Write-Host " $source_path -> $destination_path"
      Copy-Item "$source_path" -Destination "$destination_path"
      if (! $?) {
         exit 1
      }
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
   Write-Host " $source_path -> $destination_path"
   Copy-VMFile "$vm" -SourcePath "$source_path" -DestinationPath "$destination_path" -CreateFullPath -FileSource Host -Force
   if (! $?) {
       exit 1
   }
}

Write-Host "Copying files from `"$source_directory`" to `"$destination_directory`" in VM `"$vm`"..."

foreach ( $file in $source_files ) {
   $source_path = "$source_directory\$file"
   $destination_path = "$destination_directory\$file"
   Write-Host " $source_path -> $destination_path"
   Copy-VMFile "$vm" -SourcePath "$source_path" -DestinationPath "$destination_path" -CreateFullPath -FileSource Host -Force
   if (! $?) {
       exit 1
   }
}
