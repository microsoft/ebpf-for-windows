# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

##
## Initialize parameters
##
$build_directory=".\x64\Debug"

# The following files should be installed on all platforms.
[System.Collections.ArrayList]$runtime_files=@(
    "bpftool.exe",
    "ebpf-all.guid",
    "ebpf-printk.guid",
    "EbpfApi.dll",
    "EbpfCore.sys",
    "ebpfforwindows.wprp",
    "ebpfnetsh.dll",
    "ebpfsvc.exe",
    "MSVCP140D.dll",
    "NetEbpfExt.sys",
    "ucrtbased.dll",
    "VCRUNTIME140_1D.dll",
    "VCRUNTIME140D.dll")

# The following files are only needed for testing and debugging.
[System.Collections.ArrayList]$test_files=@(
    "api_test.exe",
    "api_test.pdb",
    "bindmonitor.o",
    "bindmonitor_km.sys",
    "bindmonitor_ringbuf.o",
    "bindmonitor_ringbuf_um.dll",
    "bindmonitor_ringbuf_um.dll_um.pdb",
    "bindmonitor_ringbuf_um.dll_um.pdb.sys",
    "bindmonitor_tailcall.o",
    "bindmonitor_tailcall_km.sys",
    "bindmonitor_tailcall_um.dll",
    "bindmonitor_tailcall_um.dll_um.pdb",
    "bindmonitor_tailcall_um.dll_um.pdb.sys",
    "bindmonitor_um.dll",
    "bindmonitor_um.dll_um.pdb",
    "bindmonitor_um.dll_um.pdb.sys",
    "bindmonitor_um.pdb",
    "bpf.o",
    "bpf_call.o",
    "bpf_call_um.dll",
    "bpf_call_um.dll_um.pdb",
    "bpf_call_um.dll_um.pdb.sys",
    "bpf_um.dll",
    "bpf_um.dll_um.pdb",
    "bpf_um.dll_um.pdb.sys",
    "bpftool.pdb",
    "bpftool_tests.exe",
    "bpftool_tests.pdb",
    "cgroup_sock_addr.o",
    "cgroup_sock_addr_um.dll",
    "cgroup_sock_addr_um.dll_um.pdb",
    "cgroup_sock_addr_um.dll_um.pdb.sys",
    "decap_permit_packet.o",
    "decap_permit_packet_um.dll",
    "decap_permit_packet_um.dll_um.pdb",
    "decap_permit_packet_um.dll_um.pdb.sys",
    "divide_by_zero.o",
    "divide_by_zero_um.dll",
    "divide_by_zero_um.dll_um.pdb",
    "divide_by_zero_um.dll_um.pdb.sys",
    "droppacket.o",
    "droppacket_km.sys",
    "droppacket_um.dll",
    "droppacket_um.dll_um.pdb",
    "droppacket_um.dll_um.pdb.sys",
    "droppacket_unsafe.o",
    "ebpf_client.exe",
    "ebpf_client.pdb",
    "EbpfApi.pdb",
    "ebpfnetsh.pdb",
    "encap_reflect_packet.o",
    "encap_reflect_packet_um.dll",
    "encap_reflect_packet_um.dll_um.pdb",
    "encap_reflect_packet_um.dll_um.pdb.sys",
    "map.o",
    "map_in_map.o",
    "map_in_map_um.dll",
    "map_in_map_um.dll_um.pdb",
    "map_in_map_um.dll_um.pdb.sys",
    "map_in_map_v2.o",
    "map_in_map_v2_um.dll",
    "map_in_map_v2_um.dll_um.pdb",
    "map_in_map_v2_um.dll_um.pdb.sys",
    "map_reuse.o",
    "map_reuse_2.o",
    "map_reuse_2_um.dll",
    "map_reuse_2_um.dll_um.pdb",
    "map_reuse_2_um.dll_um.pdb.sys",
    "map_reuse_um.dll",
    "map_reuse_um.dll_um.pdb",
    "map_reuse_um.dll_um.pdb.sys",
    "map_um.dll",
    "map_um.dll_um.pdb",
    "map_um.dll_um.pdb.sys",
    "printk.o",
    "printk_legacy.o",
    "printk_legacy_um.dll",
    "printk_legacy_um.dll_um.pdb",
    "printk_legacy_um.dll_um.pdb.sys",
    "printk_um.dll",
    "printk_um.dll_um.pdb",
    "printk_um.dll_um.pdb.sys",
    "printk_unsafe.o",
    "reflect_packet.o",
    "reflect_packet_um.dll",
    "reflect_packet_um.dll_um.pdb",
    "reflect_packet_um.dll_um.pdb.sys",
    "run_tests.bat",
    "sample_ebpf_ext.sys",
    "sample_ext_app.exe",
    "sample_ext_app.pdb",
    "socket_tests.exe",
    "socket_tests.pdb",
    "sockops.o",
    "sockops_um.dll",
    "sockops_um.dll_um.pdb",
    "sockops_um.dll_um.pdb.sys",
    "tail_call.o",
    "tail_call_bad.o",
    "tail_call_bad_um.dll",
    "tail_call_bad_um.dll_um.pdb",
    "tail_call_bad_um.dll_um.pdb.sys",
    "tail_call_map.o",
    "tail_call_map_um.dll",
    "tail_call_map_um.dll_um.pdb",
    "tail_call_map_um.dll_um.pdb.sys",
    "tail_call_multiple.o",
    "tail_call_multiple_um.dll",
    "tail_call_multiple_um.dll_um.pdb",
    "tail_call_multiple_um.dll_um.pdb.sys",
    "tail_call_um.dll",
    "tail_call_um.dll_um.pdb",
    "tail_call_um.dll_um.pdb.sys",
    "test_sample_ebpf.o",
    "test_sample_ebpf_um.dll",
    "test_sample_ebpf_um.dll_um.pdb",
    "test_sample_ebpf_um.dll_um.pdb.sys",
    "test_utility_helpers.o",
    "test_utility_helpers_um.dll",
    "test_utility_helpers_um.dll_um.pdb",
    "test_utility_helpers_um.dll_um.pdb.sys",
    "unit_tests.exe",
    "unit_tests.pdb")

[System.Collections.ArrayList]$built_files= $runtime_files
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

    $ deploy-ebpf [-h] [-l] [-t] [--vm="..."]

OPTIONS:
    -h, --help     Print this help message.
    -l, --local    Copies files to the local temp directory instead of into a VM
    -t, --test     Includes files needed only for testing and debugging
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
    { @("-t", "--test") -contains $_ }
        {
            $built_files= $runtime_files + $test_files
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
