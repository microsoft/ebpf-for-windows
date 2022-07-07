rem Copyright (c) Microsoft Corporation
rem SPDX-License-Identifier: MIT
@echo off

set SOURCE_DIR=%CD%
pushd %1
dir

mkdir package_data
copy bpftool.exe package_data
copy bpf2c.exe package_data
copy ebpfsvc.exe package_data
copy EbpfApi.dll package_data
copy ebpfnetsh.dll package_data
copy ebpf-all.guid package_data
copy ebpf-printk.guid package_data
copy ebpfforwindows.wprp package_data
copy %SOURCE_DIR%\LICENSE.txt package_data

mkdir package_data\lib
copy EbpfApi.lib package_data\lib

mkdir package_data\drivers
copy NetEbpfExt\NetEbpfExt.sys package_data\drivers
copy NetEbpfExt\NetEbpfExt.inf package_data\drivers

copy EbpfCore\EbpfCore.sys package_data\drivers
copy EbpfCore\EbpfCore.inf package_data\drivers

mkdir package_data\scripts
copy %SOURCE_DIR%\scripts\install-ebpf.bat package_data\scripts
copy %SOURCE_DIR%\scripts\uninstall-ebpf.bat package_data\scripts

mkdir package_data\testing
copy api_test.exe package_data\testing
copy api_test.pdb package_data\testing
copy bindmonitor.o package_data\testing
copy bindmonitor_ringbuf.o package_data\testing
copy bindmonitor_tailcall.o package_data\testing
copy bpf.o package_data\testing
copy bpf_call.o package_data\testing
copy bpftool.pdb package_data\testing
copy cgroup_sock_addr.o package_data\testing
copy decap_permit_packet.o package_data\testing
copy divide_by_zero.o package_data\testing
copy droppacket.o package_data\testing
copy droppacket_um.dll package_data\testing
copy droppacket_um.pdb package_data\testing
copy droppacket_unsafe.o package_data\testing
copy ebpf_client.exe package_data\testing
copy ebpf_client.pdb package_data\testing
copy EbpfApi.pdb package_data\testing
copy ebpfnetsh.pdb package_data\testing
copy encap_reflect_packet.o package_data\testing
copy map.o package_data\testing
copy map_in_map.o package_data\testing
copy map_in_map_v2.o package_data\testing
copy map_reuse.o package_data\testing
copy map_reuse_2.o package_data\testing
copy pidtgid.o package_data\testing
copy printk.o package_data\testing
copy printk_unsafe.o package_data\testing
copy reflect_packet.o package_data\testing
copy run_tests.bat package_data\testing
copy sample_ebpf_ext.sys package_data\testing
copy sample_ext_app.exe package_data\testing
copy sample_ext_app.pdb package_data\testing
copy tail_call.o package_data\testing
copy tail_call_bad.o package_data\testing
copy tail_call_map.o package_data\testing
copy tail_call_multiple.o package_data\testing
copy test_sample_ebpf.o package_data\testing
copy test_utility_helpers.o package_data\testing
copy unit_tests.exe package_data\testing
copy unit_tests.pdb package_data\testing

robocopy /E /IS %SOURCE_DIR%\include package_data\include

mkdir package_data\include\libbpf
robocopy /E /IS %SOURCE_DIR%\external\bpftool\libbpf\include\asm package_data\include\libbpf\asm
robocopy /E /IS %SOURCE_DIR%\external\bpftool\libbpf\include\linux package_data\include\libbpf\linux
robocopy /E /IS %SOURCE_DIR%\external\bpftool\libbpf\include\uapi package_data\include\libbpf\uapi

popd

exit /b 0
