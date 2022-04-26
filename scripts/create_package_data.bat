@echo off

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
copy api_test.exe testing
copy api_test.pdb testing
copy bindmonitor.o testing
copy bindmonitor_ringbuf.o testing
copy bindmonitor_tailcall.o testing
copy bpf.o testing
copy bpf_call.o testing
copy bpftool.pdb testing
copy cgroup_sock_addr.o testing
copy decap_permit_packet.o testing
copy divide_by_zero.o testing
copy droppacket.o testing
copy droppacket_um.dll testing
copy droppacket_um.pdb testing
copy droppacket_unsafe.o testing
copy ebpf_client.exe testing
copy ebpf_client.pdb testing
copy EbpfApi.pdb testing
copy ebpfnetsh.pdb testing
copy encap_reflect_packet.o testing
copy map.o testing
copy map_in_map.o testing
copy map_in_map_v2.o testing
copy map_reuse.o testing
copy map_reuse_2.o testing
copy printk.o testing
copy printk_unsafe.o testing
copy reflect_packet.o testing
copy run_tests.bat testing
copy sample_ebpf_ext.sys testing
copy sample_ext_app.exe testing
copy sample_ext_app.pdb testing
copy tail_call.o testing
copy tail_call_bad.o testing
copy tail_call_map.o testing
copy tail_call_multiple.o testing
copy test_sample_ebpf.o testing
copy test_utility_helpers.o testing
copy unit_tests.exe testing
copy unit_tests.pdb testing

robocopy /E /IS %SOURCE_DIR%\include package_data\include

mkdir package_data\include\libbpf
robocopy /E /IS %SOURCE_DIR%\external\bpftool\libbpf\include\asm package_data\include\libbpf\asm
robocopy /E /IS %SOURCE_DIR%\external\bpftool\libbpf\include\linux package_data\include\libbpf\linux
robocopy /E /IS %SOURCE_DIR%\external\bpftool\libbpf\include\uapi package_data\include\libbpf\uapi

exit /b 0
