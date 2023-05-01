
# 1.0. ebpf_stress_test_km.exe (test sources in .\km\)

This test application provides tests that are meant to be run against the real (kernel mode) eBPF sub-system. This
application assumes that the requisite kernel drivers (`ebpfcore.sys, netebpfext.sys`) are loaded and running.

_This application requires the `ebpfapi.dll` to be present in the DLL load path or in the same directory as this
binary._

*Test specific command-line options (all optional, defaults used if not specified):*
- `-tt=NNNN`: Number of test threads to create.
- `-td=NNNN`: Test run-time in minutes.
- `-vo=<true|false>`: Enable verbose output (default: false).
- `-er=<true|false>`: Restart extension.
- `-erd=NNNN`: Extension restart delay (in milliseconds).

_This is a 'Catch2' test application and hence if no test name is provided on the command line, all tests are run in a sequential manner._


This application provides the following tests:

## 1.1. jit_load_attach_detach_unload_random_v4_test


 This test creates threads to randomly `load`, `attach`, `detach` and `close` JIT'ed ebpf program(s). (Details in code comments)

Sample commandline invocations:

### 1.1.1. `ebpf_stress_test_km jit_load_attach_detach_unload_random_v4_test`
- thread set size, test run-time: uses default values
- test trace output: none
- extension restart: disabled


### 1.1.2. `ebpf_stress_test_km -tt=32 -td=5 -er=true jit_load_attach_detach_unload_random_v4_test`
- thread set size: 32
- test run-time: 5 minutes.
- test trace output: none
- extension restart: enabled
- extension restart delay: default.


## 1.2. native_load_attach_detach_unload_random_v4_test

This test is identical to `jit_load_attach_detach_unload_random_v4_test` except this test loads a native ebpf
program (.sys file). The command line options and their interpretation is identical as well.

Sample command line invocations:

### 1.2.1. `ebpf_stress_test_km native_load_attach_detach_unload_random_v4_test`
- use defaults.

### 1.2.2. `ebpf_stress_test_km -tt=32 -td=5 -er=true native_load_attach_detach_unload_random_v4_test`


## 1.3. native_unique_load_attach_detach_unload_random_v4_test

This test extends the ```native_load_attach_detach_unload_random_v4_test``` to use a unique native ebpf per thread.
(The test makes unique copies of the same base native program at runtime). All other behavior is identical.

### 1.3.1. `ebpf_stress_test_km -tt=32 -td=5 -er=true native_unique_load_attach_detach_unload_random_v4_test`


## 1.4. native_invoke_program_restart_extension_v4_test
This test loads 2 specific native eBPF programs in a dedicated thread and then continues to ensure their invocation
while continuosly restarting the netebpfext extension.

This test ignores the `-tt`, `-er` and `-erd` commandline parameters.

Sample command line invocations:

### 1.4.1. `ebpf_stress_test_km native_invoke_program_restart_extension_v4_test`
- uses default run-time value.

### 1.4.2. `ebpf_stress_test_km -td=15 -vo=true native_invoke_program_restart_extension_v4_test`
- runs test for 15 minutes, verbose test trace output enabled.


# 2.0. ebpf_stress_test_um.exe (test sources in .\um\)

This test application provides tests that are meant to be run against the user mode 'mock' of the eBPF sub-system. This
application does not require the presence of the eBPF kernel drivers and can be run on the dev machine as well.

_This application requires the ```ebpfapi.dll``` to be present in the DLL load path or in the same directory as this
binary._


Test specific command-line options (all optional, defaults used if not specified):

- `-tp="<program1[,program2]>`: programs to load.
- `-tt=NNNN`: Number of test threads to create.
- `-td=NNNN`: Test run-time in minutes.
- `-vo=<true|false>`: Enable verbose output (default: false).
- `-er=<true|false>`: Restart extension.
- `-erd=NNNN`: Extension restart delay (in milliseconds).

This application provides the following tests:

## 2.1. load_attach_detach_unload_sequential_test
This test loads, attaches, detaches and closes (in a sequential manner) the specified JIT'ed programs in their
respective thread sets. The test currently supprorts the `droppacket` and `bindmonitor_tailcall` programs only.
Either one or both can be specified, else `droppacket` is used by default.

Sample command line invocations:

### 2.1.1. `ebpf_stress_test_um load_attach_detach_unload_sequential_test`
- uses default run-time values for threads and run-time, loads `droppacket`

### 2.1.2. `ebpf_stress_test_km -tp="droppacket, bindmonitor_tailcall" -tt=32 -td=30 load_attach_detach_unload_sequential_test`
- uses `droppacket` and `bindmonitor_tailcall` programs
- creates a 32 thread set.
- runs the test for 30 minutes.
