
# 1.0. ebpf_stress_test_km.exe (test sources in .\km\)

This test application provides tests that are meant to be run against the real (kernel mode) eBPF sub-system. This
application assumes that the requisite kernel drivers (`ebpfcore.sys, netebpfext.sys`) are loaded and running.

_This application requires the `ebpfapi.dll` to be present in the DLL load path or in the same directory as this
binary._

*Test specific command-line options (all optional, defaults used if not specified):*
- `-tt=NNNN`: Number of test threads to create (Default: hard-coded).
- `-td=NNNN`: Test duration in minutes (Default: hard-coded).
- `-vo=<true|false>`: Enable verbose output (Default: false).
- `-er=<true|false>`: Restart extension (Default: false, where supported).
- `-erd=NNNN`: Extension restart delay in milliseconds (Default: hard-coded).

_This is a 'Catch2' test application and hence if no test name is provided on the command line, all tests are run in a
sequential manner._


This application provides the following tests:

## 1.1. jit_load_attach_detach_unload_random_v4_test


This test creates threads to randomly `load`, `attach`, `detach` and `close` JIT'ed ebpf program(s).
_(Details in code comments.)_

Sample commandline invocations:

### 1.1.1. `ebpf_stress_test_km jit_load_attach_detach_unload_random_v4_test`
- Uses default values for all supported options.


### 1.1.2. `ebpf_stress_test_km -tt=32 -td=5 -er=true jit_load_attach_detach_unload_random_v4_test`
- Creates 32 test threads.
- Runs test for 5 minutes.
- Extension restart is enabled.


## 1.2. native_load_attach_detach_unload_random_v4_test

This test is identical to `jit_load_attach_detach_unload_random_v4_test` except this test loads a native ebpf
program (.sys file). The command line options and their interpretation is identical as well.

Sample command line invocations:

### 1.2.1. `ebpf_stress_test_km native_load_attach_detach_unload_random_v4_test`
- Uses default values for all supported options.

### 1.2.2. `ebpf_stress_test_km -tt=32 -td=5 -er=true native_load_attach_detach_unload_random_v4_test`
- Creates 32 test threads.
- Runs test for 5 minutes.
- Extension restart is enabled.


## 1.3. native_unique_load_attach_detach_unload_random_v4_test

This test extends the ```native_load_attach_detach_unload_random_v4_test``` to use a unique native ebpf per thread.
(The test makes unique copies of the same base native program at runtime). All other behavior is identical.

### 1.3.1. `ebpf_stress_test_km -tt=32 -td=5 -er=true native_unique_load_attach_detach_unload_random_v4_test`
- Creates 32 test threads.
- Runs test for 5 minutes.
- Extension restart enabled.


## 1.4. native_invoke_v4_v6_programs_restart_extension_test
This test loads 2 specific native eBPF programs, each in a dedicated thread and then continues to ensure their
invocation while continuously restarting the netebpfext extension.

This test ignores the `-tt`, `-er` and `-erd` commandline parameters.

Sample command line invocations:

### 1.4.1. `ebpf_stress_test_km native_invoke_v4_v6_programs_restart_extension_test`
- Uses default values for all supported options.

### 1.4.2. `ebpf_stress_test_km -td=15 -vo=true native_invoke_v4_v6_programs_restart_extension_test`
- Runs test for 15 minutes.
- Verbose test trace output enabled.


## 1.5. sockaddr_invoke_program_test
This test first loads a specific native eBPF program. It then creates the specified # of threads where each thread
attempts a TCP 'connect' to the remote endpoint `[::1]:<target_port + thread_context.thread_index>` continuously in a
loop.  The test set up ensures that the `thread_index` passed in each `thread_context` is unique to that thread.

This causes the invocation of the in-kernel eBPF program which returns some (arbitrary) decision based on the end-point
port number.

This test can be run with or without the extension restart option.

Sample command line invocations:

### 1.5.1. `ebpf_stress_test_km sockaddr_invoke_program_test`
- Uses default values for all supported options.

### 1.5.2. `ebpf_stress_test_km -tt=32 -td=15 -vo=true -er=true -erd=250 sockaddr_invoke_program_test`
- Creates 32 test threads.
- Runs test for 15 minutes.
- Verbose test trace output enabled.
- Extension restart enabled.
- Delay of 250 ms between successive extension restarts.

## 1.6. bindmonitor_tail_call_invoke_program_test
This test first loads a specific native eBPF program. It then loads all the MAX_TAIL_CALL_CNT tail call programs and updates the program array map. It then creates the specified number of threads where each thread attempts a TCP 'bind' to the same port continuously in a loop. The test setup guarantees that the `thread_index` passed in each `thread_context` is unique to that thread, so that each thread gets a unique port (base_port + thread_index).

This causes the invocation of the in-kernel eBPF tail call programs to be executed in sequence. The last tail call program returns a PERMIT verdict.

This test can be run with or without the extension restart option.

Sample command line invocations:

### 1.6.1. `ebpf_stress_test_km bindmonitor_tail_call_invoke_program_test`
- Uses default values for all supported options.

### 1.6.2. `ebpf_stress_test_km -tt=32 -td=15 -vo=true -er=true -erd=250 bindmonitor_tail_call_invoke_program_test`
- Creates 32 test threads.
- Runs test for 15 minutes.
- Verbose test trace output enabled.
- Extension restart enabled.
- Delay of 250 ms between successive extension restarts.

# 2.0. ebpf_stress_test_um.exe (test sources in .\um\)

This test application provides tests that are meant to be run against the user mode 'mock' of the eBPF sub-system. This
application does not require the presence of the eBPF kernel drivers and can be run on the dev machine as well.

_This application requires the `ebpfapi.dll` to be present in the DLL load path or in the same directory as this
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
respective thread sets. The test currently supprorts the `droppacket` and `bindmonitor_tailcall` programs only. Either
one or both can be specified, else `droppacket` is used by default.

Sample command line invocations:

### 2.1.1. `ebpf_stress_test_um load_attach_detach_unload_sequential_test`
- Uses default values for all supported options.

### 2.1.2. `ebpf_stress_test_km -tp="droppacket, bindmonitor_tailcall" -tt=32 -td=30 load_attach_detach_unload_sequential_test`
- Uses `droppacket` and `bindmonitor_tailcall` programs.
- creates 32 test threads.
- Runs the test for 30 minutes.

## 1.7. ebpfcore_restart_with_open_handles_test

This test validates the eBPF core driver's restart behavior under different scenarios involving open handles and pinned objects. The test ensures that:

1. **ebpfcore cannot be stopped while child processes hold open handles** - Validates that the driver correctly prevents unload when user-mode processes have active references.
2. **ebpfcore can be stopped after processes exit** - Confirms proper cleanup and driver unload when all handles are released.
3. **ebpfcore behavior with pinned objects** - Tests and documents the driver's behavior when objects are pinned in the kernel namespace but no process holds handles.
4. **ebpfcore restarts and operates normally** - Verifies basic functionality after a driver restart cycle.

This test uses a helper process (`ebpf_restart_test_helper.exe`) that operates in three modes:
- **open-handles**: Creates eBPF objects and keeps handles open, blocking until signaled by the controller
- **pin-objects**: Creates objects, pins them to the kernel namespace, releases handles, and exits
- **unpin-objects**: Unpins previously pinned objects and exits

The test coordinates with the helper process using named events for IPC synchronization.

### 1.7.1. `ebpf_stress_test_km ebpfcore_restart_with_open_handles_test`
- Runs the complete driver restart stress test sequence
- Tests all scenarios: open handles, pinned objects, and restart verification

**Note**: This test may not fully stop and restart the driver if other processes (such as the eBPF service) are holding references to ebpfcore. This is expected behavior and the test will log appropriate messages in such cases.
