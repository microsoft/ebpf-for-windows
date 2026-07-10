
# 1.0. ebpf_stress_tests_km.exe (test sources in .\km\)

This test application provides tests that are meant to be run against the real (kernel mode) eBPF sub-system. This
application assumes that the requisite kernel drivers (`ebpfcore.sys, netebpfext.sys`) are loaded and running.

_This application requires the `ebpfapi.dll` to be present in the DLL load path or in the same directory as this
binary._

*Test specific command-line options (all optional, defaults used if not specified):*
- `-tt=NNNN`: Number of test threads to create (Default: test-specific; CPU count for race test).
- `-td=NNNN`: Test duration in minutes (Default: test-specific; 10 for native invoke tests, 1 for race test).
- `-ad=NNNN`: Delay in milliseconds between detach and attach operations (Default: 10).
- `-vo=<true|false>`: Enable verbose output (Default: false).
- `-er=<true|false>`: Restart extension (Default: false, where supported).
- `-erd=NNNN`: Extension restart delay in milliseconds (Default: hard-coded).

_This is a 'Catch2' test application and hence if no test name is provided on the command line, all tests are run in a
sequential manner._


This application provides the following tests:

## 1.1. sockaddr_invoke_program_test
This test first loads a specific native eBPF program. It then creates the specified # of threads where each thread
attempts a TCP 'connect' to the remote endpoint `[::1]:<target_port + thread_context.thread_index>` continuously in a
loop.  The test set up ensures that the `thread_index` passed in each `thread_context` is unique to that thread.

This causes the invocation of the in-kernel eBPF program which returns some (arbitrary) decision based on the end-point
port number.

This test can be run with or without the extension restart option.

Sample command line invocations:

### 1.1.1. `ebpf_stress_tests_km.exe sockaddr_invoke_program_test`
- Uses default values for all supported options.

### 1.1.2. `ebpf_stress_tests_km.exe -tt=32 -td=15 -vo=true -er=true -erd=250 sockaddr_invoke_program_test`
- Creates 32 test threads.
- Runs test for 15 minutes.
- Verbose test trace output enabled.
- Extension restart enabled.
- Delay of 250 ms between successive extension restarts.

## 1.2. bindmonitor_tail_call_invoke_program_test
This test first loads a specific native eBPF program. It then loads all the MAX_TAIL_CALL_CNT tail call programs and updates the program array map. It then creates the specified number of threads where each thread attempts a TCP 'bind' to the same port continuously in a loop. The test setup guarantees that the `thread_index` passed in each `thread_context` is unique to that thread, so that each thread gets a unique port (base_port + thread_index).

This causes the invocation of the in-kernel eBPF tail call programs to be executed in sequence. The last tail call program returns a PERMIT verdict.

This test can be run with or without the extension restart option.

Sample command line invocations:

### 1.2.1. `ebpf_stress_tests_km.exe bindmonitor_tail_call_invoke_program_test`
- Uses default values for all supported options.

### 1.2.2. `ebpf_stress_tests_km.exe -tt=32 -td=15 -vo=true -er=true -erd=250 bindmonitor_tail_call_invoke_program_test`
- Creates 32 test threads.
- Runs test for 15 minutes.
- Verbose test trace output enabled.
- Extension restart enabled.
- Delay of 250 ms between successive extension restarts.

## 1.3. sample_attach_invoke_detach_race_km

This race test loads the sample native program and uses a multi-threaded invoke loop in parallel with a detach/reattach
churn thread. Each invoke worker uses a stable attach key so the test exercises repeated attach-point transitions while
invocations continue. If `-tt` is not specified, this test uses the CPU count as the invoke thread count.

### 1.3.1. `ebpf_stress_tests_km.exe sample_attach_invoke_detach_race_km`
- Uses default values for all supported options.

### 1.3.2. `ebpf_stress_tests_km.exe -tt=16 -td=5 -ad=10 sample_attach_invoke_detach_race_km`
- Uses 16 invoke threads.
- Runs test for 5 minutes.
- Uses 10 ms delay between detach and attach cycles.

# 2.0. ebpf_stress_tests_um.exe (test sources in .\um\)

This test application provides tests that are meant to be run against the user mode 'mock' of the eBPF sub-system. This
application does not require the presence of the eBPF kernel drivers and can be run on the dev machine as well.

_This application requires the `ebpfapi.dll` to be present in the DLL load path or in the same directory as this
binary._


Test specific command-line options (all optional, defaults used if not specified):

- `-tt=NNNN`: Number of test threads to create (Default for race test: 4).
- `-td=NNNN`: Test run-time in minutes (Default: 1).
- `-ad=NNNN`: Delay in milliseconds between detach and attach operations (Default: 10).
- `-vo=<true|false>`: Enable verbose output (default: false).
- `-er=<true|false>`: Restart extension.
- `-erd=NNNN`: Extension restart delay (in milliseconds).

This application provides the following tests:

## 2.1. sample_attach_invoke_detach_race_um

This race test loads the sample user-mode test program and runs invoke workers in parallel with a detach/reattach churn
thread. Invoke workers are keyed by attach data to match the multi-attach behavior used in the kernel-mode variant. If
`-tt` is not specified, this test uses 4 invoke threads by default.

### 2.1.1. `ebpf_stress_tests_um.exe sample_attach_invoke_detach_race_um`
- Uses default values for all supported options.

### 2.1.2. `ebpf_stress_tests_um.exe -tt=8 -td=5 -ad=10 sample_attach_invoke_detach_race_um`
- Uses 8 invoke threads.
- Runs test for 5 minutes.
- Uses 10 ms delay between detach and attach cycles.

## 2.2. ebpf_restart_test_controller.exe - eBPF Core Driver Restart Test

This standalone test controller validates the eBPF core driver's restart behavior under different scenarios involving open handles and pinned objects. 

**Important**: This test is implemented as a standalone executable (`ebpf_restart_test_controller.exe`) that does NOT load `ebpfapi.dll`, allowing it to test driver restart scenarios without holding a reference to the driver itself. This architectural design is critical to avoid test interference.

The test ensures that:

1. **ebpfcore cannot be stopped while child processes hold open handles** - Validates that the driver correctly prevents unload when user-mode processes have active references.
2. **ebpfcore can be stopped after processes exit** - Confirms proper cleanup and driver unload when all handles are released.
3. **ebpfcore behavior with pinned objects** - Tests and documents the driver's behavior when objects are pinned in the kernel namespace but no process holds handles.
4. **ebpfcore restarts and operates normally** - Verifies basic functionality after a driver restart cycle.

This test uses a helper process (`ebpf_restart_test_helper.exe`) that operates in three modes:
- **open-handles**: Creates eBPF objects and keeps handles open, blocking until signaled by the controller
- **pin-objects**: Creates objects, pins them to the kernel namespace, releases handles, and exits
- **unpin-objects**: Unpins previously pinned objects and exits

The controller coordinates with the helper process using named events for IPC synchronization.

### 2.2.1. `ebpf_restart_test_controller.exe`
- Runs the complete driver restart stress test sequence as a standalone executable
- Tests all scenarios: open handles, pinned objects, and restart verification
- Exit code 0 indicates success, non-zero indicates test failure

**Note**: This test may not fully stop and restart the driver if other processes (such as the eBPF service) are holding references to ebpfcore. This is expected behavior and the test will log appropriate messages in such cases.

**Why a Standalone Controller?** The previous implementation had a fundamental architectural flaw where the test process itself held a reference to ebpfcore (via loading ebpfapi.dll), preventing it from testing driver restart scenarios accurately. The standalone controller avoids this issue by never loading ebpfapi.dll directly.