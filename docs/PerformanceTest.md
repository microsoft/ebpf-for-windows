# eBPF Performance Benchmark Design

## Overview

The **eBPF Performance Benchmark suite (Perf)** aims to evaluate the performance of the eBPF runtime, pinpoint areas for enhancement, and ensure timely detection and mitigation of performance regressions. The suite provides a comprehensive view of build-to-build performance, categorized by scenarios, aiding in the identification of areas requiring improvement. Measuring the performance of the user-mode libbpf library is a non-goal as libbpf operations are assumed to occur at a lower frequency.

## Architecture

The Perf suite comprises these primary components:

1. **Test Runner**: An executable designed to load, execute, and record metrics for an eBPF program.
2. **Test Suites**: A collection of eBPF programs that comprehensively test various aspects of the eBPF runtime.
3. **CI/CD Workflow**: A set of YAML files and scripts responsible for invoking the Test Runner with Test Suites, uploading resulting data to a central repository, and creating issues in case of performance regressions.

## Test Runner

The Test Runner (Runner) is a C++ program utilizing the libbpf library. It loads an eBPF program (in the kernel) and employs bpf_prog_test_run_opts to execute the BPF program on specified CPUs for a specified number of iterations. Subsequently, it calculates and outputs the average duration of the BPF programs. As a stretch goal, the Runner is designed to be platform-agnostic, enabling it to target both Windows and Linux eBPF runtimes. Given the importance of measuring both single threaded performance as well as concurrent performance, the test schema permit scheduling BPF programs on specific sets of CPUs.

## Test Suites

Each test is defined by a YAML file outlining test parameters and one or more associated eBPF programs. The parameters encompass:

1. **Program -> CPU Assignment**: Specifies which CPUs execute each program, allowing concurrent execution.
2. **Iteration Count**: Determines the number of iterations for the test.
3. **For Each Program**:
   - **Attach Type**: The type of attachment for the eBPF program (e.g., XDP, TC).
   - **Input Data**: Initial data provided to the program.
   - **Map State Preparation Function (optional)**: Function to prepare initial map state for the test.

### Example YAML file

```yaml
tests:
  - name: Baseline
    description: The Baseline test with an empty eBPF program.
    elf_file: baseline.o
    entry_point: baseline_program
    map_state_preparation: prepare_map_state_baseline
    iteration_count: 100000
    programs:
      - attach_type: XDP
        input_data: null

  - name: Hash-table Map Read
    description: Tests reading from a generic eBPF map.
    elf_file: map_tests.o
    entry_point: read_hash
    map_state_preparation: prepare_hash_state_generic_read
    iteration_count: 100000
    programs:
      - attach_type: XDP
        input_data: null

  - name: Hash-table Map Read/Write
    description: Tests reading and write a generic eBPF map.
    elf_file: map_tests.o
    entry_point: [read_hash, write_hash]
    map_state_preparation: prepare_hash_state_generic_read
    program_cpu_assignment:
        read_hash: [0, 1, 2]        # 3 CPUs assigned to read from the hash map
        write_hash: [3]             # 1 CPU assigned to write to the hash map
    iteration_count: 100000
    programs:
      - attach_type: XDP
        input_data: null

  - name: Type-Specific Map (Ring-Buffer)
    description: Tests specific properties of a ring-buffer eBPF map.
    elf_file: type_specific_ring_buffer.ebpf
    entry_point: ring_buffer_program1
    iteration_count: 100000
    programs:
      - attach_type: XDP
        input_data: null

  # Add more test cases as needed
```

## Baseline Test

The Baseline test consists of an empty function containing two instructions:

```assembly
mov32 %r0, 0
exit
```

The purpose of this test is to evaluate the baseline cost of invoking a BPF program.

## Tail Call Test

The Tail Call test measures the cost of switching from an initial BPF program to a child BPF program via a tail call. Given that tail calls are inherently map operations as well, this test could be merged with the map tests.

## Generic Map Read/Write

These tests assess the eBPF runtime's map implementation performance and include the following test types:

1. **Read**: Maps are treated as read-only. A random element is selected and read from the map.
2. **Write**: A random element is selected, and a new value is written (variants may include insert and replace).
3. **Insert/Delete**: A random element is deleted from the map and subsequently re-inserted.

## Type-Specific Map

Certain maps possess unique properties that differentiate them. These maps include, but are not limited to:

1. **Ring-Buffer**
2. **LRU**
3. **LPM**

## Helper Function

These tests involve invoking the runtime's helper functions, including the setup of any required state. This will include both general-purpose as well as program-type-specific helper function tests. Helper functions that might be of interest to measure include:
1. **bpf_xdp_adjust_head** This program type specific helper function grows and shrinks a XDP buffer.
2. **bpf_trace_printk** The performance impact of this function could be high and it is important to measure it.

## CI/CD Integration

1. **Setup and Execution**: YAML files and scripts for configuring and running tests on a benchmarking machine.
2. **Result Visualization**: Libraries for visualizing test results in a browser.

**Setup and Execution** optionally gathers CPU profiling traces to aid in diagnosing areas of the code that have high CPU usage.

## Debugging Regressions

When a [statistically significant](https://en.wikipedia.org/wiki/Statistical_significance) regression in the build-to-build performance occurs, the CI/CD workflow will create an issue to track it and include instructions on how to further investigate the regression. A developer can then schedule an on-demand run of the workflow along with CPU profiling and then download the resulting traces as artifacts. The developer can then analyze the traces and investigate the regression further.

## Test Scripts

Test scripts perform the following actions:

1. **Download and Install eBPF Runtime**
2. **Compile eBPF Programs**
3. **Execute Each Test Case**
4. **Upload Test Results**

## Test Result Storage

Test results stored in dedicated Git repo branch with a hierarchical folder structure to prevent conflicts. Test data saved in CSV format with test name, entry point, and average duration columns.

## Visualization

The QUIC and XDP for Windows teams currently possess a visualization suite for performance results. This will be restructured into a Git repository, serving as a submodule accessible to all three projects.