# eBPF Performance Benchmark Design

## Overview

The **eBPF Performance Benchmark suite (Perf)** aims to evaluate the performance of the eBPF runtime, pinpoint areas for enhancement, and ensure timely detection and mitigation of performance regressions. The suite provides a comprehensive view of build-to-build performance, categorized by scenarios, thereby aiding in the identification of areas requiring improvement.

## Architecture

The Perf suite comprises the following primary components:

1. **Test Runner**: An executable designed to load, execute, and record metrics for an eBPF program.
2. **Test Suites**: A collection of eBPF programs that comprehensively test various aspects of the eBPF runtime.
3. **CI/CD Workflow**: A set of YAML files and scripts responsible for invoking the Test Runner with Test Suites, uploading resulting data to a central repository, and creating issues in case of performance regressions.

## Test Runner

The Test Runner (Runner) is a C++ program utilizing the libbpf library. It loads an eBPF program (in the kernel) and employs bpf_prog_test_run_opts to execute the BPF program on specified CPUs for a specified number of iterations. Subsequently, it calculates and outputs the average duration of the BPF programs. As a stretch goal, the Runner is designed to be platform-agnostic, enabling it to target both Windows and Linux eBPF runtimes.

## Test Suites

Each test is defined by a YAML file outlining test parameters and one or more associated eBPF programs. The parameters encompass:

1. **Initial Map State (if applicable)**
2. **Program -> CPU Assignment**
3. **Iteration Count**
4. **For Each Program**
   - Attach Type
   - Input Data

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

Explanation of fields:
**entry_point** A function or functions in the ELF file to be called for this test.
**map_state_preparation** A optional function that is called to prepare the map state.
**program_cpu_assignment** Mapping from function to CPU. If not specified, each program is executed on every CPU.
**programs** Provide attach type for each program and any initial data.

## Baseline Test

The Baseline test consists of an empty function containing two instructions:

```assembly
mov32 %r0, 0
exit
```

The purpose of this test is to evaluate the baseline cost of invoking a BPF program.

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

These tests involve invoking the runtime's helper functions, including the setup of any required state. This will include both general purpose as well as program type specific helper function tests.

## CI/CD Integration

CI/CD integration comprises two facets:

1. **Setup and Execution**: YAML files and scripts for configuring and running tests on a benchmarking machine.
2. **Result Visualization**: Libraries for visualizing test results in a browser.

The **Setup and Execution** workflow will also optionally gather a CPU profiling traces to aid in diagnosing areas of the code that have high CPU usage.

## Debugging Regressions

When a significant regression in the build to build performance occurs, the CI/CD workflow will create a issue to track it and include instructions on how to further investigate the regression. A developer can then schedule an on-demand run of the workflow along with CPU profiling and then download the resulting traces as artifacts. The developer can then analyze the traces and investigate the regression further.

## Test Scripts

Test scripts perform the following actions:

1. **Download and Install eBPF Runtime**
2. **Compile eBPF Programs**
3. **Execute Each Test Case**
4. **Upload Test Results**

## Test result storage

The git repo will have a branch where test results are stored. The branch will contain a hierarchy of folders to avoid merge conflicts. After each test run, the work-flow will checkout the branch, add the test results, commit, and finally push the branch back to GitHub.

The test data will be stores in a CSV file with the following columns:
1. Test name and entry point.
2. Average duration of an invocation of the entry point function.

## Visualization

The QUIC and XDP for Windows teams currently possess a visualization suite for performance results. This will be restructured into a Git repository, serving as a submodule accessible to all three projects.