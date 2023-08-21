# eBPF Performance Benchmark Design

## Overview

The **eBPF Performance Benchmark suite (Perf)** aims to evaluate the performance of the eBPF runtime, pinpoint areas for enhancement, and ensure timely detection and mitigation of performance regressions. The suite provides a comprehensive view of build-to-build performance, categorized by scenarios, aiding in the identification of areas requiring improvement. Measuring the performance of the user-mode libbpf library is a non-goal as libbpf operations are assumed to occur at a lower frequency. Performance tests are performed using the [bpf_performance](https://github.com/Alan-Jowett/bpf_performance) runner.

## Architecture

The Perf suite comprises these primary components:

1. **Test Runner**: An executable designed to load, execute, and record metrics for an eBPF program.
2. **Test Suites**: A collection of eBPF programs that comprehensively test various aspects of the eBPF runtime.
3. **CI/CD Workflow**: A set of YAML files and scripts responsible for invoking the Test Runner with Test Suites, uploading resulting data to a central repository, and creating issues in case of performance regressions.

## Test Runner

For details of the test runner, see [bpf_performance](https://github.com/Alan-Jowett/bpf_performance).

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
1. **bpf_xdp_adjust_head**: This program type specific helper function grows and shrinks an XDP buffer.
2. **bpf_trace_printk**: The performance impact of this function could be high and it is important to measure it.

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