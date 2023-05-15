# Automated Tests

This file details the testing that is done in CI/CD, and that must be maintained
and extended as new features are added.

## eBPF runtime
Runtime binaries should have lightweight scaffolding for compiling the binary (.sys, .dll, .exe, etc.)
but keep core functionality in static libraries. This allows the same core logic to be used in tests
as well as the runtime binaries.

## Unit tests
Unit tests test the functionality in the static libraries. Thus, the more code that is in the static
libraries instead of in the scaffolding, the higher fidelity unit tests can be.  Unit tests also use
test libraries that contain mock implementations of system APIs such as kernel system APIs and NMR APIs,
allowing unit tests to run entirely in user mode. Unit tests are run with address sanitization on,
to catch memory issues.

Tests in this category currently include:
* bpf2c_tests.exe: This unit tests bpf2c conversion.
* netebpfext_unit.exe: This unit tests netebpfext logic.
* unit_tests.exe: This unit tests logic in ebpfcore, libbpf, and netsh.
* ebpf_stress_tests_um.exe: This tests the user mode 'mock' scaffolding's resilience in multi-threaded stress scenarios.

## Kernel tests
Whereas unit tests run in user-mode and test the static libraries, kernel tests exercise the actual
runtime binaries running on a real machine. CI/CD uses [self-hosted runners](SelfHostedRunnerSetup.md)
for this purpose. Such tests can catch bugs in lightweight scaffolding code, installation issues,
etc. and potentially help identify any gaps in the mock implementations of system APIs if any bugs
are found that should have been caught by unit tests.

Tests in this category currently include:
* api_test.exe: This tests user mode APIs to interact with eBPF.
* connect_redirect_tests.exe: This tests connection redirection functionality.
* sample_ext_app.exe: This tests the sample extension driver.
* socket_tests.exe: This tests eBPF programs that attach to socket events.
* xdp_tests.exe: This tests eBPF programs that attach to XDP.
* ebpf_stress_tests_km.exe: This tests the in-kernel eBPF sub-system's resilience in multi-threaded stress scenarios.

## Fuzz tests
All APIs exposed to developers of apps, eBPF programs, or runtime extensions should be fuzz tested
(see [Fuzzing](Fuzzing.md) for more details).  Like unit tests, fuzz tests generally do so
by linking with the static libraries, and run with address sanitization on to catch memory issues.
Each API suite currently has its own fuzzer executable, and CI/CD job.

Tests in this category currently include:
* bpf2c_fuzzer.exe: This fuzz tests bpf2c conversion.
* core_helper_fuzzer.exe: This fuzz tests the global helper APIs.
* execution_context_fuzzer.exe: This fuzz tests IOCTLs exposed by ebpfcore.
* netebpfext_fuzzer.exe: This fuzz tests the netebpfext hooks.
* verifier_fuzzer.exe: This fuzz tests verification of random eBPF programs.

## Conformance tests
For "standard" BPF functionality such as the [BPF Instruction Set Architecture (ISA)](https://github.com/dthaler/ebpf-docs/blob/update/isa/kernel.org/instruction-set.rst),
a set of BPF conformance tests are used to run the same test vectors that work against Linux, against
the verifier, the JIT compiler, etc. used by eBPF for Windows.  As other functionality beyond the ISA
becomes standardized, it is expected that other cross-project conformance tests may arise.

## App compat tests
App compat tests test scenario-specific applications or eBPF programs to verify backwards compability
and lack of regressions across builds. For example, the cilium scenario tests use eBPF programs from
the Cilium layer 4 load balancer.  Like kernel tests, app compat tests also run on a real
machine, with CI/CD using [self-hosted runners](SelfHostedRunnerSetup.md).

Tests in this category currently include:
* bpftool_tests.exe: This tests app compat for scripts (and users) that invoke bpftool commands.
* cilium_tests.exe: This tests that the Cilium L4LB eBPF programs can be verified.

## Fault injection tests
Fault injection tests inject faults in order to test behavior under fault conditions.

Tests in this category currently include:
* unit_tests.exe: The unit test discussed above, but run under fault injection conditions.
* netebpfext_unit.exe: The unit test discussed above, but run under fault injection conditions.

## Performance tests
Performance tests check for performance regressions across builds.

Tests in this category currently include:
* ebpf_performance.exe: Currently this only outputs performance numbers, rather than
  checking for regressions.  Improving this is issue #1915.
