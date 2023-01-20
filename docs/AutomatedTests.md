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

## Kernel tests
Whereas unit tests run in user-mode and test the static libraries, kernel tests exercise the actual
runtime binaries running on a real machine. CI/CD uses [self-hosted runners](SelfHostedRunnerSetup.md)
for this purpose. Such tests can catch bugs in lightweight scaffolding code, installation issues,
etc. and potentially help identify any gaps in the mock implementations of system APIs if any bugs
are found that should have been caught by unit tests.

## Fuzz tests
All APIs exposed to developers of apps, eBPF programs, or runtime extensions should be fuzz tested
(see [Fuzzing](Fuzzing.md) for more details).  Like unit tests, fuzz tests generally do so
by linking with the static libraries, and run with address sanitization on to catch memory issues.
Each API suite currently has its own fuzzer executable, and CI/CD job.

## Conformance tests
For "standard" BPF functionality such as the [BPF Instruction Set Architecture (ISA)](https://github.com/dthaler/ebpf-docs/blob/update/isa/kernel.org/instruction-set.rst),
a set of BPF conformance tests are used to run the same test vectors that work against Linux, against
the verifier, the JIT compiler, etc. used by eBPF for Windows.  As other functionality beyond the ISA
becomes standardized, it is expected that other cross-project conformance tests may arise.

## App compat tests
App compat tests test scenario-specific applications or eBPF programs to verify backwards compability
and lack of regressions across builds. For example, the cilium scenario tests use eBPF programs from
the Cilium layer 4 load balancer.

## Low memory tests
Low memory tests use error injection to fail memory allocations in order to test behavior under low
memory conditions.
