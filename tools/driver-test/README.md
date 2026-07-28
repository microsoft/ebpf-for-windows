# Driver Test build target

`driver-test.vcxproj` is an aggregator ("Utility") project that builds **only** the binaries
required to run the driver validation tests. It exists so the internal release pipeline can build
the minimal set of binaries needed for release validation, without building the unit tests,
fuzzers, and developer tools that make up the rest of the solution.

## Usage

```cmd
msbuild ebpf-for-windows.sln /t:tools\driver-test /p:Configuration=NativeOnlyRelease /p:Platform=x64
```

Building this target compiles the referenced projects plus their transitive dependencies only.

## Contents

| Artifact | Project |
| -------- | ------- |
| Sample extension driver | `undocked\tests\sample\ext\drv\sample_ext.vcxproj` |
| Sample eBPF programs (native drivers) | `tests\sample\sample.vcxproj` |
| API tests | `tests\api_test\api_test.vcxproj` |
| Socket tests | `tests\socket\socket_tests.vcxproj` |
| Connect redirect tests | `tests\connect_redirect\connect_redirect_tests.vcxproj` |
