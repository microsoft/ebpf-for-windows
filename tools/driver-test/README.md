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
| bpftool tests | `tests\bpftool_tests\bpftool_tests.vcxproj` |
| Sample extension app | `tests\sample\ext\app\sample_ext_app.vcxproj` |
| Performance tests | `tests\performance\performance.vcxproj` |
| Restart test controller | `tests\stress\restart_test_controller\ebpf_restart_test_controller.vcxproj` |
| Restart test helper | `tests\stress\restart_test_helper\ebpf_restart_test_helper.vcxproj` |
| KM stress tests | `tests\stress\km\ebpf_stress_tests_km.vcxproj` |
| eBPF MSI installer | `installer\ebpf-for-windows.wixproj` |

The MSI installer (`ebpf-for-windows.msi`) is required because the driver validation setup
(`scripts\install_ebpf.psm1`) installs the eBPF runtime (ebpfcore.sys, netebpfext.sys,
ebpfsvc.exe, ebpfapi.dll, and dependencies) from it. Building it pulls in the shippable runtime
projects as transitive dependencies.
