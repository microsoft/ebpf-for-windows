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
| TCP/UDP listener (connect redirect helper) | `tests\tcp_udp_listener\tcp_udp_listener.vcxproj` |
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

The test harness scripts, `ebpfforwindows.wprp`, and `test_execution.json` are copied to the
output directory by `scripts\setup_build\setup_build.vcxproj`, which is reached through the
solution's `ProjectDependencies` entries.

## Keeping the closure correct

Because this target deliberately builds less than the full solution, a binary the driver test
scripts launch at run time but that is missing here is **not** caught by any build. It surfaces
roughly 45 minutes into the test run as an opaque failure:

```text
This command cannot be run due to the error: The system cannot find the file specified.
```

`scripts\check_driver_test_closure.ps1` guards against that. It runs in two places:

* As a post-build step of this project (`VerifyDriverTestClosure`), asserting every required
  file is actually present in the build output directory.
* As the `Validate-Driver-Test-Closure` GitHub workflow, which runs the same script in static
  mode. That mode walks the transitive project closure of `driver-test.vcxproj` (following both
  `<ProjectReference>` items and solution `ProjectDependencies`) and needs no build, so it is
  cheap enough to run on every pull request.

When a driver test script starts invoking a new binary, add the producing project to
`driver-test.vcxproj`, to the `driver-test` `ProjectDependencies` section of
`ebpf-for-windows.sln`, and to the required-file list in
`scripts\check_driver_test_closure.ps1`.
