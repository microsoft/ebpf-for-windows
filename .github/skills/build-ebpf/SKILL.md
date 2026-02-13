---
name: build-ebpf
description: >
  Build the eBPF for Windows repository — entire solution or specific components.
  Use this skill when asked to build, compile, rebuild, restore, or clean the project
  or any of its components (drivers, libraries, tools, tests, etc.).
---

# Build eBPF for Windows

Build the eBPF for Windows solution or individual components using MSBuild.

## When to Use

- User asks to build, compile, rebuild, or clean the project
- User asks to build a specific component (driver, library, tool, test, etc.)
- User asks to restore NuGet packages
- User asks to do a full or partial build with a specific configuration
- After making code changes that need to be compiled

## Environment Requirements

- **Visual Studio Developer PowerShell** (required — regular PowerShell lacks build environment variables)
- MSBuild from VS Build Tools
- Must run from the **solution root directory** (`ebpf-for-windows.sln` location)

## Build Instructions

### Step 1: Determine What to Build

Ask the user (or infer from context) what they want to build. Options:

1. **Full solution** — build everything
2. **Specific component(s)** — use the target map below to select `/t:` targets
3. **Restore only** — just restore NuGet packages

### Step 2: Determine Configuration and Platform

| Parameter | Options | Default |
|-----------|---------|---------|
| Configuration | `Debug`, `Release`, `NativeOnlyDebug`, `NativeOnlyRelease`, `FuzzerDebug` | `Debug` |
| Platform | `x64`, `ARM64` | `x64` |

If the user doesn't specify, use `Debug` and `x64`.

### Step 3: Construct and Run the MSBuild Command

**CRITICAL RULES:**
- Always use the **solution file**: `msbuild ebpf-for-windows.sln` — never build `.vcxproj` files directly
- Always run from the **solution root directory**
- Use `/m` for parallel builds
- For first-time or fresh builds, add `-Restore` to restore NuGet packages
- For clean rebuilds, use `/t:"target:clean,target"` syntax

#### Full Solution Build

```powershell
# Standard build
msbuild ebpf-for-windows.sln /m /p:Configuration=Debug /p:Platform=x64

# With NuGet restore (first-time or after package changes)
msbuild ebpf-for-windows.sln /m /p:Configuration=Debug /p:Platform=x64 -Restore

# Clean the solution
msbuild ebpf-for-windows.sln /m /p:Configuration=Debug /p:Platform=x64 /t:clean

# With static analysis
msbuild ebpf-for-windows.sln /m /p:Configuration=Release /p:Platform=x64 /p:Analysis=True
```

#### Targeted Component Build

```powershell
# Single target
msbuild ebpf-for-windows.sln /m /p:Configuration=Debug /p:Platform=x64 /t:drivers\EbpfCore

# Multiple targets
msbuild ebpf-for-windows.sln /m /p:Configuration=Debug /p:Platform=x64 /t:"drivers\EbpfCore,drivers\netebpfext,tests\unit_tests"

# Clean + rebuild a target (use semicolon or comma separator)
msbuild ebpf-for-windows.sln /m /p:Configuration=Debug /p:Platform=x64 /t:"tools\bpf2c:Clean;tools\bpf2c"
```

### Step 4: Analyze Results

- If the build succeeds, report success with the output path (e.g., `x64\Debug\`)
- If the build fails, show the **first error(s)** and suggest fixes
- Common issues:
  - Missing NuGet packages → suggest adding `-Restore`
  - Missing environment → suggest using Visual Studio Developer PowerShell
  - Header/linker errors → suggest checking dependencies and rebuilding prerequisite targets

## MSBuild Target Map

Use this map to translate component names to MSBuild `/t:` targets.
**Solution targets use solution folder paths, not filesystem paths.**

### Drivers (Kernel Components)

| Component | Target | Source |
|-----------|--------|--------|
| EbpfCore (kernel execution context) | `drivers\EbpfCore` | `ebpfcore/` |
| EbpfCore_Usersim (usersim variant) | `drivers\EbpfCore_Usersim` | `ebpfcore/usersim/` |
| netebpfext (WFP network hooks) | `drivers\netebpfext` | `netebpfext/sys/` |
| sample_ebpf_ext (sample extension) | `undocked\drivers\sample_ebpf_ext` | `undocked/tests/sample/ext/drv/` |

### DLLs and Services (User-Mode)

| Component | Target | Source |
|-----------|--------|--------|
| EbpfApi (libbpf-compatible API) | `dlls\EbpfApi` | `ebpfapi/` |
| eBPFSvc (JIT/verification service) | `service\ebpfsvc` | `ebpfsvc/` |
| ebpfnetsh (netsh plugin) | `dlls\ebpfnetsh` | `tools/netsh/` |

### Libraries

| Component | Target | Source |
|-----------|--------|--------|
| API library | `libs\user\api` | `libs/api/` |
| Service library | `libs\user\service` | `libs/service/` |
| Execution context (kernel) | `libs\kernel\execution_context_kernel` | `libs/execution_context/kernel/` |
| Execution context (user) | `libs\user\execution_context_user` | `libs/execution_context/user/` |
| uBPF (kernel) | `libs\kernel\ubpf_kernel` | `libs/ubpf/kernel/` |
| uBPF (user) | `libs\user\ubpf_user` | `libs/ubpf/user/` |
| Runtime (kernel) | `libs\kernel\runtime_kernel` | `libs/runtime/kernel/` |
| Runtime (user) | `libs\user\runtime_user` | `libs/runtime/user/` |
| API common | `libs\user\api_common` | `libs/api_common/` |
| Shared (kernel) | `libs\kernel\shared_kernel` | `libs/shared/kernel/` |
| Shared (user) | `libs\user\shared_user` | `libs/shared/user/` |
| PE parse | `libs\user\pe-parse` | `libs/pe-parse/` |
| ELF spec | `libs\user\elf_spec` | `libs/elf_spec/` |
| Store helper | `libs\user\ebpf_store_helper` | `libs/store_helper/user/` |
| Netsh static | `libs\user\netsh_static` | `libs/ebpfnetsh/` |
| PREVAIL verifier | `libs\user\prevail` | `external/ebpf-verifier/build/` |
| libbtf | `libs\user\libbtf` | `external/ebpf-verifier/build/external/libbtf/` |
| netebpfext (user) | `libs\user\netebpfext_user` | `netebpfext/user/` |
| cxplat (kernel) | `libs\kernel\cxplat_winkernel` | `external/usersim/cxplat/` |
| cxplat (user) | `libs\user\cxplat_winuser` | `external/usersim/cxplat/` |
| usersim | `libs\user\usersim` | `external/usersim/src/` |
| usersim_dll_skeleton | `libs\user\usersim_dll_skeleton` | `external/usersim/usersim_dll_skeleton/` |

### Tools

| Component | Target | Source |
|-----------|--------|--------|
| bpf2c (native code generator) | `tools\bpf2c` | `tools/bpf2c/` |
| bpftool | `tools\bpftool` | `tools/bpftool/` |
| export_program_info | `tools\export_program_info` | `tools/export_program_info/` |
| dnsflood | `tools\dnsflood` | `tools/dnsflood/` |
| port_quota | `tools\port_quota` | `tools/port_quota/` |
| port_leak | `tools\port_leak` | `tools/port_leak/` |
| Setup build | `tools\setup_build` | `scripts/setup_build/` |
| OneBranch | `tools\onebranch` | `tools/onebranch/` |
| export_program_info_sample | `undocked\tools\export_program_info_sample` | `undocked/tools/export_program_info_sample/` |

### Tests

| Component | Target | Source |
|-----------|--------|--------|
| API tests | `tests\api_test` | `tests/api_test/` |
| Unit tests | `tests\unit_tests` | `tests/unit/` |
| bpf2c tests | `tests\bpf2c_tests` | `tests/bpf2c_tests/` |
| Performance tests | `tests\performance` | `tests/performance/` |
| Socket tests | `tests\socket_tests` | `tests/socket/` |
| Cilium tests | `tests\cilium_tests` | `tests/cilium/` |
| Connect redirect tests | `tests\connect_redirect_tests` | `tests/connect_redirect/` |
| Common tests | `tests\common_tests` | `tests/libs/common/` |
| netebpfext unit tests | `tests\netebpfext_unit` | `tests/netebpfext_unit/` |
| Sample programs | `tests\sample` | `tests/sample/` |
| bpftool tests | `installer\bpftool_tests` | `tests/bpftool_tests/` |
| bpf2c plugin | `tests\bpf2c_plugin` | `tests/bpf2c_plugin/` |
| Test utilities | `tests\test_util` | `tests/libs/util/` |
| Sample ext app | `tests\sample_ext_app` | `tests/sample/ext/app/` |
| TCP/UDP listener | `tests\tcp_udp_listener` | `tests/tcp_udp_listener/` |
| export_program_info test | `tests\export_program_info_test` | `tests/export_program_info_test/` |
| Restart test controller | `tests\ebpf_restart_test_controller` | `tests/stress/restart_test_controller/` |
| Restart test helper | `tests\ebpf_restart_test_helper` | `tests/stress/restart_test_helper/` |

### Stress Tests and Fuzzers

Stress tests build in Debug/Release. Fuzzers **require `FuzzerDebug` configuration**.

| Component | Target | Config | Source |
|-----------|--------|--------|--------|
| Stress tests (user-mode) | `tests\ebpf_stress_tests_um` | Debug | `tests/stress/um/` |
| Stress tests (kernel-mode) | `tests\ebpf_stress_tests_km` | Debug | `tests/stress/km/` |
| Execution context fuzzer | `tests\libfuzzer\execution_context_fuzzer` | FuzzerDebug | `tests/libfuzzer/execution_context/` |
| bpf2c fuzzer | `tests\libfuzzer\bpf2c_fuzzer` | FuzzerDebug | `tests/libfuzzer/bpf2c_fuzzer/` |
| Verifier fuzzer | `tests\libfuzzer\verifier_fuzzer` | FuzzerDebug | `tests/libfuzzer/verifier_fuzzer/` |
| Core helper fuzzer | `tests\libfuzzer\core_helper_fuzzer` | FuzzerDebug | `tests/libfuzzer/core_helper_fuzzer/` |
| netebpfext fuzzer | `tests\libfuzzer\netebpfext_fuzzer` | FuzzerDebug | `tests/libfuzzer/netebpfext_fuzzer/` |

### External Dependencies

| Component | Target | Source |
|-----------|--------|--------|
| Catch2 | `tests\Catch2` | `external/Catch2/` |
| Catch2WithMain | `tests\Catch2WithMain` | `external/Catch2/` |

> **Note:** The PREVAIL verifier for normal builds is `libs\user\prevail`. The `ubpf_fuzzer\*` targets
> (ebpfverifier, ubpf, libbtf, win-c, ubpf_fuzzer, ubpf_fuzzer_post_build) are only built in
> `FuzzerDebug` configuration and will fail with MSB4057 errors in Debug/Release.

### ubpf_fuzzer Targets (FuzzerDebug Only)

These targets only build in **`FuzzerDebug`** configuration:

| Component | Target | Source |
|-----------|--------|--------|
| ebpfverifier (fuzzer copy) | `ubpf_fuzzer\ebpfverifier` | `external/ubpf/build_fuzzer/external/ebpf-verifier/` |
| ubpf (fuzzer copy) | `ubpf_fuzzer\ubpf` | `external/ubpf/build_fuzzer/vm/` |
| ubpf_fuzzer | `ubpf_fuzzer\ubpf_fuzzer` | `external/ubpf/build_fuzzer/libfuzzer/` |
| libbtf (fuzzer copy) | `ubpf_fuzzer\libbtf` | `external/ubpf/build_fuzzer/.../libbtf/` |
| win-c (fuzzer copy) | `ubpf_fuzzer\win-c` | `external/ubpf/build_fuzzer/.../win-c/` |
| ubpf_fuzzer_post_build | `ubpf_fuzzer\ubpf_fuzzer_post_build` | `scripts/ubpf_fuzzer_post_build/` |

### Build Utilities and Installers

| Component | Target | Config Notes | Source |
|-----------|--------|-------------|--------|
| RPC interface | `idl\rpc_interface` | All configs | `rpc_interface/` |
| NuGet package | `tools\nuget` | All configs | `tools/nuget/` |
| Redist package | `tools\redist-package` | NativeOnly/Release only (not Debug) | `tools/redist-package/` |
| Installer (WiX) | `installer\ebpf-for-windows` | All configs | `installer/ebpf-for-windows/` |

## Common Build Patterns

Use these when the user describes what area they're working on:

| Working On | Targets to Build |
|------------|-----------------|
| API changes | `libs\user\api,dlls\EbpfApi,tests\api_test` |
| bpf2c / native code generation | `tools\bpf2c,tests\bpf2c_tests,tests\sample` |
| Kernel driver changes | `drivers\EbpfCore,drivers\netebpfext,tests\unit_tests` |
| Service changes | `libs\user\service,service\ebpfsvc,tests\ebpf_stress_tests_um` |
| Execution context changes | `libs\kernel\execution_context_kernel,libs\user\execution_context_user,tests\api_test` |
| Network extension changes | `drivers\netebpfext,tests\netebpfext_unit` |
| Verifier changes | `libs\user\prevail,tests\unit_tests` |
| Shared library changes | Rebuild all dependents — prefer full solution build |

## Dependency Chain

When building specific components, be aware of the dependency order:

1. `tools\setup_build` (build utilities — runs first)
2. `libs\kernel\shared_kernel` / `libs\user\shared_user` (fundamental utilities)
3. `libs\kernel\runtime_kernel` / `libs\user\runtime_user` (platform abstractions)
4. `libs\kernel\execution_context_kernel` / `libs\user\execution_context_user` (core eBPF execution)
5. `drivers\EbpfCore`, `drivers\netebpfext` (kernel drivers)
6. `libs\user\api`, `dlls\EbpfApi` (user-mode APIs)
7. Tests and tools

MSBuild handles dependency resolution within the solution, so you typically only need to specify the top-level target(s) you want built.

## Output Locations

Build artifacts are placed under:
- `x64\Debug\` — Debug x64 builds
- `x64\Release\` — Release x64 builds
- `x64\NativeOnlyDebug\` — NativeOnly Debug builds
- `x64\NativeOnlyRelease\` — NativeOnly Release builds
- `ARM64\Debug\` — ARM64 Debug builds (if applicable)

## Quieting Build Output

For targeted builds where you only need to see errors, use `/v:q /nologo`:

```powershell
msbuild ebpf-for-windows.sln /m /p:Configuration=Debug /p:Platform=x64 /t:"tools\bpf2c" /v:q /nologo
```

Pipe through `| Select-Object -Last N` to see just the tail when checking for success/failure.

## Repository Initialization

After cloning, changing submodule pointers, or resetting submodules, run the initialization script before building:

```powershell
# From solution root — initializes submodules, generates cmake projects, restores NuGet
.\scripts\initialize_ebpf_repo.ps1

# Or with ARM64
.\scripts\initialize_ebpf_repo.ps1 -Architecture ARM64
```

This script:
1. Runs `git submodule update --init --recursive`
2. Generates cmake projects for ebpf-verifier, Catch2, and ubpf in their respective `build/` dirs
3. Restores NuGet packages for the solution

**IMPORTANT:** If cmake-generated project files are missing (e.g., `external/ebpf-verifier/build/prevail.vcxproj`), MSBuild will error with MSB3202. Run `initialize_ebpf_repo.ps1` to regenerate them.

## Submodule Gotchas

- `msbuild /t:clean` will fail if cmake-generated projects don't exist yet — run `initialize_ebpf_repo.ps1` first
- `git stash` in the parent repo does NOT affect submodule working trees — stash separately in each submodule if needed
- After resetting submodules (`git submodule update --init --recursive`), re-run `initialize_ebpf_repo.ps1`

## BPF Program Compilation (clang → .o)

When manually compiling BPF C programs with clang, use the full set of include paths
from the `tests\sample\sample.vcxproj` CustomBuild rules:

```powershell
# Standard sample programs (tests\sample\*.c)
& 'C:\Program Files\LLVM\bin\clang.exe' -g -target bpf -O2 -Werror `
  -Iinclude -Iexternal\bpftool `
  -Itests\xdp -Itests\socket -Itests\sample\ext\inc -Itests\include `
  -c tests\sample\<name>.c -o x64\Debug\<name>.o

# Undocked sample programs (tests\sample\undocked\*.c) — add extra includes
& 'C:\Program Files\LLVM\bin\clang.exe' -g -target bpf -O2 -Werror `
  -Iinclude -Iexternal\bpftool `
  -Itests\xdp -Itests\socket -Itests\sample\ext\inc -Itests\include `
  -Itests\sample -Iundocked\tests\sample\ext\inc `
  -c tests\sample\undocked\<name>.c -o x64\Debug\<name>.o
```

**Common mistake:** Using only `-Iinclude` will fail for programs that include
`socket_tests_common.h`, `xdp_common.h`, or `sample_ext_helpers.h`.

> **Note:** The examples use `C:\Program Files\LLVM\bin\clang.exe`, the default
> LLVM install location. Adjust the path if LLVM is installed elsewhere.
