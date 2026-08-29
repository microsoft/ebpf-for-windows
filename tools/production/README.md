# Production build target

`production.vcxproj` is an aggregator ("Utility") project that builds **only** the shippable
eBPF for Windows binaries and packages. It exists so the internal release pipeline can produce
the release artifacts without building the unit tests, fuzzers, and developer tools that make up
the rest of the solution.

## Usage

```cmd
msbuild ebpf-for-windows.sln /t:tools\production /p:Configuration=NativeOnlyRelease /p:Platform=x64
```

Building this target compiles the referenced projects plus their transitive dependencies only.

## Contents

| Artifact | Project |
| -------- | ------- |
| ebpfapi.dll | `ebpfapi\ebpfapi.vcxproj` |
| ebpfcore.sys | `ebpfcore\EbpfCore.vcxproj` |
| ebpfsvc.exe | `ebpfsvc\eBPFSvc.vcxproj` |
| netebpfext.sys | `netebpfext\sys\netebpfext.vcxproj` |
| ebpfnetsh (netsh helper) | `tools\netsh\ebpfnetsh.vcxproj` |
| MSI installer | `installer\ebpf-for-windows.wixproj` |
| Developer (SDK) NuGet | `tools\nuget\nuget.vcxproj` |
| Samples NuGet | `tools\sample-package\sample-package.vcxproj` |
