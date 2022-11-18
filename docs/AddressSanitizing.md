# Address Sanitizing

*AddressSanitizer* (aka ASan) is a library for detecting memory-related issues for C/C++. It consists of a compiler instrumentation module and a run-time library. The typical performance penalty for address sanitizing is 2x.

This file details the how *Address Sanitization* is performed within the  `ebpf-for-windows.sln` solution and its CI/CD pipeline.


## Current usage in eBPF for Windows

*AddressSanitizer* is integrated with the Visual Studio project system, and is installed as a component through the *Visual Studio Installer*. Address sanitization can be enabled on a C/C++ project by adding `/fsanitize=address` to the C/C++ compiling options (either through the command line or the dedicated UI field).

On Windows, address sanitization is implemented differently for kernel-mode and user-mode modules:

- **Kernel-mode modules**: For kernel-mode modules (drivers, libraries, tests), address sanitization cannot be run through standard libraries, as they would need to be internally signed by Microsoft, and for security they could not be released.
Therefore, for this public repository, ASAN has been disabled (`/fno-sanitize-address-vcasan-lib`) and a mock library (i.e., `no_asan_kernel.vcxproj`) has been added in order to succeed in building the solution and running CI/CD pipelines, whereas the internal libraries (aka KASan) will be used within an internal ADO pipeline within Microsoft.

- **User-mode modules**: For user-mode modules (drivers, libraries, tests), address sanitization can be run normally through the standard LLVM libraries, delivered as part of Visual Studio.

### Address sanitization within the CI/CD pipeline

Within the CI/CD pipeline, address sanitizing is enabled through a global flag named `AddressSanitizer`, within `cicd.yml`.

Currently, the `fuzzing` and `sanitize_unit_tests` CI/CD tasks (see `cicid.yml`) are run upon a schedule, so that any sanitizing check failure will be processed as a separated, automatically generated issue.

## References

More information on *AddressSanitizer* can be found in the following documentation:

- [Overview of AddressSanitizer](https://learn.microsoft.com/cpp/sanitizers/asan?view=msvc-160)
- [AddressSanitizer language, build, and debugging reference](https://learn.microsoft.com/cpp/sanitizers/asan-building?view=msvc-160)
- [CLANG-LLVM - Introduction to AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html)