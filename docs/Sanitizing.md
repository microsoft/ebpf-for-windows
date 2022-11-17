# Address Sanitizing Process

This file details the how *Address Sanitization* is performed within the CI/CD pipeline. Currently, the `fuzzing` and `sanitize_unit_tests` CI/CD tasks (see `cicid.yml`) are run upon a schedule.

## Kernel-mode modules

For kernel-mode modules (drivers, libraries, tests), address sanitization cannot be run through standard libraries, as they would need to be internally signed by Microsoft, and for security they could not be release.

Therefore, to regards of the public repository, a mock library (i.e. `no_asan_kernel`) has been added in order to succeed building the solution, whereas the internal libraries will be used within an internal ADO pipeline within Microsoft.

## User-mode modules

For user-mode modules (drivers, libraries, tests), address sanitization can be run normally through the standard LLVM libraries, delivered as part of Visual Studio.


## Further information

More information can be found in the following documentation:

- [Introduction to AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)
- [Using AddressSanitizer](https://learn.microsoft.com/cpp/sanitizers/asan?view=msvc-170)
- [AddressSanitizer language, build, and debugging reference](https://learn.microsoft.com/cpp/sanitizers/asan-building?view=msvc-170#inferasanlibsno-linker-option)