# Fuzz Testing in eBPF-For-Windows

## Overview
Fuzz testing is a test methodology that finds a class of bugs in the code-base
by generating random inputs and verifying that the code doesn't crash.

## Tests
The fuzzing tests are in the repo under tests/libfuzzer. Fuzz tests execute as part
of each CI/CD workflow. The tests generate a random block of bytes that a fuzzer
uses as a test vector to determine what API to fuzz and what arguments to pass to it.

## Reproducing a failure from artifacts
When a crash happens, a folder containing the unique crash will be created. Click on *Summary* in the build section. The following example shows the process of debugging for *verifier_fuzzer* which can then be used for other CI/CD steps as well.
Download the artifact and the associated build.  For example, if verifier_fuzzer "run_test (Release)" failed, download *Artifacts-verifier_fuzzer-x64-Release* and *Build-x64-fuzzer Release*.

Copy the crash file from the artifact folder to a separate directory,  *verifier_fuzzer* files including *verifier_fuzzer.pdb*, *verifier_fuzzer.lib*, *verifier_fuzzer.exp*, and *verifier_fuzzer.exe* from debug directory. The C Runtime library, entitled, *ucrtbased.dll*, and address sanitizer files, marked by ASAN need to be included, *clang_rt.asan_dbg_dynamic-x86_64.dll* ,and *clang_rt.asan_dynamic-x86_64.dll*.

### Using the command line
Run a desired admin CMD locating to the copied files in the new directory, and enter with the following command:
```
windbgx -y SRV*;. -srcpath <your-path-to-ebpf-for-windows> verifier_fuzzer.exe <crash-file-name>
```
A window containing the windbg debugger opens up and enter ```g``` in the command box of windbg. If an access violation indicating ```Access violation - code c0000005 (first chance)``` shows up, please use ```sxi c0000005``` to ignore this error. Please use ```g``` again to see the line that crashes.

An alternative is to reproduce a crash to use the local latest build and run
```
verifier_fuzzer.exe <crash-file-name>
```
This method will show the line of crash in the source file.

### Using Visual Studio

From within Visual Studio, you can reproduce the crash as follows:

1. Set the active configuration to FuzzerDebug.
2. Right click the verifier_fuzzer project and click Properties.
3. Under Debugging, set Working Directory to: $(OutDir)
4. Under Debugging, set Command Arguments to: verifier_corpus\<crash-file-name>
5. Build the solution.
6. Copy the downloaded <crash-file-name> to the x64\FuzzerDebug\verifier_corpus directory.
7. Start (with debugging) the verifier_fuzzer from within Visual Studio.

# Regenerating the corpus for execution context fuzzer
The libfuzzer tests work best if they have an existing
[corpus](https://releases.llvm.org/11.0.0/docs/LibFuzzer.html#corpus) to work
from. The corpus for the IOCTL fuzzer (execution context fuzzer) is located in
tests\libfuzzer\execution_context\corpus.

If new IOCTLs are added, regenerate the corpus as follows:
1) Create a directory called "corpus" in the same location as the test.
2) Set the environment variable "EBPF_GENERATE_CORPUS" to "1".
3) Run the unit tests.
4) Replace the files under tests\libfuzzer\execution_context\corpus with the
generated files.
