# libFuzzer based fuzzing tools

## Overview
[LibFuzzer](https://www.llvm.org/docs/LibFuzzer.html) is an in-process, coverage-guided, evolutionary fuzzing engine. It uses a set of starting data (the corpus)
to generate new test cases, measures the code-coverage of the new test, and re-combines it form new test cases.

## Usage
1) Copy the libFuzzer binary and existing corpus to a test machine (currently only Windows 10 and Server 2019 are supported).
2) Start the libFuzzer binary, pass the path to the corpus folder, and maximum time to run: ```execution_context_fuzzer.exe execution_context_fuzzer_corpus -max_total_time 1800```
3) If the the fuzzer hits an issue, it will display the stack trace and create a file containing the input that triggered the crash.
4) Copy any new test cases and check them into the repo.

## Reproducing a crash
TBD - Build harness to reproduce crashes using an input file. Note: OneFuzz tool chain has this capability.

## Future
Once funding is available, we should setup a OneFuzz cluster and have the CI/CD pipeline deploy to it.