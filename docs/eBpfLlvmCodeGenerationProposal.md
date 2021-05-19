# Clang/LLVM as code generator for eBPF-for-Windows

## Overview

Clang/LLVM has a much richer tool chain for generating optimal ISA-specific
instruction sequences. Proposal is to use LLVM to convert eBPF byte code to
optimal native instruction sequences (replacing the current uBPF jitter).

## Background

Clang/LLVM has a language neutral internal representation (IR). Various
front-ends produce IR that is then handed off to back-ends to produce optimal
and secure ISA-specific machine code. LLVM code generation is platform aware
and can take advantage of advanced processor features like vectored / SIMD
instructions as well as having support for speculative load hardening and
other security features.

## Proposal

1. Write a Clang/LLVM front-end that translates eBPF byte code to LLVM IR.
2. Detect CPU features at runtime and configure LLVM.
3. Use LLVM back-end to generate optimal native instruction sequence.
4. Optionally provide LLVM IR versions of map helper functions (to permit
inlining of map lookups).

## Expected benefits

1. LLVM already supports x86, ARM and ARM64, so eBPF-for-Windows will be able
to JIT correctly on all these platforms.
2. LLVM can optimize the generated machine code as it has the entire control
flow graph as IR.
3. LLVM mitigations for branch prediction side-channel attacks will be applied
to the generated code.

## Future options

The conversion of source code -> LLVM IR -> eBPF -> LLVM IR -> machine code is
lossy in that some context about how to best optimize the resulting machine code
is lost at each step. A possible future change would be to have eBPF for Windows
accept LLVM IR directly, then internally convert LLVM IR -> eBPF for the verifier
and LLVM IR -> machine code for execution.