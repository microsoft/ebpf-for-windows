# Copilot Instructions for eBPF for Windows

When working on the eBPF for Windows project, please follow these guidelines to ensure code quality and consistency.

## Comment Guidelines

### Comment Formatting
- **All comments MUST be complete sentences ending with proper punctuation (periods).**
- Single-line comments should start with `//` followed by a space and a complete sentence ending with a period.
- Multi-line comments should follow the same complete sentence rule for each line.
- Inline comments should also be complete sentences ending with periods.

**Examples:**
```c
// This is a correct comment.
/* This is also a correct multi-line comment. */

// Correct: Calculate the hash value for the key.
int hash = calculate_hash(key);

// Incorrect: Calculate the hash value for the key
// Incorrect: calculate hash value
```

### Comment Content
- Comments should be clear, concise, and add value to understanding the code.
- Avoid stating the obvious; focus on explaining why, not what.
- Use doxygen comments with `@param[in]`, `@param[out]`, or `@param[in,out]` direction annotations for all public API headers.

## Coding Conventions

### Naming Conventions
Follow the naming conventions documented in [docs/DevelopmentGuide.md](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/DevelopmentGuide.md#naming-conventions)

### Type Usage
- Use fixed length types from `stdint.h` (e.g., `int64_t`, `uint8_t`) instead of language keywords.
- Use `const` and `static` modifiers to scope exposure appropriately.

### Code Structure
- Source lines MUST NOT exceed 120 columns.
- Single-line if/else/loop blocks MUST be enclosed in braces.
- Include local headers (with `""`) before system headers (with `<>`).
- List headers in alphabetical order where possible.
- Use `#pragma once` in all header files.

### License Header
Every code file must include this license header:
```c
// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
```

## What NOT to Do

- **DON'T** use global variables where possible.
- **DON'T** use abbreviations unless they are well-known terms.
- **DON'T** use hard-coded magic numbers; use `#define`, enum, or const values.
- **DON'T** use commented-out code or code in `#if 0` blocks.
- **DON'T** leave comments without proper punctuation.

## When Generating Code

1. Ensure all comments are grammatically complete sentences with proper punctuation.
2. Follow the established naming conventions consistently.
3. Include appropriate error handling and input validation.
4. Add doxygen comments for public APIs.
5. Follow the existing code structure and formatting patterns in the file being modified.
6. Use meaningful variable and function names that follow the project conventions.

## Pull Request Guidelines

- Ensure existing tests continue to pass.
- Provide tests for every bug/feature that is completed.
- Format code using clang-format before submitting.
- Verify that all comments follow the complete sentence rule.
- Check that the code follows the project's naming conventions.

Remember: Code clarity and consistency are paramount. When in doubt, follow the existing patterns in the codebase and ensure all comments are complete, well-formed sentences.