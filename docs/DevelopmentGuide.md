Development Guide
=================

Coding Conventions
------------------

* **DO** use fixed length types defined in `stdint.h` instead
  of language keywords determined by the compiler (e.g., `int64_t, uint8_t`, not
  `long, unsigned char`).

* **DO** use `const` and `static` and visibility modifiers to scope exposure of
   variables and methods as much as possible.

* **DO** use doxygen comments, with \[in,out\]
  [direction annotation](http://www.doxygen.nl/manual/commands.html#cmdparam) in all public API
  headers. This is also encouraged, but not strictly required, for internal API
  headers as well.

* **DON'T** use global variables where possible.

* **DON'T** use abbreviations unless they are already well-known terms known by
  users (e.g., "app", "info"), or are already required for use by developers (e.g.,
  "min", "max", "args").  Examples of bad use would be `num_widgets` instead of
  `widget_count`, and `opt_widgets` instead of `option_widgets` or `optional_widgets`.

* **DON'T** use hard-coded magic numbers for things that have to be consistent
  between different files.  Instead use a `#define` or an enum or const value, as appropriate.

* **DON'T** use the same C function name with two different prototypes across
  the project where possible.

* **DON'T** use commented-out code, or code in an `#if 0` or equivalent.  Make sure all code is actually
  built.

Header Files
------------

* **DO** make sure any header file can be included directly, without requiring other
  headers to be included first.  That is, any dependencies should be included within
  the header file itself.

* **DO** include local headers (with `""`) before system headers (with `<>`). This
  helps ensure that local headers don't have dependencies on other things being
  included first, and is also consistent with the use of a local header for precompiled
  headers.

* **DO** list headers in alphabetical order where possible.  This helps ensure there are not duplicate includes,
  and also helps ensure that headers are usable directly.

* **DO** use `#pragma once` in all header files, rather than using ifdefs to test for duplicate inclusion.

Style Guide
-----------

### Automated Formatting with `clang-format`

For all C/C++ files (`*.c`, `*.cpp` and `*.h`), we use `clang-format` (specifically
version ```11.0.1```) to apply our code formatting rules. After modifying C/C++ files and
before merging, be sure to run:

```sh
$ ./scripts/format-code
```

### Formatting Notes:

Our coding conventions follow the [LLVM coding standards](https://llvm.org/docs/CodingStandards.html) with
the following over-rides:

* Source lines **MUST NOT** exceed 120 columns.
* Single-line if/else/loop blocks **MUST** be enclosed in braces.

Please stage the formatting changes with your commit, instead of making an extra
"Format Code" commit. Your editor can likely be set up to automatically run
`clang-format` across the file or region you're editing. See:

- [clang-format.el](https://github.com/llvm-mirror/clang/blob/master/tools/clang-format/clang-format.el) for Emacs
- [vim-clang-format](https://github.com/rhysd/vim-clang-format) for Vim
- [vscode-cpptools](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools)
  for Visual Studio Code

The [.clang-format](../.clang-format) file describes the style that is enforced
by the script, which is based off the LLVM style with modifications closer to
the default Visual Studio style. See [clang-format style options](
http://releases.llvm.org/3.6.0/tools/clang/docs/ClangFormatStyleOptions.html)
for details.

If you see unexpected formatting changes in the code, verify that you are running version 11 or higher of the LLVM tool-chain.

### License Header

The following license header **must** be included at the top of every code file:

```c
// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
```

It should be prefixed with the file's comment marker. If there is a compelling
reason to not include this header, the file can be added to
`.check-license.ignore`.

All files are checked for this header with the script:

```sh
$ ./scripts/check-license
```

### Naming Conventions

Naming conventions we use that are not automated include:

1. Use `lower_snake_case` for variable, member/field, and function names.
2. Use `UPPER_SNAKE_CASE` for macro names and constants.
3. Prefer `lower_snake_case` file names for headers and sources.
4. Prefer full words for names over contractions (i.e., `memory_context`, not
   `mem_ctx`).
5. Prefix names with `_` to indicate internal and private fields or methods
   (e.g., `_internal_field, _internal_method()`).
6. The single underscore (`_` ) is reserved for local definitions (static,
   file-scope definitions).
   e.g., static ebpf_result_t _do_something(..).
7. Prefix `struct` definitions with `_` (this is an exception to point 6), and always create a `typedef` with the
   suffix `_t`.  For example:
```c
typedef struct _ebpf_widget
{
    uint64_t count;
} ebpf_widget_t;
```
8. Prefix eBPF specific names in the global namespace with `ebpf_` (e.g., `ebpf_result_t`).

Above all, if a file happens to differ in style from these guidelines (e.g.,
private members are named `m_member` rather than `_member`), the existing style
in that file takes precedence.
