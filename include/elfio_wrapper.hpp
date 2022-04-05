// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma warning(push)
#pragma warning(disable : 4244)  // conversion from 'int' to 'ELFIO::Elf_Half', possible loss of data
#pragma warning(disable : 4458)  // declaration of 'name' hides class member
#pragma warning(disable : 6011)  // 'Dereferencing NULL pointer - https://github.com/vbpf/ebpf-verifier/issues/239
#pragma warning(disable : 26451) // Arithmetic overflow
#pragma warning(disable : 26450) // Arithmetic overflow
#pragma warning(disable : 26495) // Always initialize a member variable
#include "elfio/elfio.hpp"
#pragma warning(pop)
