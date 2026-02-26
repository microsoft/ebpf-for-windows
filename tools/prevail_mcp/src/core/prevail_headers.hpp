// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

/// @file Wrapper for including PREVAIL verifier headers with warning suppression.
/// Mirrors the pattern in libs/api_common/ebpf_verifier_wrapper.hpp.

// Prevent bpf_conformance's ebpf_inst.h from being included, as it conflicts with
// the ebpf_inst typedef used in this project (which aliases prevail::EbpfInst).
#ifndef BPF_CONFORMANCE_CORE_EBPF_INST_H
#define BPF_CONFORMANCE_CORE_EBPF_INST_H
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4100)  // Unreferenced formal parameter.
#pragma warning(disable : 4244)  // Conversion from 'type1' to 'type2', possible loss of data.
#pragma warning(disable : 4267)  // Conversion from 'size_t' to 'int', possible loss of data.
#pragma warning(disable : 4458)  // Declaration hides class member.
#pragma warning(disable : 26439) // Function may not throw.
#pragma warning(disable : 26450) // Arithmetic overflow.
#pragma warning(disable : 26451) // Arithmetic overflow.
#pragma warning(disable : 26495) // Always initialize a member variable.
#endif
#undef FALSE
#undef TRUE
#undef min
#undef max

#include "cfg/cfg.hpp"
#include "config.hpp"
#include "ebpf_verifier.hpp"
#include "elf_loader.hpp"
#include "ir/program.hpp"
#include "ir/unmarshal.hpp"
#include "platform.hpp"
#include "result.hpp"
#include "string_constraints.hpp"
#include "verifier.hpp"

#define FALSE 0
#define TRUE 1
#ifdef _MSC_VER
#pragma warning(pop)
#endif
