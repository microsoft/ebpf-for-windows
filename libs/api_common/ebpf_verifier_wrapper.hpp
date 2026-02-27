// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Prevent bpf_conformance's ebpf_inst.h from being included, as it conflicts with
// the ebpf_inst typedef used in this project (which aliases prevail::EbpfInst).
#ifndef BPF_CONFORMANCE_CORE_EBPF_INST_H
#define BPF_CONFORMANCE_CORE_EBPF_INST_H
#endif

#pragma warning(push)
#pragma warning(disable : 4100)  // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244)  // 'conversion' conversion from 'type1' to
                                 // 'type2', possible loss of data
#pragma warning(disable : 4267)  // conversion from 'size_t' to 'int', possible loss of data
#pragma warning(disable : 4458)  // declaration of 'warnings' hides class member
#pragma warning(disable : 26439) // This kind of function may not
                                 // throw. Declare it 'noexcept'
#pragma warning(disable : 26450) // Arithmetic overflow
#pragma warning(disable : 26451) // Arithmetic overflow
#pragma warning(disable : 26495) // Always initialize a member variable
#undef FALSE
#undef TRUE
#undef min
#undef max
#include "ebpf_verifier.hpp"
#include "platform.hpp"
#define FALSE 0
#define TRUE 1
#pragma warning(pop)
