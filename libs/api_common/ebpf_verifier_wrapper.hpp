// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma warning(push)
#pragma warning(disable : 4100)  // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244)  // 'conversion' conversion from 'type1' to
                                 // 'type2', possible loss of data
#pragma warning(disable : 26451) // Arithmetic overflow
#pragma warning(disable : 26450) // Arithmetic overflow
#pragma warning(disable : 26439) // This kind of function may not
                                 // throw. Declare it 'noexcept'
#pragma warning(disable : 26495) // Always initialize a member variable
#undef FALSE
#undef TRUE
#undef min
#undef max
#include "ebpf_verifier.hpp"
#pragma warning(pop)
