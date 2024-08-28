// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "crab_verifier_wrapper.hpp"
#include "ebpf_nethooks.h"
#include "ebpf_program_types.h"

#define PTYPE(name, descr, native_type, prefixes) \
    {                                             \
        name, descr, native_type, prefixes        \
    }

#define PTYPE_PRIVILEGED(name, descr, native_type, prefixes) \
    {                                                        \
        name, descr, native_type, prefixes, true             \
    }

// Allow for comma as a separator between multiple prefixes, to make
// the preprocessor treat a prefix list as one macro argument.
#define COMMA ,

typedef struct _ebpf_section_definition
{
    _Field_z_ const char* section_prefix;
    ebpf_program_type_t* program_type;
    ebpf_attach_type_t* attach_type;
    bpf_prog_type_t bpf_prog_type;
    bpf_attach_type_t bpf_attach_type;
} ebpf_section_definition_t;

struct ebpf_attach_type_compare
{
    bool
    operator()(const ebpf_attach_type_t& lhs, const ebpf_attach_type_t& rhs) const
    {
        return (memcmp(&lhs, &rhs, sizeof(ebpf_attach_type_t)) < 0);
    }
};

struct helper_function_info_t
{
    template <typename T> helper_function_info_t(const T& t) : count(EBPF_COUNT_OF(t)), data(t) {}
    const size_t count;
    const ebpf_helper_function_prototype_t* data;
};
