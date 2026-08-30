// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

int
sample_stress_load_program(
    const char* file_name,
    bpf_prog_type program_type,
    bpf_object** object,
    bpf_program** program,
    fd_t* program_fd,
    fd_t* map_fd);

int
sample_stress_initialize_test_map(fd_t map_fd);

void
sample_stress_close_program(bpf_object* object);
