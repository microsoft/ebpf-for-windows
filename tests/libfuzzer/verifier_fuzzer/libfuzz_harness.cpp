// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"
#include "libfuzzer.h"
#include "test_helper.hpp"

#include <chrono>
#include <cstdlib>

bool use_ebpf_store = true;
extern "C" size_t cxplat_fuzzing_memory_limit;

FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int*, char***) { return 0; }

FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    cxplat_fuzzing_memory_limit = 1024 * 1024;
    ebpf_watchdog_timer_t watchdog_timer;
    try {
        _test_helper_libbpf test_helper;
        test_helper.initialize();

        bpf_object_open_opts opts = {};
        opts.sz = sizeof(opts);
        opts.object_name = "test";
        bpf_object* bpf_object = bpf_object__open_mem(data, size, &opts);

        if (!bpf_object) {
            return 0;
        }

        bpf_object->execution_type = EBPF_EXECUTION_INTERPRET;

        if (bpf_object__load(bpf_object) == 0) {
            // For each program, run it with bpf_prog_test_run
            struct bpf_program* program;
            bpf_object__for_each_program(program, bpf_object)
            {
                bpf_test_run_opts test_attr = {};
                uint8_t program_data[4096] = {0};
                uint8_t context[4096] = {0};

                test_attr.data_in = program_data;
                test_attr.data_size_in = sizeof(program_data);
                test_attr.data_out = program_data;
                test_attr.data_size_out = sizeof(program_data);
                test_attr.repeat = 1;
                test_attr.duration = 0;
                test_attr.ctx_in = context;
                test_attr.ctx_size_in = sizeof(context);
                test_attr.ctx_out = context;
                test_attr.ctx_size_out = sizeof(context);
                test_attr.retval = 0;

                if (bpf_prog_test_run_opts(bpf_program__fd(program), &test_attr) != 0) {
                    break;
                }
                printf("Program %s ran successfully\n", bpf_program__name(program));
            }
        }

        bpf_object__close(bpf_object);

    } catch (std::runtime_error&) {
    }

    return 0; // Non-zero return values are reserved for future use.
}
