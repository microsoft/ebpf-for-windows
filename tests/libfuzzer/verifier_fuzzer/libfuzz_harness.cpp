// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_internal.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"
#undef max
#include "elfio/elfio.hpp"
#include "libfuzzer.h"
#include "test_helper.hpp"

#include <chrono>
#include <cstdlib>

bool use_ebpf_store = true;
extern "C" size_t cxplat_fuzzing_memory_limit;

FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int*, char***) { return 0; }

// Treat the input data as an ELF file and a block of data to be passed to the program.
// Load the ELF file and run each program in the ELF file with the data as input.
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
                // For now, limit the size of the data to 4096 bytes.
                // The IOCTL interface limits the total message size to 64k, so this should leave extra space.
                uint8_t program_data[4096] = {0};
                uint32_t program_data_size = 0;
                uint8_t context[4096] = {0};

                std::stringstream stream(std::string((const char*)data, size));

                ELFIO::elfio reader;
                // Read the ELF file from the stream to determine its length.
                // This leaves the stream at the end of the ELF file.
                // All data after the ELF file is considered the data to be passed to the program.
                if (!reader.load(stream)) {
                    return 0;
                }

                // Copy the remaining data into the program_data buffer.
                stream.read((char*)program_data, sizeof(program_data));

                program_data_size = static_cast<uint32_t>(stream.gcount());

                test_attr.data_in = program_data;
                test_attr.data_size_in = program_data_size;
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
                printf(
                    "Program %s ran successfully with %d bytes of data\n",
                    bpf_program__name(program),
                    program_data_size);
            }
        }

        bpf_object__close(bpf_object);

    } catch (std::runtime_error&) {
    }

    return 0; // Non-zero return values are reserved for future use.
}
