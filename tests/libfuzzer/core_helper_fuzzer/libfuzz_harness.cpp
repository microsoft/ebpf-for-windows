// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_CORE_HELPER_FUZZER

#include "ebpf_core.h"
#include "ebpf_handle.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "helpers.h"
#include "libfuzzer.h"
#include "netebpf_ext_helper.h"
#include "platform.h"

#include <Windows.h>
#include <chrono>
#include <filesystem>
#include <map>
#include <vector>

// Currently the only program type with helpers is XDP. Although this test just
// uses the mock helper for XDP, it does result in exercising the core path for
// ids out of range of the core ones.
static std::vector<GUID> _program_types = {EBPF_PROGRAM_TYPE_XDP};

static std::map<std::string, ebpf_map_definition_in_memory_t> _map_definitions = {
    {
        "BPF_MAP_TYPE_HASH",
        {
            BPF_MAP_TYPE_HASH,
            4,
            4,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_ARRAY",
        {
            BPF_MAP_TYPE_ARRAY,
            4,
            4,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_PROG_ARRAY",
        {
            BPF_MAP_TYPE_PROG_ARRAY,
            4,
            4,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_PERCPU_HASH",
        {
            BPF_MAP_TYPE_PERCPU_HASH,
            4,
            4,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_PERCPU_ARRAY",
        {
            BPF_MAP_TYPE_PERCPU_ARRAY,
            4,
            4,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_HASH_OF_MAPS",
        {
            BPF_MAP_TYPE_HASH_OF_MAPS,
            4,
            4,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_ARRAY_OF_MAPS",
        {
            BPF_MAP_TYPE_ARRAY_OF_MAPS,
            4,
            4,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_LRU_HASH",
        {
            BPF_MAP_TYPE_LRU_HASH,
            4,
            4,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_LPM_TRIE",
        {
            BPF_MAP_TYPE_LPM_TRIE,
            4,
            4,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_QUEUE",
        {
            BPF_MAP_TYPE_QUEUE,
            0,
            4,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_LRU_PERCPU_HASH",
        {
            BPF_MAP_TYPE_LRU_PERCPU_HASH,
            4,
            4,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_STACK",
        {
            BPF_MAP_TYPE_STACK,
            0,
            4,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_PERCPU_ARRAY",
        {
            BPF_MAP_TYPE_PERCPU_ARRAY,
            0,
            4,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_RINGBUF",
        {
            BPF_MAP_TYPE_RINGBUF,
            0,
            4,
            64 * 1024,
        },
    },
};

void
fuzz_async_completion(void*, size_t, ebpf_result_t){};

class fuzz_wrapper
{
  public:
    fuzz_wrapper()
    {
        ebpf_result_t result = ebpf_core_initiate();
        if (result != EBPF_SUCCESS) {
            throw std::runtime_error("ebpf_core_initiate failed");
        }
    }
    void
    make_program(const GUID type)
    {
        ebpf_handle_t program_handle;

        std::string program_name = "program name";
        std::string file = "file name";
        std::string section = "section name";
        ebpf_program_parameters_t params{
            type,
            type,
            {reinterpret_cast<uint8_t*>(program_name.data()), program_name.size()},
            {reinterpret_cast<uint8_t*>(section.data()), section.size()},
            {reinterpret_cast<uint8_t*>(file.data()), file.size()},
            EBPF_CODE_JIT};

        if (ebpf_program_create_and_initialize(&params, &program_handle) == EBPF_SUCCESS) {
            handles.push_back(program_handle);
        }
        for (const auto& [name, def] : _map_definitions) {
            ebpf_utf8_string_t utf8_name{reinterpret_cast<uint8_t*>(const_cast<char*>(name.data())), name.size()};
            ebpf_handle_t handle;
            if (ebpf_core_create_map(&utf8_name, &def, ebpf_handle_invalid, &handle) == EBPF_SUCCESS) {
                handles.push_back(handle);

                ebpf_map_t* map = NULL;
                if (EBPF_OBJECT_REFERENCE_BY_HANDLE(handle, EBPF_OBJECT_MAP, (ebpf_core_object_t**)&map) ==
                    EBPF_SUCCESS) {
                    maps[def.type] = map;
                    if (def.type == BPF_MAP_TYPE_PROG_ARRAY) {
                        prog_array_map = map;
                    }
                }
            }
        }
    }
    ~fuzz_wrapper()
    {
        for (auto& [_, map] : maps) {
            EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)map);
        }
        for (auto& handle : handles) {
            // Ignore invalid handle close.
            // Fuzzing may have already closed this handle.
            (void)ebpf_handle_close(handle);
        };
        program_information_providers.clear();
        ebpf_core_terminate();
    }

    ebpf_handle_t
    get_program_handle()
    {
        return handles[0];
    }

    _Ret_maybenull_ ebpf_map_t*
    get_map(ebpf_map_type_t type)
    {
        return maps.contains(type) ? maps[type] : nullptr;
    }

    _Ret_maybenull_ ebpf_map_t*
    get_prog_array_map()
    {
        return prog_array_map;
    }

  private:
    std::vector<std::unique_ptr<_program_info_provider>> program_information_providers;
    std::vector<ebpf_handle_t> handles;
    std::map<ebpf_map_type_t, ebpf_map_t*> maps;
    ebpf_map_t* prog_array_map = nullptr;
};

_Ret_maybenull_ ebpf_map_definition_in_memory_t*
get_map_definition(ebpf_map_type_t type)
{
    for (auto& [_, m] : _map_definitions) {
        if (m.type == type) {
            return &m;
        }
    }
    return nullptr;
}

FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int*, char***) { return 0; }

// Generic helper prototypes.
typedef uint64_t (*function0_t)();
typedef uint64_t (*function1_t)(uint64_t r1);
typedef uint64_t (*function2_t)(uint64_t r1, uint64_t r2);
typedef uint64_t (*function3_t)(uint64_t r1, uint64_t r2, uint64_t r3);
typedef uint64_t (*function4_t)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4);
typedef uint64_t (*function5_t)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);

// Consume the next output_size bytes from the input data and save them in the supplied output buffer.
bool
consume_data(const uint8_t** input, size_t* input_size, _Out_writes_(output_size) uint8_t* output, size_t output_size)
{
    if (*input_size < output_size) {
        return false;
    }
    memcpy(output, *input, output_size);
    *input += output_size;
    *input_size -= output_size;
    return true;
}

// For testing purposes, use up to 64-byte buffers for things like csum diff.
#define MAX_BUFFER_SIZE 64

void
fuzz_program(
    fuzz_wrapper& fuzz_state,
    ebpf_handle_t program_handle,
    _In_ const ebpf_program_t* program,
    _In_reads_(data_left_size) const uint8_t* data_left,
    size_t data_left_size)
{
    // Get the set of helper function prototypes.
    ebpf_program_info_t* program_info = nullptr;
    ebpf_result_t result = ebpf_program_get_program_info(program, &program_info);
    if (result != EBPF_SUCCESS) {
        return;
    }

    // Get helper index.
    uint8_t helper_index;
    if (!consume_data(&data_left, &data_left_size, &helper_index, sizeof(helper_index)) ||
        (helper_index >= program_info->count_of_program_type_specific_helpers)) {
        // No such helper id.
        return;
    }
    const ebpf_helper_function_prototype_t* prototype =
        &program_info->program_type_specific_helper_prototype[helper_index];

    // Get the helper function pointer.
    ebpf_helper_id_t helper_function_id = (ebpf_helper_id_t)prototype->helper_id;
    uint64_t helper_function_address = 0;
    result =
        ebpf_core_resolve_helper(program_handle, 1, (const uint32_t*)&helper_function_id, &helper_function_address);
    if (result != EBPF_SUCCESS) {
        return;
    }

    // Declare some memory usable when calling a helper.
    uint8_t packet_buffer[MAX_BUFFER_SIZE] = {0};
    std::vector<uint8_t> packet{packet_buffer, packet_buffer + sizeof(packet_buffer)};
    xdp_md_helper_t xdp_helper(packet);
    char writable_buffer[MAX_BUFFER_SIZE] = {0};
    int readable_buffer_index = 0;
    char readable_buffer[2][MAX_BUFFER_SIZE];
    char map_key[MAX_BUFFER_SIZE];
    char map_value[MAX_BUFFER_SIZE];
    ebpf_map_type_t map_type = BPF_MAP_TYPE_UNSPEC;

    // Fill args based on data supplied by the fuzzer.
    uint64_t argument[5] = {0};
    int arg_count = 0;
    while (arg_count < 5) {
        ebpf_argument_type_t type = prototype->arguments[arg_count];
        if (type == EBPF_ARGUMENT_TYPE_DONTCARE) {
            break;
        }
        switch (type) {
        case EBPF_ARGUMENT_TYPE_ANYTHING: {
            // Fill the argument with supplied data.
            if (!consume_data(
                    &data_left, &data_left_size, (uint8_t*)&argument[arg_count], sizeof(argument[arg_count]))) {
                return;
            }
            break;
        }
        case EBPF_ARGUMENT_TYPE_CONST_SIZE: {
            assert(arg_count > 0);
            assert(argument[arg_count - 1] != 0);
            if (arg_count == 0 || argument[arg_count - 1] == 0) {
                // Should never happen but we need to keep analysis build happy.
                return;
            }

            // Put the supplied size into the argument.
            uint8_t arg_size;
            if (!consume_data(&data_left, &data_left_size, (uint8_t*)&arg_size, sizeof(arg_size)) || (arg_size == 0) ||
                (arg_size > MAX_BUFFER_SIZE)) {
                return;
            }
            argument[arg_count] = arg_size;

            // Put the supplied data into the previous argument.
            if (!consume_data(&data_left, &data_left_size, (uint8_t*)argument[arg_count - 1], arg_size)) {
                return;
            }
            break;
        }
        case EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: {
            assert(arg_count > 0);
            assert(argument[arg_count - 1] != 0);
            if (arg_count == 0 || argument[arg_count - 1] == 0) {
                // Should never happen but we need to keep analysis build happy.
                return;
            }

            // Put the supplied size into the argument.
            uint8_t arg_size;
            if (!consume_data(&data_left, &data_left_size, (uint8_t*)&arg_size, sizeof(arg_size)) ||
                (arg_size > MAX_BUFFER_SIZE)) {
                return;
            }
            argument[arg_count] = arg_size;
            if (arg_size == 0) {
                // Set the previous argument to NULL.
                if (prototype->arguments[arg_count - 1] == EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL) {
                    argument[arg_count - 1] = 0;
                }
            } else {
                // Put the supplied data into the previous argument.
                if (!consume_data(&data_left, &data_left_size, (uint8_t*)argument[arg_count - 1], arg_size)) {
                    return;
                }
            }
            break;
        }
        case EBPF_ARGUMENT_TYPE_PTR_TO_CTX:
            // Put the context into the argument.
            argument[arg_count] = (uint64_t)&xdp_helper;
            break;
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP: {
            // Put a map pointer into the argument.
            uint8_t index;
            if (!consume_data(&data_left, &data_left_size, &index, sizeof(index))) {
                return;
            }
            map_type = (ebpf_map_type_t)index;
            argument[arg_count] = (uint64_t)fuzz_state.get_map(map_type);
            if (argument[arg_count] == 0) {
                return;
            }
            break;
        }
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY: {
            // Put the supplied data into the argument.
            ebpf_map_definition_in_memory_t* definition = get_map_definition(map_type);
            if ((definition == nullptr) ||
                !consume_data(&data_left, &data_left_size, (uint8_t*)&map_key, definition->key_size)) {
                return;
            }
            argument[arg_count] = (uint64_t)map_key;
            break;
        }
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS:
            // Put the PROG_ARRAY map pointer into the argument.
            argument[arg_count] = (uint64_t)fuzz_state.get_prog_array_map();
            break;
        case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE: {
            // Put the supplied data into the argument.
            ebpf_map_definition_in_memory_t* definition = get_map_definition(map_type);
            if ((definition == nullptr) ||
                !consume_data(&data_left, &data_left_size, (uint8_t*)&map_value, definition->value_size)) {
                return;
            }
            argument[arg_count] = (uint64_t)map_value;
            break;
        }
        case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM:
            // Put a pointer to the next readable buffer into the argument.
            argument[arg_count] = (uint64_t)readable_buffer[readable_buffer_index++];
            break;
        case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL:
            // Put a pointer to the next readable buffer into the argument.
            argument[arg_count] = (uint64_t)readable_buffer[readable_buffer_index++];
            break;
        case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM:
            // Put a pointer to the writable buffer into the argument.
            argument[arg_count] = (uint64_t)writable_buffer;
            break;
        }
        arg_count++;
    }
    if (data_left_size > 0) {
        // Fuzzer supplied too much data.
        return;
    }

    // Call into the helper.
    switch (arg_count) {
    case 0:
        ((function0_t)helper_function_address)();
        break;
    case 1:
        ((function1_t)helper_function_address)(argument[0]);
        break;

    case 2:
        ((function2_t)helper_function_address)(argument[0], argument[1]);
        break;
    case 3:
        ((function3_t)helper_function_address)(argument[0], argument[1], argument[2]);
        break;
    case 4:
        ((function4_t)helper_function_address)(argument[0], argument[1], argument[2], argument[3]);
        break;
    case 5:
        ((function5_t)helper_function_address)(argument[0], argument[1], argument[2], argument[3], argument[4]);
        break;
    }
}

FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    ebpf_watchdog_timer_t watchdog_timer;

    // Get the program.
    fuzz_wrapper fuzz_state;
    netebpf_ext_helper_t helper;
    fuzz_state.make_program(EBPF_PROGRAM_TYPE_XDP);
    ebpf_handle_t program_handle = fuzz_state.get_program_handle();
    ebpf_program_t* program = NULL;
    ebpf_result_t result =
        EBPF_OBJECT_REFERENCE_BY_HANDLE(program_handle, EBPF_OBJECT_PROGRAM, (ebpf_core_object_t**)&program);
    if (result != EBPF_SUCCESS) {
        return 0;
    }

    fuzz_program(fuzz_state, program_handle, program, data, size);

    EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)program);

    return 0; // Non-zero return values are reserved for future use.
}
