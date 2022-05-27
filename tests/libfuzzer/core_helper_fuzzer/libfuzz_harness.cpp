// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <Windows.h>

#include <chrono>
#include <filesystem>
#include <map>
#include <vector>

#define REQUIRE(X)                 \
    {                              \
        bool x = (X);              \
        UNREFERENCED_PARAMETER(x); \
    }

#include "ebpf_core.h"
#include "ebpf_handle.h"
#include "ebpf_program.h"
#include "helpers.h"
#include "libfuzzer.h"
#include "platform.h"

#if 0
class program_info
{
  public:

    GUID program_type;
    std::unique_ptr<_program_info_provider> provider;
    ebpf_handle_t program_handle;

        program_info(const GUID& type) {
            program_type = type;
            provider = std::make_unique<_program_info_provider>(type);
            program_handle = ebpf_handle_invalid;
        }
};

static std::vector<std::unique_ptr<program_info>> _program_infos;
#endif

// Currently the only program type with helpers is XDP.
// TODO: but all this does is fuzz the test mock helper, so not very interesting.
static std::vector<GUID> _program_types = {EBPF_PROGRAM_TYPE_XDP};

static std::map<std::string, ebpf_map_definition_in_memory_t> _map_definitions = {
    {
        "BPF_MAP_TYPE_HASH",
        {
            BPF_MAP_TYPE_HASH,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_ARRAY",
        {
            BPF_MAP_TYPE_ARRAY,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_PROG_ARRAY",
        {
            BPF_MAP_TYPE_PROG_ARRAY,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_PERCPU_HASH",
        {
            BPF_MAP_TYPE_PERCPU_HASH,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_PERCPU_ARRAY",
        {
            BPF_MAP_TYPE_PERCPU_ARRAY,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_HASH_OF_MAPS",
        {
            BPF_MAP_TYPE_HASH_OF_MAPS,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_ARRAY_OF_MAPS",
        {
            BPF_MAP_TYPE_ARRAY_OF_MAPS,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_LRU_HASH",
        {
            BPF_MAP_TYPE_LRU_HASH,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_LPM_TRIE",
        {
            BPF_MAP_TYPE_LPM_TRIE,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_QUEUE",
        {
            BPF_MAP_TYPE_QUEUE,
            0,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_LRU_PERCPU_HASH",
        {
            BPF_MAP_TYPE_LRU_PERCPU_HASH,
            4,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_STACK",
        {
            BPF_MAP_TYPE_STACK,
            0,
            20,
            10,
        },
    },
    {
        "BPF_MAP_TYPE_STACK",
        {
            BPF_MAP_TYPE_PERCPU_ARRAY,
            0,
            20,
            10,
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
        ebpf_core_initiate();
        const GUID type = EBPF_PROGRAM_TYPE_XDP;
        _program_info_provider provider(type);
        ebpf_handle_t program_handle;

        std::string program_name = "program name";
        std::string file = "file name";
        std::string section = "section name";
        ebpf_program_parameters_t params{
            type,
            type,
            {reinterpret_cast<uint8_t*>(program_name.data()), program_name.size()},
            {reinterpret_cast<uint8_t*>(file.data()), file.size()},
            {reinterpret_cast<uint8_t*>(section.data()), section.size()},
            EBPF_CODE_JIT};

        if (ebpf_program_create_and_initialize(&params, &program_handle) == EBPF_SUCCESS) {
            handles.push_back(program_handle);
        }
        for (const auto& [name, def] : _map_definitions) {
            ebpf_utf8_string_t utf8_name{reinterpret_cast<uint8_t*>(const_cast<char*>(name.data())), name.size()};
            ebpf_handle_t handle;
            if (ebpf_core_create_map(&utf8_name, &def, ebpf_handle_invalid, &handle) == EBPF_SUCCESS) {
                handles.push_back(handle);
            }
        }
    }
    ~fuzz_wrapper()
    {
        for (auto& handle : handles) {
            ebpf_handle_close(handle);
        };
        program_information_providers.clear();
        ebpf_core_terminate();
    }

    ebpf_handle_t
    get_program_handle()
    {
        return handles[0];
    }

  private:
    std::vector<std::unique_ptr<_program_info_provider>> program_information_providers;
    std::vector<ebpf_handle_t> handles;
};

FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int*, char***) { return 0; }

typedef uint64_t (*function0_t)();
typedef uint64_t (*function1_t)(uint64_t r1);
typedef uint64_t (*function2_t)(uint64_t r1, uint64_t r2);
typedef uint64_t (*function3_t)(uint64_t r1, uint64_t r2, uint64_t r3);
typedef uint64_t (*function4_t)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4);
typedef uint64_t (*function5_t)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);

FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzz_wrapper fuzz_state;

    // Get the program.
    ebpf_handle_t program_handle = fuzz_state.get_program_handle();
    ebpf_program_t* program = NULL;
    ebpf_result_t result =
        ebpf_reference_object_by_handle(program_handle, EBPF_OBJECT_PROGRAM, (ebpf_core_object_t**)&program);
    if (result != EBPF_SUCCESS) {
        return 0;
    }

    // Get the set of helper function prototypes.
    ebpf_program_info_t* program_info = nullptr;
    result = ebpf_program_get_program_info(program, &program_info);
    if (result != EBPF_SUCCESS) {
        ebpf_object_release_reference((ebpf_core_object_t*)program);
        return 0;
    }

#if 1
    // Set the program to use all helper ids.
    uint32_t* helper_function_ids = new uint32_t[program_info->count_of_helpers];
    for (uint32_t i = 0; i < program_info->count_of_helpers; i++) {
        helper_function_ids[i] = program_info->helper_prototype[i].helper_id;
    }

    result = ebpf_program_set_helper_function_ids(program, program_info->count_of_helpers, helper_function_ids);
    if (result != EBPF_SUCCESS) {
        return 0;
    }

    // Get all the helper function pointers.
    uint64_t* helper_function_addresses = new uint64_t[program_info->count_of_helpers];
    memset(helper_function_addresses, 0, program_info->count_of_helpers * sizeof(*helper_function_addresses));
    result =
        ebpf_program_get_helper_function_addresses(program, program_info->count_of_helpers, helper_function_addresses);
    if (result != EBPF_SUCCESS) {
        return 0;
    }
#else
    // Get all the helper function pointers.
    uint32_t* helper_function_ids = new uint32_t[program_info->count_of_helpers];
    for (uint32_t i = 0; i < program_info->count_of_helpers; i++) {
        helper_function_ids[i] = program_info->helper_prototype[i].helper_id;
    }
    uint64_t* helper_function_addresses = new uint64_t[program_info->count_of_helpers];
    memset(helper_function_addresses, 0, program_info->count_of_helpers * sizeof(*helper_function_addresses));
    result = ebpf_core_resolve_helper(
        program_handle, program_info->count_of_helpers, helper_function_ids, helper_function_addresses);
    if (result != EBPF_SUCCESS) {
        return 0;
    }
#endif

    // Call into a helper the same way the interpreter would.
    uint64_t argument[5] = {0};
    for (uint32_t i = 0; i < program_info->count_of_helpers; i++) {
        int arg_count = 0;
        while (arg_count < 5 && program_info->helper_prototype[i].arguments[arg_count] != EBPF_ARGUMENT_TYPE_DONTCARE) {
            arg_count++;
        }

        // TODO: fill args based on data.
        UNREFERENCED_PARAMETER(data);
        UNREFERENCED_PARAMETER(size);

        switch (arg_count) {
        case 0:
            ((function0_t)helper_function_addresses[i])();
            break;
        case 1:
            ((function1_t)helper_function_addresses[i])(argument[0]);
            break;
        case 2: {
            function2_t fcn = (function2_t)helper_function_addresses[i];
            fcn(argument[0], argument[1]);
            break;
        }
        case 3:
            ((function3_t)helper_function_addresses[i])(argument[0], argument[1], argument[2]);
            break;
        case 4:
            ((function4_t)helper_function_addresses[i])(argument[0], argument[1], argument[2], argument[3]);
            break;
        case 5:
            ((function5_t)helper_function_addresses[i])(
                argument[0], argument[1], argument[2], argument[3], argument[4]);
            break;
        }
    }

    ebpf_object_release_reference((ebpf_core_object_t*)program);

    return 0; // Non-zero return values are reserved for future use.
}
