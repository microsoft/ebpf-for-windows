// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_core.h"
#include "ebpf_handle.h"
#include "ebpf_program.h"
#include "helpers.h"
#include "libfuzzer.h"
#include "platform.h"

#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <map>
#include <mutex>
#include <vector>

#define REQUIRE(X)                 \
    {                              \
        bool x = (X);              \
        UNREFERENCED_PARAMETER(x); \
    }

extern "C" size_t ebpf_fuzzing_memory_limit;

static std::vector<GUID> _program_types = {
    EBPF_PROGRAM_TYPE_XDP,
    EBPF_PROGRAM_TYPE_BIND,
    EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR,
    EBPF_PROGRAM_TYPE_SOCK_OPS,
    EBPF_PROGRAM_TYPE_SAMPLE};

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
        "BPF_MAP_TYPE_PERCPU_ARRAY",
        {
            BPF_MAP_TYPE_PERCPU_ARRAY,
            0,
            20,
            10,
        },
    },
};

static std::mutex _ebpf_fuzzer_async_mutex;
static std::condition_variable _ebpf_fuzzer_async_cv;
static bool _ebpf_fuzzer_async_done = false;

void
fuzz_async_completion(void*, size_t, ebpf_result_t)
{
    std::unique_lock<std::mutex> lock(_ebpf_fuzzer_async_mutex);
    _ebpf_fuzzer_async_done = true;
    _ebpf_fuzzer_async_cv.notify_all();
};

class fuzz_wrapper
{
  public:
    fuzz_wrapper()
    {
        ebpf_result_t result = ebpf_core_initiate();
        if (result != EBPF_SUCCESS) {
            throw std::runtime_error("ebpf_core_initiate failed");
        }
        for (const auto& type : _program_types) {
            program_information_providers.push_back(std::make_unique<_program_info_provider>());
            if (program_information_providers.back()->initialize(type) != EBPF_SUCCESS) {
                throw std::runtime_error("program_info initialization failed");
            }
        }
        for (const auto& type : _program_types) {
            std::string name = "program name";
            std::string file = "file name";
            std::string section = "section name";
            ebpf_program_parameters_t params{
                type,
                type,
                {reinterpret_cast<uint8_t*>(name.data()), name.size()},
                {reinterpret_cast<uint8_t*>(section.data()), section.size()},
                {reinterpret_cast<uint8_t*>(file.data()), file.size()},
                EBPF_CODE_JIT};
            ebpf_handle_t handle;
            if (ebpf_program_create_and_initialize(&params, &handle) == EBPF_SUCCESS) {
                handles.push_back(handle);
            }
        }
        for (const auto& [name, def] : _map_definitions) {
            cxplat_utf8_string_t utf8_name{reinterpret_cast<uint8_t*>(const_cast<char*>(name.data())), name.size()};
            ebpf_handle_t handle;
            if (ebpf_core_create_map(&utf8_name, &def, ebpf_handle_invalid, &handle) == EBPF_SUCCESS) {
                handles.push_back(handle);
            }
        }
    }
    ~fuzz_wrapper()
    {
        for (auto& handle : handles) {
            // Ignore errors.
            // Fuzzing code is not expected to be correct.
            (void)ebpf_handle_close(handle);
        };
        program_information_providers.clear();
        ebpf_core_terminate();
    }

  private:
    std::vector<std::unique_ptr<_program_info_provider>> program_information_providers;
    std::vector<ebpf_handle_t> handles;
};

void
fuzz_ioctl(std::vector<uint8_t>& random_buffer)
{
    fuzz_wrapper fuzz_state;
    bool async = false;
    std::vector<uint8_t> request;
    std::vector<uint8_t> reply;
    uint16_t reply_buffer_length = 0;

    {
        std::unique_lock<std::mutex> lock(_ebpf_fuzzer_async_mutex);
        _ebpf_fuzzer_async_done = false;
    }

    if (random_buffer.size() < sizeof(ebpf_operation_header_t)) {
        return;
    }

    // Use first 2 bytes of random buffer to determine reply buffer length.
    reply_buffer_length = reinterpret_cast<uint16_t*>(random_buffer.data())[0];
    reply.resize(reply_buffer_length);

    auto header = reinterpret_cast<ebpf_operation_header_t*>(random_buffer.data());
    auto operation_id = header->id;
    header->length = static_cast<uint16_t>(random_buffer.size());

    size_t minimum_request_size;
    size_t minimum_reply_size;

    ebpf_result_t result =
        ebpf_core_get_protocol_handler_properties(operation_id, &minimum_request_size, &minimum_reply_size, &async);
    if (result != EBPF_SUCCESS) {
        return;
    }

    // Intentionally ignoring minimum_request_size and minimum_reply_size.
    result = ebpf_core_invoke_protocol_handler(
        operation_id,
        random_buffer.data(),
        static_cast<uint16_t>(random_buffer.size()),
        reply.data(),
        static_cast<uint16_t>(reply.size()),
        async ? &async : nullptr,
        async ? &fuzz_async_completion : nullptr);

    if ((result == EBPF_PENDING) && async) {
        ebpf_core_cancel_protocol_handler(&async);
        std::unique_lock<std::mutex> lock(_ebpf_fuzzer_async_mutex);
        _ebpf_fuzzer_async_cv.wait(lock, []() { return _ebpf_fuzzer_async_done; });
    }
}

// Disable program invocation for fuzzing.
extern "C" bool ebpf_program_disable_invoke;

FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int*, char***)
{
    ebpf_fuzzing_memory_limit = 1024 * 1024 * 10;
    ebpf_program_disable_invoke = true;
    return 0;
}

FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    ebpf_watchdog_timer_t watchdog_timer;

    std::vector<uint8_t> random_buffer(size);
    memcpy(random_buffer.data(), data, size);

    fuzz_ioctl(random_buffer);

    return 0; // Non-zero return values are reserved for future use.
}
