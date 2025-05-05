// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_core.h"
#include "ebpf_handle.h"
#include "ebpf_program.h"
#include "ebpf_vm_isa.hpp"
#include "helpers.h"
#include "libfuzzer.h"
#include "platform.h"

#include <chrono>
#include <condition_variable>
#include <ebpf_epoch.h>
#include <filesystem>
#include <map>
#include <mutex>
#include <vector>

using namespace prevail;

extern "C"
{
    _Must_inspect_result_ ebpf_result_t
    ebpf_core_initiate_pinning_table();

    void
    ebpf_core_terminate_pinning_table();
}

#define REQUIRE(X)                 \
    {                              \
        bool x = (X);              \
        UNREFERENCED_PARAMETER(x); \
    }

extern "C" size_t cxplat_fuzzing_memory_limit;

static std::vector<std::pair<GUID, GUID>> _program_types = {
    {
        EBPF_PROGRAM_TYPE_XDP,
        EBPF_ATTACH_TYPE_XDP,
    },
    {
        EBPF_PROGRAM_TYPE_BIND,
        EBPF_ATTACH_TYPE_BIND,
    },
    {
        EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR,
        EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT,
    },
    {
        EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR,
        EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT,
    },
    {
        EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR,
        EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT,
    },
    {
        EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR,
        EBPF_ATTACH_TYPE_CGROUP_INET6_RECV_ACCEPT,
    },
    {
        EBPF_PROGRAM_TYPE_SOCK_OPS,
        EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS,
    },
    {
        EBPF_PROGRAM_TYPE_SAMPLE,
        EBPF_ATTACH_TYPE_SAMPLE,
    }};

static std::vector<std::pair<std::string, ebpf_map_definition_in_memory_t>> _map_definitions = {
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
            sizeof(ebpf_id_t),
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
            sizeof(ebpf_id_t),
            10,
        },
    },
    {
        "BPF_MAP_TYPE_ARRAY_OF_MAPS",
        {
            BPF_MAP_TYPE_ARRAY_OF_MAPS,
            4,
            sizeof(ebpf_id_t),
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
            4,
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

typedef class _hook_provider
{
  public:
    _hook_provider(ebpf_program_type_t program_type, ebpf_attach_type_t attach_type)
        : client_binding_context(nullptr), client_data(nullptr), client_dispatch_table(nullptr),
          client_registration_instance(nullptr), nmr_binding_handle(nullptr), nmr_provider_handle(nullptr)
    {
        attach_provider_data.header.version = EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION;
        attach_provider_data.header.size = EBPF_ATTACH_PROVIDER_DATA_CURRENT_VERSION_SIZE;
        attach_provider_data.supported_program_type = program_type;
        attach_provider_data.bpf_attach_type = BPF_ATTACH_TYPE_UNSPEC;
        this->attach_type = attach_type;
        module_id.Guid = attach_type;
    }
    ebpf_result_t
    initialize()
    {
        NTSTATUS status = NmrRegisterProvider(&provider_characteristics, this, &nmr_provider_handle);
        return (status == STATUS_SUCCESS) ? EBPF_SUCCESS : EBPF_FAILED;
    }
    ~_hook_provider()
    {
        // Best effort cleanup. Ignore errors.
        if (nmr_provider_handle != NULL) {
            NTSTATUS status = NmrDeregisterProvider(nmr_provider_handle);
            if (status == STATUS_PENDING) {
                NmrWaitForProviderDeregisterComplete(nmr_provider_handle);
            } else {
                ebpf_assert(status == STATUS_SUCCESS);
            }
        }
    }

  private:
    static NTSTATUS
    provider_attach_client_callback(
        HANDLE nmr_binding_handle,
        _Inout_ void* provider_context,
        _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
        _In_ const void* client_binding_context,
        _In_ const void* client_dispatch,
        _Out_ void** provider_binding_context,
        _Out_ const void** provider_dispatch)
    {
        auto hook = reinterpret_cast<_hook_provider*>(provider_context);

        hook->client_registration_instance = client_registration_instance;
        hook->client_binding_context = client_binding_context;
        hook->nmr_binding_handle = nmr_binding_handle;
        hook->client_dispatch_table = (ebpf_extension_dispatch_table_t*)client_dispatch;
        *provider_binding_context = provider_context;
        *provider_dispatch = NULL;
        return STATUS_SUCCESS;
    };

    static NTSTATUS
    provider_detach_client_callback(_Inout_ void* provider_binding_context)
    {
        auto hook = reinterpret_cast<_hook_provider*>(provider_binding_context);
        hook->client_binding_context = nullptr;
        hook->client_data = nullptr;
        hook->client_dispatch_table = nullptr;

        // There should be no in-progress calls to any client functions,
        // we can return success rather than pending.
        return EBPF_SUCCESS;
    };

    ebpf_attach_type_t attach_type;
    ebpf_attach_provider_data_t attach_provider_data;

    NPI_MODULEID module_id = {
        sizeof(NPI_MODULEID),
        MIT_GUID,
    };
    const NPI_PROVIDER_CHARACTERISTICS provider_characteristics = {
        0,
        sizeof(provider_characteristics),
        (NPI_PROVIDER_ATTACH_CLIENT_FN*)provider_attach_client_callback,
        (NPI_PROVIDER_DETACH_CLIENT_FN*)provider_detach_client_callback,
        NULL,
        {
            0,
            sizeof(NPI_REGISTRATION_INSTANCE),
            &EBPF_HOOK_EXTENSION_IID,
            &module_id,
            0,
            &attach_provider_data,
        },
    };
    HANDLE nmr_provider_handle;

    PNPI_REGISTRATION_INSTANCE client_registration_instance = nullptr;
    const void* client_binding_context = nullptr;
    const ebpf_extension_data_t* client_data = nullptr;
    const ebpf_extension_dispatch_table_t* client_dispatch_table = nullptr;
    HANDLE nmr_binding_handle = nullptr;
} hook_provider_t;

class fuzz_wrapper_global_state
{
  public:
    fuzz_wrapper_global_state()
    {
        ebpf_result_t result = ebpf_core_initiate();
        if (result != EBPF_SUCCESS) {
            throw std::runtime_error("ebpf_core_initiate failed");
        }

        for (const auto& type : _program_types) {
            program_information_providers.push_back(std::make_unique<_program_info_provider>());
            if (program_information_providers.back()->initialize(type.first) != EBPF_SUCCESS) {
                throw std::runtime_error("program_info initialization failed");
            }
            hook_providers.push_back(std::make_unique<hook_provider_t>(type.first, type.second));
            if (hook_providers.back()->initialize() != EBPF_SUCCESS) {
                throw std::runtime_error("hook provider initialization failed");
            }
        }
    }
    ~fuzz_wrapper_global_state() { ebpf_core_terminate(); }

  private:
    std::vector<std::unique_ptr<_program_info_provider>> program_information_providers;
    std::vector<std::unique_ptr<hook_provider_t>> hook_providers;
};

class fuzz_wrapper
{
  public:
    fuzz_wrapper()
    {
        for (const auto& type : _program_types) {
            std::string name = "program name";
            std::string file = "file name";
            std::string section = "section name";
            ebpf_program_parameters_t params{
                type.first,
                type.second,
                {reinterpret_cast<uint8_t*>(name.data()), name.size()},
                {reinterpret_cast<uint8_t*>(section.data()), section.size()},
                {reinterpret_cast<uint8_t*>(file.data()), file.size()},
                EBPF_CODE_EBPF};
            ebpf_handle_t handle;
            if (ebpf_program_create_and_initialize(&params, &handle) == EBPF_SUCCESS) {
                handles.push_back(handle);
            } else {
                throw std::runtime_error("create of program failed");
            }

            // BPF program that sets r0 to 0 and returns.
            prevail::EbpfInst instructions[] = {
                {
                    .opcode = 0xb4, // mov r0, 0
                },
                {
                    .opcode = 0x95, // exit
                }};

            if (ebpf_core_load_code(
                    handle, EBPF_CODE_EBPF, nullptr, reinterpret_cast<uint8_t*>(instructions), sizeof(instructions)) !=
                EBPF_SUCCESS) {
                throw std::runtime_error("load code failed");
            }
        }
        std::map<ebpf_map_type_t, ebpf_id_t> map_to_id;
        std::map<ebpf_map_type_t, ebpf_handle_t> map_to_handle;
        for (const auto& [name, def] : _map_definitions) {
            cxplat_utf8_string_t utf8_name{reinterpret_cast<uint8_t*>(const_cast<char*>(name.data())), name.size()};
            ebpf_handle_t handle;
            ebpf_handle_t inner_map_handle = ebpf_handle_invalid;
            ebpf_map_definition_in_memory_t modified_def = def;

            if ((def.type == BPF_MAP_TYPE_ARRAY_OF_MAPS) || (def.type == BPF_MAP_TYPE_HASH_OF_MAPS)) {
                modified_def.inner_map_id = map_to_id[BPF_MAP_TYPE_HASH];
                inner_map_handle = map_to_handle[BPF_MAP_TYPE_HASH];
            }

            if (ebpf_core_create_map(&utf8_name, &modified_def, inner_map_handle, &handle) == EBPF_SUCCESS) {
                handles.push_back(handle);
            } else {
                throw std::runtime_error("create of map " + name + " failed");
            }

            ebpf_id_t id;
            ebpf_object_type_t type;
            if (ebpf_core_get_id_and_type_from_handle(handle, &id, &type) != EBPF_SUCCESS) {
                throw std::runtime_error("get id and type from handle failed");
            }

            map_to_id[def.type] = id;
            map_to_handle[def.type] = handle;
        }

        // Associate all maps with all programs.
        // First convert map_to_handle to vector of handles.
        std::vector<ebpf_handle_t> map_handles;
        std::vector<uintptr_t> map_addresses;
        for (const auto& [type, handle] : map_to_handle) {
            if (type == BPF_MAP_TYPE_PROG_ARRAY) {
                continue;
            }
            map_handles.push_back(handle);
        }
        map_addresses.resize(map_handles.size());
        for (size_t i = 0; i < _program_types.size(); i++) {
            if (ebpf_core_resolve_maps(
                    handles[i], static_cast<uint32_t>(map_handles.size()), map_handles.data(), map_addresses.data()) !=
                EBPF_SUCCESS) {
                throw std::runtime_error("resolve maps failed");
            }
        }

        // Create links for all programs.
        for (size_t i = 0; i < _program_types.size(); i++) {
            std::vector<uint8_t> request_buffer;
            std::vector<uint8_t> reply_buffer;

            request_buffer.resize(EBPF_OFFSET_OF(ebpf_operation_link_program_request_t, data) + sizeof(ebpf_id_t));
            reply_buffer.resize(sizeof(ebpf_operation_link_program_reply_t));
            auto request = reinterpret_cast<ebpf_operation_link_program_request_t*>(request_buffer.data());
            auto reply = reinterpret_cast<ebpf_operation_link_program_reply_t*>(reply_buffer.data());

            request->header.id = EBPF_OPERATION_LINK_PROGRAM;
            request->header.length = static_cast<uint16_t>(request_buffer.size());
            request->attach_type = _program_types[i].second;
            request->program_handle = handles[i];

            if (ebpf_core_invoke_protocol_handler(
                    EBPF_OPERATION_LINK_PROGRAM,
                    request_buffer.data(),
                    static_cast<uint16_t>(request_buffer.size()),
                    reply_buffer.data(),
                    static_cast<uint16_t>(reply_buffer.size()),
                    nullptr,
                    nullptr) != EBPF_SUCCESS) {
                throw std::runtime_error("unable to link");
            }

            handles.push_back(reply->link_handle);
        }
    }
    ~fuzz_wrapper()
    {
        ebpf_handle_table_terminate();
        ebpf_core_terminate_pinning_table();
        ebpf_object_tracking_terminate();
        ebpf_epoch_synchronize();
        ebpf_object_tracking_initiate();
        ebpf_assert(ebpf_core_initiate_pinning_table() == EBPF_SUCCESS);
        ebpf_assert(ebpf_handle_table_initiate() == EBPF_SUCCESS);
    }

  private:
    std::vector<ebpf_handle_t> handles;
};

std::unique_ptr<fuzz_wrapper_global_state> _fuzz_wrapper_global_state;

void
fuzz_ioctl(std::vector<uint8_t>& random_buffer)
{
    fuzz_wrapper fuzz_state;
    bool async = false;
    std::vector<uint8_t> request;
    std::vector<uint8_t> reply;
    uint16_t reply_buffer_length = 0;
    std::vector<ebpf_id_t> ids;

    {
        std::unique_lock<std::mutex> lock(_ebpf_fuzzer_async_mutex);
        _ebpf_fuzzer_async_done = false;
    }

    // The seed contains the following:
    // 1. The first 2 bytes are used to determine the length of the reply buffer.
    // 2. The rest of the seed is used to generate the random buffer.

    if (random_buffer.size() < sizeof(uint16_t)) {
        return;
    }

    reply_buffer_length = reinterpret_cast<uint16_t*>(random_buffer.data())[0];
    reply.resize(reply_buffer_length);

    // Move past the first 2 bytes.
    random_buffer.erase(random_buffer.begin(), random_buffer.begin() + sizeof(uint16_t));

    if (random_buffer.size() < sizeof(ebpf_operation_header_t)) {
        return;
    }

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

    // To prevent the emulated kernel from writing to a random location, we need to ensure that the
    // map_ids pointer points to a valid memory location. We will allocate memory for the map_ids
    // and set the pointer to it in the request.
    // The size is set by libfuzzer.
    if (operation_id == EBPF_OPERATION_GET_OBJECT_INFO) {
        ebpf_operation_get_object_info_request_t* info_request =
            reinterpret_cast<ebpf_operation_get_object_info_request_t*>(random_buffer.data());
        if (header->length > EBPF_OFFSET_OF(ebpf_operation_get_object_info_request_t, info)) {
            uint16_t length = header->length - EBPF_OFFSET_OF(ebpf_operation_get_object_info_request_t, info);
            if (length >= sizeof(bpf_prog_info)) {
                bpf_prog_info* info = reinterpret_cast<bpf_prog_info*>(info_request->info);

                // Cap nr_map_ids to 1 million to prevent OOM.
                info->nr_map_ids = info->nr_map_ids & 0xFFFFF;
                // Set the pointer to user allocated memory.
                ids.resize(info->nr_map_ids);
                info->map_ids = reinterpret_cast<uintptr_t>(ids.data());
            }
        }
    }

    // Limit maximum test runs to 1024 while fuzzing to prevent timeouts.
    if (operation_id == EBPF_OPERATION_PROGRAM_TEST_RUN) {
        ebpf_operation_program_test_run_request_t* test_request =
            reinterpret_cast<ebpf_operation_program_test_run_request_t*>(random_buffer.data());
        if (header->length >= EBPF_OFFSET_OF(ebpf_operation_program_test_run_request_t, data)) {
            if (test_request->repeat_count > 1024) {
                test_request->repeat_count = 1024;
            }
        }
    }

    // Intentionally ignoring minimum_request_size and minimum_reply_size.
    result = ebpf_core_invoke_protocol_handler(
        operation_id,
        random_buffer.data(),
        static_cast<uint16_t>(random_buffer.size()),
        reply.size() ? reply.data() : nullptr,
        static_cast<uint16_t>(reply.size()),
        async ? &async : nullptr,
        async ? &fuzz_async_completion : nullptr);

    if ((result == EBPF_PENDING) && async) {
        {
            // Wait 10s for async operation to complete.
            std::unique_lock<std::mutex> lock(_ebpf_fuzzer_async_mutex);
            _ebpf_fuzzer_async_cv.wait_for(lock, std::chrono::seconds(10), []() { return _ebpf_fuzzer_async_done; });
        }
        ebpf_core_cancel_protocol_handler(&async);
        {
            std::unique_lock<std::mutex> lock(_ebpf_fuzzer_async_mutex);
            _ebpf_fuzzer_async_cv.wait(lock, []() { return _ebpf_fuzzer_async_done; });
        }
    }
}

// Disable program invocation for fuzzing.
extern "C" bool ebpf_program_disable_invoke;

FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int*, char***)
{
    cxplat_fuzzing_memory_limit = 1024 * 1024 * 10;
    ebpf_program_disable_invoke = true;
    _fuzz_wrapper_global_state = std::make_unique<fuzz_wrapper_global_state>();
    // Ensure that the ebpfcore runtime is stopped before the usersim runtime.
    atexit([]() { _fuzz_wrapper_global_state.reset(); });
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
