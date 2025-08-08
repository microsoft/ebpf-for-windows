// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_async.h"
#include "ebpf_core.h"
#include "ebpf_maps.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "ebpf_program_attach_type_guids.h"
#include "ebpf_ring_buffer.h"

#ifdef __cplusplus

extern bool _ebpf_platform_code_integrity_enabled;

template <typename T> class ebpf_object_deleter
{
  public:
    void
    operator()(T* object)
    {
        ebpf_object_release_reference(reinterpret_cast<ebpf_core_object_t*>(object), EBPF_FILE_ID_EXECUTION_CONTEXT_UNIT_TESTS, __LINE__);
    }
};

#if !defined(CONFIG_BPF_JIT_DISABLED)
typedef struct _free_trampoline_table
{
    void
    operator()(_In_opt_ _Post_invalid_ ebpf_trampoline_table_t* table)
    {
        if (table != nullptr) {
            ebpf_free_trampoline_table(table);
        }
    }
} free_trampoline_table_t;

typedef std::unique_ptr<ebpf_trampoline_table_t, free_trampoline_table_t> ebpf_trampoline_table_ptr;
#endif

typedef std::unique_ptr<ebpf_map_t, ebpf_object_deleter<ebpf_map_t>> map_ptr;
typedef std::unique_ptr<ebpf_program_t, ebpf_object_deleter<ebpf_program_t>> program_ptr;
typedef std::unique_ptr<ebpf_link_t, ebpf_object_deleter<ebpf_link_t>> link_ptr;

typedef class _ebpf_async_wrapper
{
  public:
    _ebpf_async_wrapper();
    ~_ebpf_async_wrapper();

    ebpf_result_t
    get_result();

    bool
    get_completed();

    size_t
    get_reply_size();

    void
    wait();

  private:
    static void
    completion_callback(_In_ void* context, size_t reply_size, ebpf_result_t result);
    
    ebpf_result_t _result = EBPF_SUCCESS;
    size_t _reply_size = 0;
    bool _completed = false;
    HANDLE _event;
} ebpf_async_wrapper_t;

class _ebpf_core_initializer
{
  public:
    void
    initialize();
    ~_ebpf_core_initializer();
};

typedef struct empty_reply
{
} empty_reply_t;

static empty_reply_t _empty_reply;
typedef std::vector<uint8_t> ebpf_protocol_buffer_t;

// Template must be implemented at instantiation time.
template <typename request_t, typename reply_t = empty_reply_t>
_Must_inspect_result_ ebpf_result_t
invoke_protocol(
    ebpf_operation_id_t operation_id,
    request_t& request,
    reply_t& reply = _empty_reply,
    _Inout_opt_ void* async = nullptr)
{
    uint32_t request_size;
    void* request_ptr;
    uint32_t reply_size;
    void* reply_ptr;
    bool variable_reply_size = false;

    if constexpr (std::is_same<request_t, nullptr_t>::value) {
        request_size = 0;
        request_ptr = nullptr;
    } else if constexpr (std::is_same<request_t, ebpf_protocol_buffer_t>::value) {
        request_size = static_cast<uint32_t>(request.size());
        request_ptr = request.data();
    } else {
        request_size = sizeof(request);
        request_ptr = &request;
    }

    if constexpr (std::is_same<reply_t, nullptr_t>::value) {
        reply_size = 0;
        reply_ptr = nullptr;
    } else if constexpr (std::is_same<reply_t, ebpf_protocol_buffer_t>::value) {
        reply_size = static_cast<uint32_t>(reply.size());
        reply_ptr = reply.data();
        variable_reply_size = true;
    } else if constexpr (std::is_same<reply_t, empty_reply>::value) {
        reply_size = 0;
        reply_ptr = nullptr;
    } else {
        reply_size = static_cast<uint32_t>(sizeof(reply));
        reply_ptr = &reply;
    }
    auto header = reinterpret_cast<ebpf_operation_header_t*>(request_ptr);
    header->id = operation_id;
    header->length = static_cast<uint16_t>(request_size);

    auto completion = [](void*, size_t, ebpf_result_t) {};

    return ebpf_core_invoke_protocol_handler(
        operation_id,
        request_ptr,
        static_cast<uint16_t>(request_size),
        reply_ptr,
        static_cast<uint16_t>(reply_size),
        async,
        completion);
}

void
create_various_objects(std::vector<ebpf_handle_t>& program_handles, std::map<std::string, ebpf_handle_t>& map_handles);

extern std::vector<GUID> _program_types;
extern std::map<std::string, ebpf_map_definition_in_memory_t> _map_definitions;

#define NEGATIVE_TEST_PROLOG()                                                        \
    _ebpf_core_initializer core;                                                      \
    core.initialize();                                                                \
    std::vector<std::unique_ptr<_program_info_provider>> program_info_providers;      \
    for (const auto& type : _program_types) {                                         \
        program_info_providers.push_back(std::make_unique<_program_info_provider>()); \
        REQUIRE(program_info_providers.back()->initialize(type) == EBPF_SUCCESS);     \
    }                                                                                 \
    std::vector<ebpf_handle_t> program_handles;                                       \
    std::map<std::string, ebpf_handle_t> map_handles;                                 \
    create_various_objects(program_handles, map_handles);

extern "C"
{
#endif

#define TEST_FUNCTION_RETURN 42
#define TOTAL_HELPER_COUNT 3

#if defined(CONFIG_BPF_JIT_DISABLED) || defined(CONFIG_BPF_INTERPRETER_DISABLED)
void
test_blocked_by_policy(ebpf_operation_id_t operation);
#endif

#ifdef __cplusplus
}
#endif