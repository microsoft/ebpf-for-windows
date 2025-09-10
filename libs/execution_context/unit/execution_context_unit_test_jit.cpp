// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "catch_wrapper.hpp"
#include "ebpf_async.h"
#include "ebpf_core.h"
#include "ebpf_maps.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "ebpf_ring_buffer.h"
#include "execution_context_unit_test_jit.h"
#include "helpers.h"
#include "test_helper.hpp"

_ebpf_async_wrapper::_ebpf_async_wrapper()
{
    _event = CreateEvent(nullptr, false, false, nullptr);
    if (_event == INVALID_HANDLE_VALUE) {
        throw std::bad_alloc();
    }
    if (ebpf_async_set_completion_callback(this, _ebpf_async_wrapper::completion_callback) != EBPF_SUCCESS) {
        throw std::runtime_error("ebpf_async_set_completion_callback failed");
    }
}
_ebpf_async_wrapper::~_ebpf_async_wrapper()
{
    if (!_completed) {
        ebpf_async_complete(this, 0, EBPF_CANCELED);
    }
}

ebpf_result_t
_ebpf_async_wrapper::get_result()
{
    return _result;
}

bool
_ebpf_async_wrapper::get_completed()
{
    return _completed;
}

size_t
_ebpf_async_wrapper::get_reply_size()
{
    return _reply_size;
}

void
_ebpf_async_wrapper::wait()
{
    REQUIRE(WaitForSingleObject(_event, INFINITE) == WAIT_OBJECT_0);
}

void
_ebpf_async_wrapper::completion_callback(_In_ void* context, size_t reply_size, ebpf_result_t result)
{
    ebpf_async_wrapper_t* async_wrapper = (ebpf_async_wrapper_t*)context;
    async_wrapper->_result = result;
    async_wrapper->_reply_size = reply_size;
    async_wrapper->_completed = true;
    SetEvent(async_wrapper->_event);
}

void
_ebpf_core_initializer::initialize()
{
    REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
}

_ebpf_core_initializer::~_ebpf_core_initializer()
{
    ebpf_core_terminate();
}

void
create_various_objects(std::vector<ebpf_handle_t>& program_handles, std::map<std::string, ebpf_handle_t>& map_handles)
{
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
            EBPF_CODE_NONE};
        ebpf_handle_t handle;
        REQUIRE(ebpf_program_create_and_initialize(&params, &handle) == EBPF_SUCCESS);
        program_handles.push_back(handle);
    }
    for (const auto& [name, def] : _map_definitions) {
        cxplat_utf8_string_t utf8_name{reinterpret_cast<uint8_t*>(const_cast<char*>(name.data())), name.size()};
        ebpf_handle_t handle;
        ebpf_handle_t inner_handle = ebpf_handle_invalid;
        if (def.inner_map_id != 0) {
            inner_handle = map_handles.begin()->second;
        }
        REQUIRE(ebpf_core_create_map(&utf8_name, &def, inner_handle, &handle) == EBPF_SUCCESS);
        map_handles.insert({name, handle});
    }
}

#if defined(CONFIG_BPF_JIT_DISABLED) || defined(CONFIG_BPF_INTERPRETER_DISABLED)
void
test_blocked_by_policy(ebpf_operation_id_t operation)
{
    NEGATIVE_TEST_PROLOG();

    ebpf_result_t expected_result = EBPF_BLOCKED_BY_POLICY;

    std::vector<uint8_t> request(sizeof(ebpf_operation_header_t));
    std::vector<uint8_t> reply(sizeof(ebpf_operation_header_t));

    REQUIRE(invoke_protocol(operation, request, reply) == expected_result);

    // Use a request buffer larger than ebpf_operation_header_t, and try again.
    request.resize(request.size() + 10);
    REQUIRE(invoke_protocol(operation, request, reply) == expected_result);
}
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
void
test_ebpf_operation_create_program()
{
    NEGATIVE_TEST_PROLOG();

    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data));
    std::vector<uint8_t> reply(sizeof(ebpf_operation_create_program_reply_t));
    auto create_program_request = reinterpret_cast<ebpf_operation_create_program_request_t*>(request.data());
    create_program_request->program_type = _program_types[0];
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    create_program_request->program_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    // No name, no section offset, no filename - Should be permitted.
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_SUCCESS);

    request.resize(request.size() + 10);
    create_program_request = reinterpret_cast<ebpf_operation_create_program_request_t*>(request.data());

    // Section name before start of valid region.
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data) - 1;
    create_program_request->program_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);

    // Program name before start of valid region.
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    create_program_request->program_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data) - 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);

    // Section name past end of valid region.
    create_program_request->section_name_offset = create_program_request->header.length + 1;
    create_program_request->program_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);

    // Section name past end of valid region.
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    create_program_request->program_name_offset = create_program_request->header.length + 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);

    request.resize(request.size() + 1024);
    create_program_request = reinterpret_cast<ebpf_operation_create_program_request_t*>(request.data());

    // Large file name.
    create_program_request->section_name_offset = create_program_request->header.length;
    create_program_request->program_name_offset = create_program_request->header.length;
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);

    // Large section name - Permitted.
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    create_program_request->program_name_offset = create_program_request->header.length;
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_SUCCESS);

    // Large program name.
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    create_program_request->program_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);
}
#else
void
test_ebpf_operation_create_program()
{
    test_blocked_by_policy(EBPF_OPERATION_CREATE_PROGRAM);
}
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("EBPF_OPERATION_LOAD_CODE", "[execution_context][negative]")
{

    // Test with type jit.
    {
        NEGATIVE_TEST_PROLOG();

        ebpf_operation_load_code_request_t load_code_request{
            {sizeof(ebpf_operation_load_code_request_t), EBPF_OPERATION_LOAD_CODE},
            program_handles[0],
            EBPF_CODE_JIT,
            static_cast<uint8_t>('0xcc')};

        // Invalid handle.
        load_code_request.program_handle = ebpf_handle_invalid;
        REQUIRE(invoke_protocol(EBPF_OPERATION_LOAD_CODE, load_code_request) == EBPF_INVALID_OBJECT);
        load_code_request.program_handle = program_handles[0];

        load_code_request.code_type = EBPF_CODE_NATIVE;
        REQUIRE(invoke_protocol(EBPF_OPERATION_LOAD_CODE, load_code_request) == EBPF_INVALID_ARGUMENT);
        load_code_request.code_type = EBPF_CODE_JIT;

        load_code_request.code_type = static_cast<ebpf_code_type_t>(-1);
        REQUIRE(invoke_protocol(EBPF_OPERATION_LOAD_CODE, load_code_request) == EBPF_INVALID_ARGUMENT);
        load_code_request.code_type = EBPF_CODE_JIT;
    }

    // HVCI can only be changed at init time.
    _ebpf_platform_code_integrity_enabled = true;
    {
        NEGATIVE_TEST_PROLOG();

        ebpf_operation_load_code_request_t load_code_request{
            {sizeof(ebpf_operation_load_code_request_t), EBPF_OPERATION_LOAD_CODE},
            program_handles[0],
            EBPF_CODE_JIT,
            static_cast<uint8_t>('0xcc')};

        // HVCI on.
        REQUIRE(invoke_protocol(EBPF_OPERATION_LOAD_CODE, load_code_request) == EBPF_BLOCKED_BY_POLICY);
    }
    _ebpf_platform_code_integrity_enabled = false;
}
#else
TEST_CASE("EBPF_OPERATION_LOAD_CODE", "[execution_context][negative]")
{
    test_blocked_by_policy(EBPF_OPERATION_LOAD_CODE);
}
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED)
void
test_program_context()
{
    // single_instance_hook_t call ebpapi functions, which requires calling ebpf_api_initiate/ebpf_api_terminate.
    _test_helper_end_to_end end_to_end;
    end_to_end.initialize();

    program_info_provider_t program_info_provider;
    REQUIRE(program_info_provider.initialize(EBPF_PROGRAM_TYPE_SAMPLE) == EBPF_SUCCESS);
    const cxplat_utf8_string_t program_name{(uint8_t*)("foo"), 3};
    const cxplat_utf8_string_t section_name{(uint8_t*)("bar"), 3};
    const ebpf_program_parameters_t program_parameters{
        EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE, program_name, section_name};
    program_ptr program;
    {
        ebpf_program_t* local_program = nullptr;
        REQUIRE(ebpf_program_create(&program_parameters, &local_program) == EBPF_SUCCESS);
        program.reset(local_program);
    }

    ebpf_map_definition_in_memory_t map_definition{BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint64_t), 10};
    map_ptr map;
    {
        ebpf_map_t* local_map;
        cxplat_utf8_string_t map_name = {0};
        REQUIRE(
            ebpf_map_create(&map_name, &map_definition, (uintptr_t)ebpf_handle_invalid, &local_map) == EBPF_SUCCESS);
        map.reset(local_map);
    }

    ebpf_program_info_t* program_info;

    ebpf_program_type_t returned_program_type = ebpf_program_type_uuid(program.get());
    REQUIRE(
        memcmp(&program_parameters.program_type, &returned_program_type, sizeof(program_parameters.program_type)) == 0);

    REQUIRE(ebpf_program_get_program_info(program.get(), &program_info) == EBPF_SUCCESS);
    REQUIRE(program_info != nullptr);
    ebpf_program_free_program_info(program_info);

    ebpf_map_t* maps[] = {map.get()};

    REQUIRE(((ebpf_core_object_t*)map.get())->base.reference_count == 1);
    REQUIRE(ebpf_program_associate_maps(program.get(), maps, EBPF_COUNT_OF(maps)) == EBPF_SUCCESS);
    REQUIRE(((ebpf_core_object_t*)map.get())->base.reference_count == 2);

    ebpf_trampoline_table_ptr table;
    ebpf_result_t (*test_function)();
    auto provider_function1 = []() { return (ebpf_result_t)TEST_FUNCTION_RETURN; };
    ebpf_result_t (*function_pointer1)() = provider_function1;
    uint32_t test_function_ids[] = {(EBPF_MAX_GENERAL_HELPER_FUNCTION + 1)};
    const void* helper_functions[] = {(void*)function_pointer1};
    ebpf_helper_function_addresses_t helper_function_addresses = {
        EBPF_HELPER_FUNCTION_ADDRESSES_HEADER, EBPF_COUNT_OF(helper_functions), (uint64_t*)helper_functions};

    {
        ebpf_trampoline_table_t* local_table = nullptr;
        REQUIRE(ebpf_allocate_trampoline_table(1, &local_table) == EBPF_SUCCESS);
        table.reset(local_table);
    }
    REQUIRE(
        ebpf_update_trampoline_table(
            table.get(), EBPF_COUNT_OF(test_function_ids), test_function_ids, &helper_function_addresses) ==
        EBPF_SUCCESS);
    REQUIRE(
        ebpf_get_trampoline_function(
            table.get(), EBPF_MAX_GENERAL_HELPER_FUNCTION + 1, reinterpret_cast<void**>(&test_function)) ==
        EBPF_SUCCESS);

    // Size of the actual function is unknown, but we know the allocation is on page granularity.
    REQUIRE(
        ebpf_program_load_code(
            program.get(), EBPF_CODE_JIT, nullptr, reinterpret_cast<uint8_t*>(test_function), PAGE_SIZE) ==
        EBPF_SUCCESS);
    uint32_t result = 0;
    sample_program_context_header_t ctx_header{0};
    sample_program_context_t* ctx = &ctx_header.context;

    ebpf_execution_context_state_t state{};
    ebpf_get_execution_context_state(&state);
    ebpf_result_t ebpf_result = ebpf_program_invoke(program.get(), ctx, &result, &state);
    REQUIRE(ebpf_result == EBPF_SUCCESS);
    REQUIRE(result == TEST_FUNCTION_RETURN);

    ebpf_program_test_run_options_t options = {0};
    sample_program_context_t in_ctx{0};
    sample_program_context_t out_ctx{0};
    options.repeat_count = 10;
    options.context_in = reinterpret_cast<uint8_t*>(&in_ctx);
    options.context_size_in = sizeof(in_ctx);
    options.context_out = reinterpret_cast<uint8_t*>(&out_ctx);
    options.context_size_out = sizeof(out_ctx);

    ebpf_async_wrapper_t async_context;
    uint64_t unused_completion_context = 0;

    REQUIRE(
        ebpf_program_execute_test_run(
            program.get(),
            &options,
            &async_context,
            &unused_completion_context,
            [](_In_ ebpf_result_t result,
               _In_ const ebpf_program_t* program,
               _In_ const ebpf_program_test_run_options_t* options,
               _Inout_ void* completion_context,
               _Inout_ void* async_context) {
                ebpf_assert(program != nullptr);
                ebpf_assert(options != nullptr);
                ebpf_assert(completion_context != nullptr);
                ebpf_assert(async_context != nullptr);
                ebpf_async_complete(async_context, options->data_size_out, result);
            }) == EBPF_PENDING);

    async_context.wait();
    REQUIRE(async_context.get_result() == EBPF_SUCCESS);
    REQUIRE(async_context.get_completed() == true);

    REQUIRE(options.return_value == TEST_FUNCTION_RETURN);
    REQUIRE(options.duration > 0);

    helper_function_address_t addresses[TOTAL_HELPER_COUNT] = {};
    uint32_t helper_function_ids[] = {1, 3, 2};
    REQUIRE(
        ebpf_program_set_helper_function_ids(program.get(), EBPF_COUNT_OF(helper_function_ids), helper_function_ids) ==
        EBPF_SUCCESS);
    REQUIRE(
        ebpf_program_get_helper_function_addresses(program.get(), EBPF_COUNT_OF(helper_function_ids), addresses) ==
        EBPF_SUCCESS);
    REQUIRE(addresses[0].address != 0);
    REQUIRE(addresses[1].address != 0);
    REQUIRE(addresses[2].address != 0);

    link_ptr link;

    // Correct attach type, but wrong program type.
    {
        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_SAMPLE);
        REQUIRE(hook.initialize() == EBPF_SUCCESS);
        ebpf_link_t* local_link = nullptr;
        REQUIRE(ebpf_link_create(EBPF_ATTACH_TYPE_SAMPLE, nullptr, 0, &local_link) == EBPF_SUCCESS);
        link.reset(local_link);
        REQUIRE(ebpf_link_attach_program(link.get(), program.get()) == EBPF_EXTENSION_FAILED_TO_LOAD);
    }

    // Wrong attach type, but correct program type.
    {
        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_BIND);
        REQUIRE(hook.initialize() == EBPF_SUCCESS);
        ebpf_link_t* local_link = nullptr;
        REQUIRE(ebpf_link_create(EBPF_ATTACH_TYPE_SAMPLE, nullptr, 0, &local_link) == EBPF_SUCCESS);
        link.reset(local_link);
        REQUIRE(ebpf_link_attach_program(link.get(), program.get()) == EBPF_EXTENSION_FAILED_TO_LOAD);
    }

    // Correct attach type and correct program type.
    {
        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_SAMPLE, EBPF_ATTACH_TYPE_SAMPLE);
        REQUIRE(hook.initialize() == EBPF_SUCCESS);
        ebpf_link_t* local_link = nullptr;
        REQUIRE(ebpf_link_create(EBPF_ATTACH_TYPE_SAMPLE, nullptr, 0, &local_link) == EBPF_SUCCESS);
        link.reset(local_link);

        // Attach should succeed.
        REQUIRE(ebpf_link_attach_program(link.get(), program.get()) == EBPF_SUCCESS);

        // Not possible to attach again.

        // First detach should succeed.
        ebpf_link_detach_program(link.get());

        // Second detach should be no-op.
        ebpf_link_detach_program(link.get());
    }

    link.reset();

    ebpf_free_trampoline_table(table.release());
}

// Only run the test if JIT is enabled.
TEST_CASE("program", "[execution_context]")
{
    test_program_context();
}
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED)
// These tests exist to verify ebpf_core's parsing of messages.
// See libbpf_test.cpp for invalid parameter but correctly formed message cases.
TEST_CASE("EBPF_OPERATION_RESOLVE_HELPER", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();

    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_request_t, helper_id) + sizeof(uint32_t));
    std::vector<uint8_t> reply(
        EBPF_OFFSET_OF(ebpf_operation_resolve_helper_reply_t, address) + sizeof(helper_function_address_t));
    auto resolve_helper_request = reinterpret_cast<ebpf_operation_resolve_helper_request_t*>(request.data());

    // Invalid handle.
    resolve_helper_request->program_handle = ebpf_handle_invalid;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_HELPER, request, reply) == EBPF_INVALID_OBJECT);

    // Invalid helper id.
    resolve_helper_request->program_handle = program_handles[0];
    resolve_helper_request->helper_id[0] = UINT32_MAX;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_HELPER, request, reply) == EBPF_INVALID_ARGUMENT);

    reply.resize(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_reply_t, address));
    // Reply too small.
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_HELPER, request, reply) == EBPF_INVALID_ARGUMENT);

    // Set no helper functions.
    request.resize(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_request_t, helper_id));
    resolve_helper_request = reinterpret_cast<ebpf_operation_resolve_helper_request_t*>(request.data());
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_HELPER, request, reply) == EBPF_SUCCESS);

    // Set helper function multiple times.
    request.resize(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_request_t, helper_id) + sizeof(uint32_t));
    reply.resize(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_reply_t, address) + sizeof(uintptr_t));
    resolve_helper_request = reinterpret_cast<ebpf_operation_resolve_helper_request_t*>(request.data());
    resolve_helper_request->program_handle = program_handles[0];
    resolve_helper_request->helper_id[0] = 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_HELPER, request, reply) == EBPF_INVALID_ARGUMENT);
}

TEST_CASE("EBPF_OPERATION_RESOLVE_MAP", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();

    std::vector<uint8_t> request(
        EBPF_OFFSET_OF(ebpf_operation_resolve_map_request_t, map_handle) + sizeof(ebpf_handle_t) * 2);
    std::vector<uint8_t> reply(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_reply_t, address) + sizeof(uintptr_t) * 2);
    auto resolve_map_request = reinterpret_cast<ebpf_operation_resolve_map_request_t*>(request.data());

    // Invalid handle.
    resolve_map_request->program_handle = ebpf_handle_invalid;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_MAP, request, reply) == EBPF_INVALID_OBJECT);

    // 1 invalid map.
    resolve_map_request->program_handle = program_handles[0];
    resolve_map_request->map_handle[0] = ebpf_handle_invalid;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_MAP, request, reply) == EBPF_INVALID_OBJECT);

    resolve_map_request->program_handle = program_handles[0];
    resolve_map_request->map_handle[0] = map_handles["BPF_MAP_TYPE_HASH"];
    resolve_map_request->map_handle[1] = ebpf_handle_invalid;
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_MAP, request, reply) == EBPF_INVALID_OBJECT);

    // Reply too small.
    reply.resize(EBPF_OFFSET_OF(ebpf_operation_resolve_helper_reply_t, address) + sizeof(uintptr_t));
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_MAP, request, reply) == EBPF_INVALID_ARGUMENT);

    // 0 maps.
    request.resize(EBPF_OFFSET_OF(ebpf_operation_resolve_map_request_t, map_handle));
    resolve_map_request = reinterpret_cast<ebpf_operation_resolve_map_request_t*>(request.data());
    resolve_map_request->program_handle = program_handles[0];
    REQUIRE(invoke_protocol(EBPF_OPERATION_RESOLVE_MAP, request, reply) == EBPF_INVALID_ARGUMENT);
}
#else
TEST_CASE("EBPF_OPERATION_RESOLVE_HELPER", "[execution_context][negative]")
{
    test_blocked_by_policy(EBPF_OPERATION_RESOLVE_HELPER);
}

TEST_CASE("EBPF_OPERATION_RESOLVE_MAP", "[execution_context][negative]")
{
    test_blocked_by_policy(EBPF_OPERATION_RESOLVE_MAP);
}
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("EBPF_OPERATION_CREATE_PROGRAM", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();

    std::vector<uint8_t> request(EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data));
    std::vector<uint8_t> reply(sizeof(ebpf_operation_create_program_reply_t));
    auto create_program_request = reinterpret_cast<ebpf_operation_create_program_request_t*>(request.data());
    create_program_request->program_type = _program_types[0];
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    create_program_request->program_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    // No name, no section offset, no filename - Should be permitted.
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_SUCCESS);

    request.resize(request.size() + 10);
    create_program_request = reinterpret_cast<ebpf_operation_create_program_request_t*>(request.data());

    // Section name before start of valid region.
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data) - 1;
    create_program_request->program_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);

    // Program name before start of valid region.
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    create_program_request->program_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data) - 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);

    // Section name past end of valid region.
    create_program_request->section_name_offset = create_program_request->header.length + 1;
    create_program_request->program_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);

    // Section name past end of valid region.
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    create_program_request->program_name_offset = create_program_request->header.length + 1;
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);

    request.resize(request.size() + 1024);
    create_program_request = reinterpret_cast<ebpf_operation_create_program_request_t*>(request.data());

    // Large file name.
    create_program_request->section_name_offset = create_program_request->header.length;
    create_program_request->program_name_offset = create_program_request->header.length;
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);

    // Large section name - Permitted.
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    create_program_request->program_name_offset = create_program_request->header.length;
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_SUCCESS);

    // Large program name.
    create_program_request->section_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    create_program_request->program_name_offset = EBPF_OFFSET_OF(ebpf_operation_create_program_request_t, data);
    REQUIRE(invoke_protocol(EBPF_OPERATION_CREATE_PROGRAM, request, reply) == EBPF_INVALID_ARGUMENT);
}
#else
TEST_CASE("EBPF_OPERATION_CREATE_PROGRAM", "[execution_context][negative]")
{
    test_blocked_by_policy(EBPF_OPERATION_CREATE_PROGRAM);
}
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("EBPF_OPERATION_GET_EC_FUNCTION", "[execution_context][negative]")
{
    NEGATIVE_TEST_PROLOG();
    ebpf_operation_get_ec_function_request_t request;
    ebpf_operation_get_ec_function_reply_t reply;

    request.function = static_cast<ebpf_ec_function_t>(EBPF_EC_FUNCTION_LOG + 1);
    // Wrong EC function.
    REQUIRE(invoke_protocol(EBPF_OPERATION_GET_EC_FUNCTION, request, reply) == EBPF_INVALID_ARGUMENT);
}
#else
TEST_CASE("EBPF_OPERATION_GET_EC_FUNCTION", "[execution_context][negative]")
{
    test_blocked_by_policy(EBPF_OPERATION_GET_EC_FUNCTION);
}
#endif