/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#include <iostream>
#include <fstream>
#include <random>
#include <vector>
#include <list>
#define CATCH_CONFIG_MAIN
#include "catch.hpp"

typedef uint32_t NTSTATUS;
#define STATUS_SUCCESS  0

#include "protocol.h"
extern "C"
{
#include "../ebpf_core.h"
}

TEST_CASE("ebpf_core_initialize", "ebpf_core_initialize") {
    REQUIRE(ebpf_core_initialize() == STATUS_SUCCESS);
    ebpf_core_terminate();
}

TEST_CASE("LoadAttachDetachUnload", "AttachDetach") {
    REQUIRE(ebpf_core_initialize() == STATUS_SUCCESS);
    std::vector<uint8_t> buffer(1024);

    auto load_request = reinterpret_cast<_ebpf_operation_load_code_request*>(buffer.data());
    _ebpf_operation_load_code_reply load_reply;
    load_request->header.length = buffer.size();
    load_request->header.id = ebpf_operation_id_t::EBPF_OPERATION_LOAD_CODE;

    REQUIRE(ebpf_core_protocol_load_code(load_request, &load_reply) == STATUS_SUCCESS);

    _ebpf_operation_attach_detach_request attach_request{ sizeof(attach_request), ebpf_operation_id_t::EBPF_OPERATION_ATTACH_CODE, load_reply.handle, EBPF_HOOK_XDP };
    REQUIRE(ebpf_core_protocol_attach_code(&attach_request, nullptr) == STATUS_SUCCESS);

    _ebpf_operation_attach_detach_request detach_request{ sizeof(detach_request), ebpf_operation_id_t::EBPF_OPERATION_DETACH_CODE, load_reply.handle, EBPF_HOOK_XDP };
    REQUIRE(ebpf_core_protocol_detach_code(&detach_request, nullptr) == STATUS_SUCCESS);

    _ebpf_operation_unload_code_request unload_request{ sizeof(unload_request), ebpf_operation_id_t::EBPF_OPERATION_UNLOAD_CODE, load_reply.handle };
    REQUIRE(ebpf_core_protocol_unload_code(&unload_request, nullptr) == STATUS_SUCCESS);

    ebpf_core_terminate();
}

TEST_CASE("ResolveHelper", "ResolveHelper") {
    _ebpf_operation_resolve_helper_request request{ sizeof(_ebpf_operation_resolve_helper_request), ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_HELPER };
    _ebpf_operation_resolve_helper_reply reply;

    for (ebpf_helper_function_t helper_id = EBPF_LOOKUP_ELEMENT; helper_id <= ebpf_delete_element; helper_id = static_cast<ebpf_helper_function_t>(helper_id + 1))
    {
        reply.address[0] = 0;
        request.helper_id[0] = helper_id;
        REQUIRE(ebpf_core_protocol_resolve_helper(&request, &reply) == STATUS_SUCCESS);
        REQUIRE(reply.address[0] != 0);
    }
}

TEST_CASE("MapTests", "MapTests") {
    REQUIRE(ebpf_core_initialize() == STATUS_SUCCESS);

    _ebpf_operation_create_map_request create_request{ 
        sizeof(_ebpf_operation_create_map_request), 
        ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP, 
        {
            sizeof(ebpf_map_definition_t),
            2, 
            sizeof(uint32_t), 
            sizeof(uint64_t), 
            10
        }};
    _ebpf_operation_create_map_reply create_reply;

    REQUIRE(ebpf_core_protocol_create_map(&create_request, &create_reply) == STATUS_SUCCESS);
    REQUIRE(create_reply.handle != 0);
    
    for (uint32_t i = 0; i < 10; i++)
    {
        std::vector<uint8_t> request_buffer;
        std::vector<uint8_t> reply_buffer;

        request_buffer.resize(sizeof(_ebpf_operation_map_update_element_request) - 1 + create_request.ebpf_map_definition.key_size + create_request.ebpf_map_definition.value_size);
        auto update_request = reinterpret_cast<_ebpf_operation_map_update_element_request*>(request_buffer.data());
        update_request->header.length = request_buffer.size();
        update_request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_UPDATE_ELEMENT;
        update_request->handle = create_reply.handle;
        auto key = reinterpret_cast<uint32_t*>(update_request->data);
        *key = i;
        auto value = reinterpret_cast<uint64_t*>(key + 1);
        *value = 0x1234567890abcdef;
        
        REQUIRE(ebpf_core_protocol_map_update_element(update_request, nullptr) == ERROR_SUCCESS);

        request_buffer.resize(sizeof(_ebpf_operation_map_lookup_element_request) - 1 + create_request.ebpf_map_definition.key_size);
        reply_buffer.resize(sizeof(_ebpf_operation_map_lookup_element_reply) - 1 + create_request.ebpf_map_definition.value_size);
        auto lookup_request = reinterpret_cast<_ebpf_operation_map_lookup_element_request*>(request_buffer.data());
        auto lookup_reply = reinterpret_cast<_ebpf_operation_map_lookup_element_reply*>(reply_buffer.data());
        lookup_request->header.length = request_buffer.size();
        lookup_request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_LOOKUP_ELEMENT;
        lookup_request->handle = create_reply.handle;
        key = reinterpret_cast<uint32_t*>(lookup_request->key);
        *key = i;
        lookup_reply->header.length = reply_buffer.size();
        REQUIRE(ebpf_core_protocol_map_lookup_element(lookup_request, lookup_reply) == STATUS_SUCCESS);
        value = reinterpret_cast<uint64_t*>(lookup_reply->value);
        REQUIRE(*value == 0x1234567890abcdef);

        request_buffer.resize(sizeof(_ebpf_operation_map_delete_element_request) - 1 + create_request.ebpf_map_definition.key_size);
        auto delete_request = reinterpret_cast<_ebpf_operation_map_delete_element_request*>(request_buffer.data());
        delete_request->header.length = request_buffer.size();
        delete_request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_UPDATE_ELEMENT;
        delete_request->handle = create_reply.handle;
        key = reinterpret_cast<uint32_t*>(delete_request->key);
        *key = i;

        REQUIRE(ebpf_core_protocol_map_delete_element(delete_request, nullptr) == ERROR_SUCCESS);

        request_buffer.resize(sizeof(_ebpf_operation_map_lookup_element_request) - 1 + create_request.ebpf_map_definition.key_size);
        reply_buffer.resize(sizeof(_ebpf_operation_map_lookup_element_reply) - 1 + create_request.ebpf_map_definition.value_size);
        lookup_request = reinterpret_cast<_ebpf_operation_map_lookup_element_request*>(request_buffer.data());
        lookup_reply = reinterpret_cast<_ebpf_operation_map_lookup_element_reply*>(reply_buffer.data());
        lookup_request->header.length = request_buffer.size();
        lookup_request->header.id = ebpf_operation_id_t::EBPF_OPERATION_MAP_LOOKUP_ELEMENT;
        lookup_request->handle = create_reply.handle;
        key = reinterpret_cast<uint32_t*>(lookup_request->key);
        *key = i;
        lookup_reply->header.length = reply_buffer.size();
        REQUIRE(ebpf_core_protocol_map_lookup_element(lookup_request, lookup_reply) == STATUS_SUCCESS);
        value = reinterpret_cast<uint64_t*>(lookup_reply->value);
        REQUIRE(*value == 0);
    }

    ebpf_core_terminate();
}

TEST_CASE("HelperTests", "HelperTests") {
    REQUIRE(ebpf_core_initialize() == STATUS_SUCCESS);

    _ebpf_operation_create_map_request create_request{
        sizeof(_ebpf_operation_create_map_request),
        ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP,
        {
            sizeof(ebpf_map_definition_t),
            2,
            sizeof(uint32_t),
            sizeof(uint64_t),
            10
        } };
    _ebpf_operation_create_map_reply create_reply;

    REQUIRE(ebpf_core_protocol_create_map(&create_request, &create_reply) == STATUS_SUCCESS);
    REQUIRE(create_reply.handle != 0);

    _ebpf_operation_resolve_map_request resolve_request{ sizeof(_ebpf_operation_resolve_map_request), ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_MAP, create_reply.handle };
    _ebpf_operation_resolve_map_reply resolve_reply{ sizeof(_ebpf_operation_resolve_map_reply) };
    REQUIRE(ebpf_core_protocol_resolve_map(&resolve_request, &resolve_reply) == STATUS_SUCCESS);
    REQUIRE(resolve_reply.address[0] != 0);

    auto map = resolve_reply.address[0];

    _ebpf_operation_resolve_helper_request request{ sizeof(_ebpf_operation_resolve_helper_request), ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_HELPER };
    _ebpf_operation_resolve_helper_reply reply;

    std::vector<uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t)> helper_functions(5);

    for (ebpf_helper_function_t id = EBPF_LOOKUP_ELEMENT; id < EBPF_INVALID; id = static_cast<ebpf_helper_function_t>(id + 1))
    {
        reply.address[0] = 0;
        request.helper_id[0] = id;
        REQUIRE(ebpf_core_protocol_resolve_helper(&request, &reply) == STATUS_SUCCESS);
        REQUIRE(reply.address[0] != 0);
        helper_functions[id] = reinterpret_cast<uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t)>(reply.address[0]);
    }

    for (uint64_t i = 0; i < 10; i++)
    {
        uint64_t key = i;
        uint64_t value = 0x123456789abcdef;
        helper_functions[EBPF_UPDATE_ELEMENT](map, reinterpret_cast<uint64_t>(&key), reinterpret_cast<uint64_t>(&value), 0);

        auto element_address = helper_functions[EBPF_LOOKUP_ELEMENT](map, reinterpret_cast<uint64_t>(&key), 0, 0);
        REQUIRE(*reinterpret_cast<uint64_t*>(element_address) == 0x123456789abcdef);

        helper_functions[ebpf_delete_element](map, reinterpret_cast<uint64_t>(&key), 0, 0);

        element_address = helper_functions[EBPF_LOOKUP_ELEMENT](map, reinterpret_cast<uint64_t>(&key), 0, 0);
        REQUIRE(*reinterpret_cast<uint64_t*>(element_address) == 0);
    }

    ebpf_core_terminate();
}

