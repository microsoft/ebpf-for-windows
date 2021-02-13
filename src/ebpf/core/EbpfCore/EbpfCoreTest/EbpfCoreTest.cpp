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

TEST_CASE("EbpfCoreInitialize", "EbpfCoreInitialize") {
    REQUIRE(EbpfCoreInitialize() == STATUS_SUCCESS);
    EbpfCoreTerminate();
}

TEST_CASE("LoadAttachDetachUnload", "AttachDetach") {
    REQUIRE(EbpfCoreInitialize() == STATUS_SUCCESS);
    std::vector<uint8_t> buffer(1024);

    auto load_request = reinterpret_cast<EbpfOpLoadRequest*>(buffer.data());
    EbpfOpLoadReply load_reply;
    load_request->header.length = buffer.size();
    load_request->header.id = EbpfOperation::load_code;

    REQUIRE(EbpfCoreProtocolLoadCode(load_request, &load_reply) == STATUS_SUCCESS);

    EbpfOpAttachDetachRequest attach_request{ sizeof(attach_request), EbpfOperation::attach, load_reply.handle, ebpf_hook_xdp };
    REQUIRE(EbpfCoreProtocolAttachCode(&attach_request, nullptr) == STATUS_SUCCESS);

    EbpfOpAttachDetachRequest detach_request{ sizeof(detach_request), EbpfOperation::detach, load_reply.handle, ebpf_hook_xdp };
    REQUIRE(EbpfCoreProtocolDetachCode(&detach_request, nullptr) == STATUS_SUCCESS);

    EbpfOpUnloadRequest unload_request{ sizeof(unload_request), EbpfOperation::unload_code, load_reply.handle };
    REQUIRE(EbpfCoreProtocolUnloadCode(&unload_request, nullptr) == STATUS_SUCCESS);

    EbpfCoreTerminate();
}

TEST_CASE("ResolveHelper", "ResolveHelper") {
    EbpfOpResolveHelperRequest request{ sizeof(EbpfOpResolveHelperRequest), EbpfOperation::resolve_helper };
    EbpfOpResolveHelperReply reply;

    for (ebpf_helper_function helper_id = ebpf_lookup_element; helper_id <= ebpf_delete_element; helper_id = static_cast<ebpf_helper_function>(helper_id + 1))
    {
        reply.address[0] = 0;
        request.helper_id[0] = helper_id;
        REQUIRE(EbpfCoreProtocolResolveHelper(&request, &reply) == STATUS_SUCCESS);
        REQUIRE(reply.address[0] != 0);
    }
}

TEST_CASE("MapTests", "MapTests") {
    REQUIRE(EbpfCoreInitialize() == STATUS_SUCCESS);

    EbpfOpCreateMapRequest create_request{ sizeof(EbpfOpCreateMapRequest), EbpfOperation::create_map, 2, sizeof(uint32_t), sizeof(uint64_t), 10 };
    EbpfOpCreateMapReply create_reply;

    REQUIRE(EbpfCoreProtocolCreateMap(&create_request, &create_reply) == STATUS_SUCCESS);
    REQUIRE(create_reply.handle != 0);
    
    for (uint32_t i = 0; i < 10; i++)
    {
        std::vector<uint8_t> request_buffer;
        std::vector<uint8_t> reply_buffer;

        request_buffer.resize(sizeof(EpfOpMapUpdateElementRequest) - 1 + create_request.key_size + create_request.value_size);
        auto update_request = reinterpret_cast<EpfOpMapUpdateElementRequest*>(request_buffer.data());
        update_request->header.length = request_buffer.size();
        update_request->header.id = EbpfOperation::map_update_element;
        update_request->handle = create_reply.handle;
        auto key = reinterpret_cast<uint32_t*>(update_request->data);
        *key = i;
        auto value = reinterpret_cast<uint64_t*>(key + 1);
        *value = 0x1234567890abcdef;
        
        REQUIRE(EbpfCoreProtocolMapUpdateElement(update_request, nullptr) == ERROR_SUCCESS);

        request_buffer.resize(sizeof(EbpfOpMapLookupElementRequest) - 1 + create_request.key_size);
        reply_buffer.resize(sizeof(EbpfOpMapLookupElementReply) - 1 + create_request.value_size);
        auto lookup_request = reinterpret_cast<EbpfOpMapLookupElementRequest*>(request_buffer.data());
        auto lookup_reply = reinterpret_cast<EbpfOpMapLookupElementReply*>(reply_buffer.data());
        lookup_request->header.length = request_buffer.size();
        lookup_request->header.id = EbpfOperation::map_lookup_element;
        lookup_request->handle = create_reply.handle;
        key = reinterpret_cast<uint32_t*>(lookup_request->key);
        *key = i;
        lookup_reply->header.length = reply_buffer.size();
        REQUIRE(EbpfCoreProtocolMapLookupElement(lookup_request, lookup_reply) == STATUS_SUCCESS);
        value = reinterpret_cast<uint64_t*>(lookup_reply->value);
        REQUIRE(*value == 0x1234567890abcdef);

        request_buffer.resize(sizeof(EbpfOpMapDeleteElementRequest) - 1 + create_request.key_size);
        auto delete_request = reinterpret_cast<EbpfOpMapDeleteElementRequest*>(request_buffer.data());
        delete_request->header.length = request_buffer.size();
        delete_request->header.id = EbpfOperation::map_update_element;
        delete_request->handle = create_reply.handle;
        key = reinterpret_cast<uint32_t*>(delete_request->key);
        *key = i;

        REQUIRE(EbpfCoreProtocolMapDeleteElement(delete_request, nullptr) == ERROR_SUCCESS);

        request_buffer.resize(sizeof(EbpfOpMapLookupElementRequest) - 1 + create_request.key_size);
        reply_buffer.resize(sizeof(EbpfOpMapLookupElementReply) - 1 + create_request.value_size);
        lookup_request = reinterpret_cast<EbpfOpMapLookupElementRequest*>(request_buffer.data());
        lookup_reply = reinterpret_cast<EbpfOpMapLookupElementReply*>(reply_buffer.data());
        lookup_request->header.length = request_buffer.size();
        lookup_request->header.id = EbpfOperation::map_lookup_element;
        lookup_request->handle = create_reply.handle;
        key = reinterpret_cast<uint32_t*>(lookup_request->key);
        *key = i;
        lookup_reply->header.length = reply_buffer.size();
        REQUIRE(EbpfCoreProtocolMapLookupElement(lookup_request, lookup_reply) == STATUS_SUCCESS);
        value = reinterpret_cast<uint64_t*>(lookup_reply->value);
        REQUIRE(*value == 0);
    }

    EbpfCoreTerminate();
}

TEST_CASE("HelperTests", "HelperTests") {
    REQUIRE(EbpfCoreInitialize() == STATUS_SUCCESS);

    EbpfOpCreateMapRequest create_request{ sizeof(EbpfOpCreateMapRequest), EbpfOperation::create_map, 2, sizeof(uint32_t), sizeof(uint64_t), 10 };
    EbpfOpCreateMapReply create_reply;

    REQUIRE(EbpfCoreProtocolCreateMap(&create_request, &create_reply) == STATUS_SUCCESS);
    REQUIRE(create_reply.handle != 0);

    EbpfOpResolveMapRequest resolve_request{ sizeof(EbpfOpResolveMapRequest), EbpfOperation::resolve_map, create_reply.handle };
    EbpfOpResolveMapReply resolve_reply{ sizeof(EbpfOpResolveHelperReply) };
    REQUIRE(EbpfCoreProtocolResolveMap(&resolve_request, &resolve_reply) == STATUS_SUCCESS);
    REQUIRE(resolve_reply.address[0] != 0);

    auto map = resolve_reply.address[0];

    EbpfOpResolveHelperRequest request{ sizeof(EbpfOpResolveHelperRequest), EbpfOperation::resolve_helper };
    EbpfOpResolveHelperReply reply;

    std::vector<uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t)> helper_functions(5);

    for (ebpf_helper_function id = ebpf_lookup_element; id < ebpf_invalid; id = static_cast<ebpf_helper_function>(id + 1))
    {
        reply.address[0] = 0;
        request.helper_id[0] = id;
        REQUIRE(EbpfCoreProtocolResolveHelper(&request, &reply) == STATUS_SUCCESS);
        REQUIRE(reply.address[0] != 0);
        helper_functions[id] = reinterpret_cast<uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t)>(reply.address[0]);
    }

    for (uint64_t i = 0; i < 10; i++)
    {
        uint64_t key = i;
        uint64_t value = 0x123456789abcdef;
        helper_functions[ebpf_update_element](map, reinterpret_cast<uint64_t>(&key), reinterpret_cast<uint64_t>(&value), 0);

        auto element_address = helper_functions[ebpf_lookup_element](map, reinterpret_cast<uint64_t>(&key), 0, 0);
        REQUIRE(*reinterpret_cast<uint64_t*>(element_address) == 0x123456789abcdef);

        helper_functions[ebpf_delete_element](map, reinterpret_cast<uint64_t>(&key), 0, 0);

        element_address = helper_functions[ebpf_lookup_element](map, reinterpret_cast<uint64_t>(&key), 0, 0);
        REQUIRE(*reinterpret_cast<uint64_t*>(element_address) == 0);
    }

    EbpfCoreTerminate();
}

