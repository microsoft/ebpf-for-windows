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

#define EBPF_API
#include "../api.h"
#include "mock.h"
#include "../protocol.h"

uint8_t h = 0;
auto success_create_file_handler = [&](_In_ LPCWSTR lpFileName,
    _In_ DWORD dwDesiredAccess,
    _In_ DWORD dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_ DWORD dwCreationDisposition,
    _In_ DWORD dwFlagsAndAttributes,
    _In_opt_ HANDLE hTemplateFile) -> HANDLE
{
    SetLastError(ERROR_SUCCESS);
    return reinterpret_cast<HANDLE>(&h);
};
auto success_close_handle_handler = [&](_In_ HANDLE hObject) -> BOOL
{
    if (hObject != &h)
    {
        throw std::exception("Test failed - closing wrong handle");
    }
    return TRUE;
};

std::list<std::vector<uint8_t>> request_messages;
std::list<std::vector<uint8_t>> reply_messages;

auto success_ioctl = [&](_In_ HANDLE hDevice,
    _In_ DWORD dwIoControlCode,
    _In_reads_bytes_opt_(nInBufferSize) LPVOID lpInBuffer,
    _In_ DWORD nInBufferSize,
    _Out_writes_bytes_to_opt_(nOutBufferSize, *lpBytesReturned) LPVOID lpOutBuffer,
    _In_ DWORD nOutBufferSize,
    _Out_opt_ LPDWORD lpBytesReturned,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
    ) -> BOOL
{
    if (hDevice != &h)
    {
        throw std::exception("Test failed - using wrong handle");
    }

    if (reply_messages.empty())
    {
        throw std::exception("Test failed - no reply message queue");
    }

    auto in_begin = reinterpret_cast<uint8_t*>(lpInBuffer);
    auto in_end = in_begin + nInBufferSize;
    auto out_begin = reinterpret_cast<uint8_t*>(lpOutBuffer);
    auto out_end = out_begin + nOutBufferSize;

    std::vector<uint8_t> request;
    std::vector<uint8_t>& reply = reply_messages.front();
    if (reply.size() > nOutBufferSize)
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    *lpBytesReturned = static_cast<DWORD>(reply.size());

    request.resize(nInBufferSize);
    std::copy(in_begin, in_end, request.begin());
    std::copy(reply.begin(), reply.end(), out_begin);

    reply_messages.pop_front();
    request_messages.emplace_back(std::move(request));

    return TRUE;
};

void push_back_reply_message(_ebpf_operation_header* header)
{
    std::vector<uint8_t> reply(header->length);

    std::copy(reinterpret_cast<uint8_t*>(header), reinterpret_cast<uint8_t*>(header) + header->length, reply.begin());
    reply_messages.emplace_back(std::move(reply));
}

template <typename request_message_t>
request_message_t* front_request_message()
{
    auto message = reinterpret_cast<request_message_t*>(request_messages.front().data());
    size_t expected_size = 0;
    ebpf_operation_id_t expected_id = (ebpf_operation_id_t)-1;
    if constexpr (std::is_same<request_message_t, _ebpf_operation_eidence_request>::value) {
        expected_size = sizeof(_ebpf_operation_eidence_request);
        expected_id = ebpf_operation_id_t::EBPF_OPERATION_EVIDENCE;
    }
    else if constexpr (std::is_same<request_message_t, _ebpf_operation_resolve_helper_request>::value) {
        expected_size = sizeof(_ebpf_operation_resolve_helper_request);
        expected_id = ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_HELPER;
    }
    else if constexpr (std::is_same<request_message_t, _ebpf_operation_resolve_map_request>::value) {
        expected_size = sizeof(_ebpf_operation_resolve_helper_reply);
        expected_id = ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_MAP;
    }
    else if constexpr (std::is_same<request_message_t, _ebpf_operation_load_code_request>::value) {
        expected_id = ebpf_operation_id_t::EBPF_OPERATION_LOAD_CODE;
    }
    else if constexpr (std::is_same<request_message_t, _ebpf_operation_attach_detach_request>::value) {
        expected_size = sizeof(_ebpf_operation_attach_detach_request);
        switch (message->header.id) {
        case ebpf_operation_id_t::EBPF_OPERATION_ATTACH_CODE:
        case ebpf_operation_id_t::EBPF_OPERATION_DETACH_CODE:
            break;
        default:
            REQUIRE(message->header.id == ebpf_operation_id_t::EBPF_OPERATION_ATTACH_CODE);
            break;
        }
    }
    else if constexpr (std::is_same<request_message_t, _ebpf_operation_create_map_request>::value) {
        expected_size = sizeof(_ebpf_operation_create_map_request);
        expected_id = ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP;
    }
    else if constexpr (std::is_same<request_message_t, _ebpf_operation_map_lookup_element_request>::value) {
        expected_size = sizeof(_ebpf_operation_map_lookup_element_request);
        expected_id = ebpf_operation_id_t::EBPF_OPERATION_MAP_LOOKUP_ELEMENT;
    }
    else if constexpr (std::is_same<request_message_t, _ebpf_operation_map_update_element_request>::value) {
        expected_size = sizeof(_ebpf_operation_map_update_element_request);
        expected_id = ebpf_operation_id_t::EBPF_OPERATION_MAP_UPDATE_ELEMENT;
    }
    else if constexpr (std::is_same<request_message_t, _ebpf_operation_map_delete_element_request>::value) {
        expected_size = sizeof(_ebpf_operation_map_update_element_request);
        expected_id = ebpf_operation_id_t::EBPF_OPERATION_MAP_UPDATE_ELEMENT;
    }

    if (expected_id != (ebpf_operation_id_t)-1)
        REQUIRE(expected_id == message->header.id);

    if (expected_size > 0)
        REQUIRE(expected_size == message->header.length);
    return message;
}

TEST_CASE("Open failed", "[open_fail]") {
    create_file_handler = [](_In_ LPCWSTR lpFileName,
        _In_ DWORD dwDesiredAccess,
        _In_ DWORD dwShareMode,
        _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        _In_ DWORD dwCreationDisposition,
        _In_ DWORD dwFlagsAndAttributes,
        _In_opt_ HANDLE hTemplateFile) -> HANDLE {
            SetLastError(ERROR_FILE_NOT_FOUND);
            return INVALID_HANDLE_VALUE;
    };

    close_handle_handler = [](_In_ HANDLE hObject) -> BOOL {
        throw std::exception("Test failed - closing handle not opened");
    };

    REQUIRE(ebpf_api_initiate() == ERROR_FILE_NOT_FOUND);
    ebpf_api_terminate();
}

TEST_CASE("Open success", "[open_success]") {
    create_file_handler = success_create_file_handler;
    close_handle_handler = success_close_handle_handler;

    REQUIRE(ebpf_api_initiate() == ERROR_SUCCESS);
    ebpf_api_terminate();
}

TEST_CASE("Load program fail - file not found", "[load_fail_not_found]") {
    create_file_handler = success_create_file_handler;
    close_handle_handler = success_close_handle_handler;

    HANDLE handle;
    char* error_message = nullptr;
    const char* fake_file_name = "not_a_real_file.elf";

    REQUIRE(ebpf_api_initiate() == ERROR_SUCCESS);

    REQUIRE(ebpf_api_load_program(fake_file_name, "xdp_fake", &handle, &error_message) == ERROR_INVALID_PARAMETER);
    REQUIRE_THAT(error_message, Catch::Matchers::Contains(fake_file_name));
    ebpf_api_free_error_message(error_message);
    ebpf_api_terminate();
}

TEST_CASE("Load program fail - malformed", "[load_fail_bad_file]") {
    create_file_handler = success_create_file_handler;
    close_handle_handler = success_close_handle_handler;

    char temp_file_name[MAX_PATH];
    REQUIRE(GetTempFileNameA(".", "bad_elf", 0, temp_file_name) != 0);

    HANDLE handle;
    char* error_message = nullptr;

    std::fstream out_file(temp_file_name, std::ios_base::out | std::ios_base::trunc);
    std::default_random_engine generator;
    std::uniform_int_distribution<uint16_t> distribution(0, 255);

    for (size_t i = 0; i < 4096; i++)
    {
        out_file.put(static_cast<char>(distribution(generator)));
    }
    out_file.flush();
    out_file.close();

    REQUIRE(ebpf_api_initiate() == ERROR_SUCCESS);

    REQUIRE(ebpf_api_load_program(temp_file_name, "xdp_fake", &handle, &error_message) == ERROR_INVALID_PARAMETER);
    REQUIRE_THAT(error_message, Catch::Matchers::Contains(temp_file_name));
    ebpf_api_free_error_message(error_message);
    ebpf_api_terminate();

    DeleteFileA(temp_file_name);
}

TEST_CASE("Load program success", "[load_success]") {
    create_file_handler = success_create_file_handler;
    close_handle_handler = success_close_handle_handler;
    device_io_control_handler = success_ioctl;

    HANDLE handle;
    char* error_message = nullptr;

    _ebpf_operation_load_code_reply load_reply{ sizeof(_ebpf_operation_load_code_reply), ebpf_operation_id_t::EBPF_OPERATION_LOAD_CODE, reinterpret_cast<uint64_t>(&h) };
    push_back_reply_message(&load_reply.header);

    REQUIRE(ebpf_api_initiate() == ERROR_SUCCESS);

    REQUIRE(ebpf_api_load_program("bpf.o", "xdp_prog", &handle, &error_message) == ERROR_SUCCESS);

    auto load_request = front_request_message<_ebpf_operation_load_code_request>();

    request_messages.clear();

    ebpf_api_free_error_message(error_message);
    ebpf_api_terminate();
}

unsigned long test_map[1] = { 0 };

void* map_lookup_elem(void* map, void* key)
{
    return test_map;
}

TEST_CASE("Load program success - EBPF_OPERATION_CREATE_MAP", "[load_success - create map]") {
    create_file_handler = success_create_file_handler;
    close_handle_handler = success_close_handle_handler;
    device_io_control_handler = success_ioctl;

    HANDLE handle;
    char* error_message = nullptr;

    _ebpf_operation_create_map_reply map_create_reply{ sizeof(_ebpf_operation_create_map_reply), ebpf_operation_id_t::EBPF_OPERATION_CREATE_MAP, (15) };
    push_back_reply_message(&map_create_reply.header);

    _ebpf_operation_resolve_map_reply map_resolve_reply{ sizeof(_ebpf_operation_resolve_map_reply), ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_MAP, reinterpret_cast<uint64_t>(test_map) };
    push_back_reply_message(&map_resolve_reply.header);

    _ebpf_operation_resolve_helper_reply helper_reply{ sizeof(_ebpf_operation_resolve_helper_reply), ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_HELPER, reinterpret_cast<uint64_t>(map_lookup_elem) };
    push_back_reply_message(&helper_reply.header);

    _ebpf_operation_load_code_reply load_reply{ sizeof(_ebpf_operation_load_code_reply), ebpf_operation_id_t::EBPF_OPERATION_LOAD_CODE, reinterpret_cast<uint64_t>(&h) };
    push_back_reply_message(&load_reply.header);

    REQUIRE(ebpf_api_initiate() == ERROR_SUCCESS);

    auto result = ebpf_api_load_program("droppacket.o", "xdp", &handle, &error_message);
    if (result)
    {
        printf("error_message=%s\n", error_message);
    }
    REQUIRE(result == 0);

    auto map_create_request = front_request_message<_ebpf_operation_create_map_request>();
    REQUIRE(map_create_request->ebpf_map_definition.size == sizeof(struct _ebpf_map_definition));
    REQUIRE(map_create_request->ebpf_map_definition.type == 2);
    REQUIRE(map_create_request->ebpf_map_definition.key_size == 4);
    REQUIRE(map_create_request->ebpf_map_definition.value_size == 8);
    REQUIRE(map_create_request->ebpf_map_definition.max_entries == 1);
    request_messages.pop_front();

    auto resolve_map_request = front_request_message<_ebpf_operation_resolve_map_request>();
    REQUIRE(resolve_map_request->map_handle[0] == 15);
    request_messages.pop_front();

    auto resolve_request = front_request_message<_ebpf_operation_resolve_helper_request>();
    REQUIRE(resolve_request->helper_id[0] == 1);
    request_messages.pop_front();

    auto load_request = front_request_message<_ebpf_operation_load_code_request>();

    auto code_size = load_request->header.length - sizeof(_ebpf_operation_header);
    auto code_page = VirtualAlloc(NULL, code_size, MEM_COMMIT, PAGE_READWRITE);
    REQUIRE(code_page != nullptr);
    DWORD oldProtect = 0;
    memcpy(code_page, &load_request->machine_code[0], code_size);
    VirtualProtect(code_page, code_size, PAGE_EXECUTE_READ, &oldProtect);
    request_messages.pop_front();

    ebpf_api_free_error_message(error_message);
    ebpf_api_terminate();

    typedef unsigned long __u64;
    typedef unsigned int __u32;
    typedef unsigned short __u16;
    typedef unsigned char __u8;

    typedef struct _xdp_md
    {
        void* data;
        void* data_end;
        __u64 data_meta;
    } xdp_md_t;

    typedef struct _IPV4_HEADER {
        union {
            __u8 VersionAndHeaderLength;   // Version and header length.
            struct {
                __u8 HeaderLength : 4;
                __u8 Version : 4;
            };
        };
        union {
            __u8 TypeOfServiceAndEcnField; // Type of service & ECN (RFC 3168).
            struct {
                __u8 EcnField : 2;
                __u8 TypeOfService : 6;
            };
        };
        __u16 TotalLength;                 // Total length of datagram.
        __u16 Identification;
        union {
            __u16 FlagsAndOffset;          // Flags and fragment offset.
            struct {
                __u16 DontUse1 : 5;        // High bits of fragment offset.
                __u16 MoreFragments : 1;
                __u16 DontFragment : 1;
                __u16 Reserved : 1;
                __u16 DontUse2 : 8;        // Low bits of fragment offset.
            };
        };
        __u8 TimeToLive;
        __u8 Protocol;
        __u16 HeaderChecksum;
        __u32 SourceAddress;
        __u32 DestinationAddress;
    } IPV4_HEADER, * PIPV4_HEADER;

    typedef struct UDP_HEADER_ {
        __u16 srcPort;
        __u16 destPort;
        __u16 length;
        __u16 checksum;
    } UDP_HEADER;


    std::vector<uint8_t> packet(sizeof(IPV4_HEADER) + sizeof(UDP_HEADER));
    auto ipv4 = reinterpret_cast<IPV4_HEADER*>(packet.data());
    auto udp = reinterpret_cast<UDP_HEADER*>(ipv4 + 1);

    ipv4->Protocol = 17;

    udp->length = 0;

    uint64_t (*xdp_hook)(xdp_md_t* ctx) = reinterpret_cast<decltype(xdp_hook)>(code_page);
    
    // Test that we drop the packet and increment the map
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};
    REQUIRE(xdp_hook(&ctx) == 2);
    REQUIRE(test_map[0] == 1);

    // Test we don't drop the packet if udp size == 1
    // Change to 1 byte udp packet
    udp->length = 0x0900;

    REQUIRE(xdp_hook(&ctx) == 1);
    // Check that we don't update the map
    REQUIRE(test_map[0] == 1);

}