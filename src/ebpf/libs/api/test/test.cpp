/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
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

void push_back_reply_message(EbpfOpHeader* header)
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
    EbpfOperation expected_id = (EbpfOperation)-1;
    if constexpr (std::is_same<request_message_t, EbpfOpEvidenceRequest>::value) {
        expected_size = sizeof(EbpfOpEvidenceRequest);
        expected_id = EbpfOperation::evidence;
    }
    else if constexpr (std::is_same<request_message_t, EbpfOpResolveHelperRequest>::value) {
        expected_size = sizeof(EbpfOpResolveHelperRequest);
        expected_id = EbpfOperation::resolve_helper;
    }
    else if constexpr (std::is_same<request_message_t, EbpfOpResolveMapRequest>::value) {
        expected_size = sizeof(EbpfOpResolveMapRequest);
        expected_id = EbpfOperation::resolve_map;
    }
    else if constexpr (std::is_same<request_message_t, EbpfOpLoadRequest>::value) {
        expected_id = EbpfOperation::load_code;
    }
    else if constexpr (std::is_same<request_message_t, EbpfOpAttachDetachRequest>::value) {
        expected_size = sizeof(EbpfOpAttachDetachRequest);
        switch (message->header.id) {
        case EbpfOperation::attach:
        case EbpfOperation::detach:
            break;
        default:
            REQUIRE(message->header.id == EbpfOperation::attach);
            break;
        }
    }
    else if constexpr (std::is_same<request_message_t, EbpfOpCreateMapRequest>::value) {
        expected_size = sizeof(EbpfOpCreateMapRequest);
        expected_id = EbpfOperation::create_map;
    }
    else if constexpr (std::is_same<request_message_t, EbpfOpMapLookupElementRequest>::value) {
        expected_size = sizeof(EbpfOpMapLookupElementRequest);
        expected_id = EbpfOperation::map_lookup_element;
    }
    else if constexpr (std::is_same<request_message_t, EpfOpMapUpdateElementRequest>::value) {
        expected_size = sizeof(EpfOpMapUpdateElementRequest);
        expected_id = EbpfOperation::map_update_element;
    }
    else if constexpr (std::is_same<request_message_t, EbpfOpMapDeleteElementRequest>::value) {
        expected_size = sizeof(EpfOpMapUpdateElementRequest);
        expected_id = EbpfOperation::map_update_element;
    }

    if (expected_id != (EbpfOperation)-1)
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

    REQUIRE(EbpfApiInit() == ERROR_FILE_NOT_FOUND);
    EbpfApiTerminate();
}

TEST_CASE("Open success", "[open_success]") {
    create_file_handler = success_create_file_handler;
    close_handle_handler = success_close_handle_handler;

    REQUIRE(EbpfApiInit() == ERROR_SUCCESS);
    EbpfApiTerminate();
}

TEST_CASE("Load program fail - file not found", "[load_fail_not_found]") {
    create_file_handler = success_create_file_handler;
    close_handle_handler = success_close_handle_handler;

    HANDLE handle;
    char* error_message = nullptr;
    const char* fake_file_name = "not_a_real_file.elf";

    REQUIRE(EbpfApiInit() == ERROR_SUCCESS);

    REQUIRE(EbpfApiLoadProgram(fake_file_name, "xdp_fake", &handle, &error_message) == ERROR_INVALID_PARAMETER);
    REQUIRE_THAT(error_message, Catch::Matchers::Contains(fake_file_name));
    EbpfApiFreeErrorMessage(error_message);
    EbpfApiTerminate();
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

    REQUIRE(EbpfApiInit() == ERROR_SUCCESS);

    REQUIRE(EbpfApiLoadProgram(temp_file_name, "xdp_fake", &handle, &error_message) == ERROR_INVALID_PARAMETER);
    REQUIRE_THAT(error_message, Catch::Matchers::Contains(temp_file_name));
    EbpfApiFreeErrorMessage(error_message);
    EbpfApiTerminate();

    DeleteFileA(temp_file_name);
}

TEST_CASE("Load program success", "[load_success]") {
    create_file_handler = success_create_file_handler;
    close_handle_handler = success_close_handle_handler;
    device_io_control_handler = success_ioctl;

    HANDLE handle;
    char* error_message = nullptr;

    EbpfOpLoadReply load_reply{ sizeof(EbpfOpLoadReply), EbpfOperation::load_code, reinterpret_cast<uint64_t>(&h) };
    push_back_reply_message(&load_reply.header);

    REQUIRE(EbpfApiInit() == ERROR_SUCCESS);

    REQUIRE(EbpfApiLoadProgram("bpf.o", "xdp_prog", &handle, &error_message) == ERROR_SUCCESS);

    auto load_request = front_request_message<EbpfOpLoadRequest>();

    request_messages.clear();

    EbpfApiFreeErrorMessage(error_message);
    EbpfApiTerminate();
}

//TEST_CASE("Load program success - resolve helper", "[load_success - resolve helper]") {
//    create_file_handler = success_create_file_handler;
//    close_handle_handler = success_close_handle_handler;
//    device_io_control_handler = success_ioctl;
//
//    HANDLE handle;
//    char* error_message = nullptr;
//
//    EbpfOpResolveHelperReply helper_reply{ sizeof(EbpfOpResolveHelperReply), EbpfOperation::resolve_helper, reinterpret_cast<uint64_t>(&GetTickCount) };
//    push_back_reply_message(&helper_reply.header);
//
//    EbpfOpLoadReply load_reply{ sizeof(EbpfOpLoadReply), EbpfOperation::load_code, reinterpret_cast<uint64_t>(&h) };
//    push_back_reply_message(&load_reply.header);
//
//    REQUIRE(EbpfApiInit() == ERROR_SUCCESS);
//
//    REQUIRE(EbpfApiLoadProgram("bpf_call.o", "xdp_prog", &handle, &error_message) == 0);
//
//    auto resolve_request = front_request_message<EbpfOpResolveHelperRequest>();
//    REQUIRE(resolve_request->helper_id[0] == 3);
//    request_messages.pop_front();
//
//    auto load_request = front_request_message<EbpfOpLoadRequest>();
//    request_messages.pop_front();
//
//    EbpfApiFreeErrorMessage(error_message);
//    EbpfApiTerminate();
//}

unsigned long test_map[1] = { 0 };

void* map_lookup_elem(void* map, void* key)
{
    return test_map;
}

TEST_CASE("Load program success - create_map", "[load_success - create map]") {
    create_file_handler = success_create_file_handler;
    close_handle_handler = success_close_handle_handler;
    device_io_control_handler = success_ioctl;

    HANDLE handle;
    char* error_message = nullptr;

    EbpfOpCreateMapReply map_create_reply{ sizeof(EbpfOpCreateMapReply), EbpfOperation::create_map, 15 };
    push_back_reply_message(&map_create_reply.header);

    EbpfOpResolveMapReply map_resolve_reply{ sizeof(EbpfOpResolveMapReply), EbpfOperation::resolve_map, reinterpret_cast<uint64_t>(test_map) };
    push_back_reply_message(&map_resolve_reply.header);

    EbpfOpResolveHelperReply helper_reply{ sizeof(EbpfOpResolveHelperReply), EbpfOperation::resolve_helper, reinterpret_cast<uint64_t>(map_lookup_elem) };
    push_back_reply_message(&helper_reply.header);

    EbpfOpLoadReply load_reply{ sizeof(EbpfOpLoadReply), EbpfOperation::load_code, reinterpret_cast<uint64_t>(&h) };
    push_back_reply_message(&load_reply.header);

    REQUIRE(EbpfApiInit() == ERROR_SUCCESS);

    auto result = EbpfApiLoadProgram("droppacket.o", "xdp", &handle, &error_message);
    if (result)
    {
        printf("error_message=%s\n", error_message);
    }
    REQUIRE(result == 0);

    auto map_create_request = front_request_message<EbpfOpCreateMapRequest>();
    REQUIRE(map_create_request->type == 2);
    REQUIRE(map_create_request->key_size == 4);
    REQUIRE(map_create_request->value_size == 4);
    REQUIRE(map_create_request->max_entries == 1);
    REQUIRE(map_create_request->map_flags == 0);
    request_messages.pop_front();

    auto resolve_map_request = front_request_message<EbpfOpResolveMapRequest>();
    REQUIRE(resolve_map_request->map_id[0] == 15);
    request_messages.pop_front();

    auto resolve_request = front_request_message<EbpfOpResolveHelperRequest>();
    REQUIRE(resolve_request->helper_id[0] == 1);
    request_messages.pop_front();

    auto load_request = front_request_message<EbpfOpLoadRequest>();

    auto code_size = load_request->header.length - sizeof(EbpfOpHeader);
    auto code_page = VirtualAlloc(NULL, code_size, MEM_COMMIT, PAGE_READWRITE);
    REQUIRE(code_page != nullptr);
    DWORD oldProtect = 0;
    memcpy(code_page, &load_request->machine_code[0], code_size);
    VirtualProtect(code_page, code_size, PAGE_EXECUTE_READ, &oldProtect);
    request_messages.pop_front();

    EbpfApiFreeErrorMessage(error_message);
    EbpfApiTerminate();

    typedef unsigned long __u64;
    typedef unsigned int __u32;
    typedef unsigned short __u16;
    typedef unsigned char __u8;

    typedef struct xdp_md_
    {
        void* data;
        void* data_end;
        __u64 data_meta;
    } xdp_md;

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

    uint64_t (*xdp_hook)(xdp_md* ctx) = reinterpret_cast<decltype(xdp_hook)>(code_page);
    
    // Test that we drop the packet and increment the map
    xdp_md ctx{packet.data(), packet.data() + packet.size()};
    REQUIRE(xdp_hook(&ctx) == 2);
    REQUIRE(test_map[0] == 1);

    // Test we don't drop the packet if udp size == 1
    // Change to 1 byte udp packet
    udp->length = 0x0900;

    REQUIRE(xdp_hook(&ctx) == 1);
    // Check that we don't update the map
    REQUIRE(test_map[0] == 1);

}