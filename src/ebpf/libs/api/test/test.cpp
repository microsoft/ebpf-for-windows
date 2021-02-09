// test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

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

TEST_CASE("Load program success - resolve helper", "[load_success - resolve helper]") {
    create_file_handler = success_create_file_handler;
    close_handle_handler = success_close_handle_handler;
    device_io_control_handler = success_ioctl;

    HANDLE handle;
    char* error_message = nullptr;

    EbpfOpResolveHelperReply helper_reply{ sizeof(EbpfOpResolveHelperReply), EbpfOperation::resolve_helper, reinterpret_cast<uint64_t>(&GetTickCount) };
    push_back_reply_message(&helper_reply.header);

    EbpfOpLoadReply load_reply{ sizeof(EbpfOpLoadReply), EbpfOperation::load_code, reinterpret_cast<uint64_t>(&h) };
    push_back_reply_message(&load_reply.header);

    REQUIRE(EbpfApiInit() == ERROR_SUCCESS);

    REQUIRE(EbpfApiLoadProgram("bpf_call.o", "xdp_prog", &handle, &error_message) == 0);

    auto resolve_request = front_request_message<EbpfOpResolveHelperRequest>();
    REQUIRE(resolve_request->helper_id[0] == 3);
    request_messages.pop_front();

    auto load_request = front_request_message<EbpfOpLoadRequest>();
    request_messages.pop_front();

    EbpfApiFreeErrorMessage(error_message);
    EbpfApiTerminate();
}