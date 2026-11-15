// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_api.h"
#include "namespaces.h"
#include "tokens.h"

#include <iostream>
#include <rpc.h>
#include <string>
#include <vector>

namespace {
bool
parse_namespace_guid(const wchar_t* text, GUID& namespace_id)
{
    wchar_t uuid[37]{};
    if (wcslen(text) != 38 || text[0] != L'{' || text[37] != L'}') {
        return false;
    }
    memcpy(uuid, text + 1, 36 * sizeof(wchar_t));
    return UuidFromStringW(reinterpret_cast<RPC_WSTR>(uuid), &namespace_id) == RPC_S_OK;
}

class namespace_restore
{
  public:
    explicit namespace_restore(const GUID& previous) : _previous(previous) {}
    ~namespace_restore() { (void)restore(); }
    ebpf_result_t
    restore()
    {
        if (!_active) {
            return EBPF_SUCCESS;
        }
        _active = false;
        auto result = ebpf_set_thread_namespace(&_previous);
        if (result != EBPF_SUCCESS) {
            std::cerr << "error " << result << ": could not restore namespace after command\n";
        }
        return result;
    }

  private:
    GUID _previous;
    bool _active = true;
};
} // namespace

bool
ebpf_netsh_has_namespace_argument(LPWSTR* argv, DWORD current_index, DWORD argc) noexcept
{
    for (DWORD index = current_index; index < argc; ++index) {
        if (_wcsnicmp(argv[index], L"namespace=", 10) == 0) {
            return true;
        }
    }
    return false;
}

unsigned long
ebpf_netsh_namespace_command(
    FN_HANDLE_CMD* handler,
    LPCWSTR machine,
    LPWSTR* argv,
    DWORD current_index,
    DWORD argc,
    DWORD flags,
    LPCVOID data,
    BOOL* done)
try {
    std::vector<LPWSTR> arguments;
    arguments.reserve(argc);
    GUID requested{}, previous{};
    bool found = false;
    for (DWORD index = 0; index < argc; ++index) {
        if (index >= current_index && _wcsnicmp(argv[index], L"namespace=", 10) == 0) {
            if (found || !parse_namespace_guid(argv[index] + 10, requested)) {
                std::cerr << "error: expected one namespace={xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} argument\n";
                return ERROR_SUPPRESS_OUTPUT;
            }
            found = true;
        } else {
            arguments.push_back(argv[index]);
        }
    }
    if (!found) {
        return handler(machine, argv, current_index, argc, flags, data, done);
    }
    auto result = ebpf_get_thread_namespace(&previous);
    if (result == EBPF_SUCCESS) {
        result = ebpf_set_thread_namespace(&requested);
    }
    if (result != EBPF_SUCCESS) {
        std::cerr << "error " << result << ": could not select command namespace\n";
        return ERROR_SUPPRESS_OUTPUT;
    }
    namespace_restore restore(previous);
    auto status =
        handler(machine, arguments.data(), current_index, static_cast<DWORD>(arguments.size()), flags, data, done);
    if (restore.restore() != EBPF_SUCCESS) {
        return ERROR_SUPPRESS_OUTPUT;
    }
    return status;
} catch (const std::bad_alloc&) {
    std::cerr << "error: could not allocate command arguments\n";
    return ERROR_NOT_ENOUGH_MEMORY;
}

unsigned long
handle_ebpf_set_thread_namespace(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {{L"namespace", NS_REQ_PRESENT, FALSE}};
    unsigned long tag_type[1]{};
    auto status = PreprocessCommand(nullptr, argv, current_index, argc, tags, 1, 1, 1, tag_type);
    if (status != NO_ERROR) {
        return status;
    }

    // UuidFromString also accepts noncanonical forms. Require the documented CLI spelling.
    const auto text = argv[current_index];
    GUID namespace_id{};
    if (!parse_namespace_guid(text, namespace_id)) {
        std::cerr << "error: invalid namespace GUID; expected {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\n";
        return ERROR_SUPPRESS_OUTPUT;
    }

    auto result = ebpf_set_thread_namespace(&namespace_id);
    if (result != EBPF_SUCCESS) {
        std::cerr << "error " << result << ": could not set namespace\n";
        return ERROR_SUPPRESS_OUTPUT;
    }
    return NO_ERROR;
}

unsigned long
handle_ebpf_show_namespace(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(argv);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);
    if (current_index != argc) {
        return ERROR_INVALID_SYNTAX;
    }

    GUID namespace_id{};
    auto result = ebpf_get_thread_namespace(&namespace_id);
    if (result != EBPF_SUCCESS) {
        std::cerr << "error " << result << ": could not get namespace\n";
        return ERROR_SUPPRESS_OUTPUT;
    }
    RPC_CSTR text = nullptr;
    auto status = UuidToStringA(&namespace_id, &text);
    if (status != RPC_S_OK) {
        return status;
    }
    std::cout << "{" << reinterpret_cast<const char*>(text) << "}\n";
    RpcStringFreeA(&text);
    return NO_ERROR;
}
