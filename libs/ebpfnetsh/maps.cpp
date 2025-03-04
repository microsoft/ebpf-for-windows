// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"
#include "ebpf_windows.h"
#include "maps.h"
#include "platform.h"
#include "tokens.h"

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

std::string
down_cast_from_wstring(const std::wstring& wide_string);

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
handle_ebpf_show_maps(
    IN LPCWSTR machine,
    _Inout_updates_(argc) LPWSTR* argv,
    IN DWORD current_index,
    IN DWORD argc,
    IN DWORD flags,
    IN LPCVOID data,
    OUT BOOL* done)
{
    UNREFERENCED_PARAMETER(argv);
    UNREFERENCED_PARAMETER(current_index);
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    std::cout << "\n";
    std::cout << "                              Key  Value      Max  Inner\n";
    std::cout << "     ID            Map Type  Size   Size  Entries     ID  Pins  Name\n";
    std::cout << "=======  ==================  ====  =====  =======  =====  ====  ========\n";

    uint32_t map_id = 0;
    for (;;) {
        if (bpf_map_get_next_id(map_id, &map_id) < 0) {
            break;
        }

        fd_t map_fd = bpf_map_get_fd_by_id(map_id);
        if (map_fd < 0) {
            break;
        }

        struct bpf_map_info info;
        uint32_t info_size = (uint32_t)sizeof(info);
        if (bpf_obj_get_info_by_fd(map_fd, &info, &info_size) == 0) {
            printf(
                "%7u  %18s%6u%7u%9u%7d%6u  %s\n",
                info.id,
                libbpf_bpf_map_type_str(info.type),
                info.key_size,
                info.value_size,
                info.max_entries,
                info.inner_map_id,
                info.pinned_path_count,
                info.name);
        }

        Platform::_close(map_fd);
    }
    return NO_ERROR;
}

template <typename F>
unsigned long
handle_ebpf_pinunpin_map_common(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done, F&& f)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {
        {TOKEN_ID, NS_REQ_PRESENT, FALSE},
        {TOKEN_PINPATH, NS_REQ_ZERO, FALSE},
    };
    const int ID_INDEX = 0;
    const int PINPATH_INDEX = 1;

    unsigned long tag_type[_countof(tags)]{};

    unsigned long status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);
    if (status != EBPF_SUCCESS) {
        return status;
    }

    std::string pinpath;
    uint32_t id = 0;

    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case PINPATH_INDEX:
            pinpath = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;

        case ID_INDEX:
            id = wcstoul(argv[current_index + i], nullptr, 0);
            break;
        }
    }

    auto fd = bpf_map_get_fd_by_id(id);
    if (fd < 0)
        return ERROR_INVALID_PARAMETER;

    if (pinpath.empty()) {
        bpf_map_info info{};
        uint32_t size = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd, &info, &size) == 0) {
            pinpath = info.name;
        }
    }
    if (!pinpath.empty()) {
        status = f(fd, pinpath.c_str());
    } else {
        status = ERROR_INVALID_PARAMETER;
    }
    Platform::_close(fd);

    return status;
}

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
handle_ebpf_pin_map(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    return handle_ebpf_pinunpin_map_common(
        machine, argv, current_index, argc, flags, data, done, [](auto fd, auto pinpath) {
            return bpf_obj_pin(fd, pinpath);
        });
}

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
handle_ebpf_unpin_map(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    // Unpin map from a specific pin path.
    return handle_ebpf_pinunpin_map_common(
        machine, argv, current_index, argc, flags, data, done, [](auto, auto pinpath) {
            return ebpf_object_unpin(pinpath);
        });
}
