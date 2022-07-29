// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>
#include <iomanip>
#include <netsh.h>
#include <string>
#include <vector>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"
#include "ebpf_windows.h"
#include "platform.h"
#include "maps.h"
#include "tokens.h"

DWORD
handle_ebpf_show_maps(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(argv);
    UNREFERENCED_PARAMETER(current_index);
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    std::cout << "\n";
    std::cout << "                             Key  Value      Max  Inner\n";
    std::cout << "    ID            Map Type  Size   Size  Entries     ID  Pins  Name\n";
    std::cout << "======  ==================  ====  =====  =======  =====  ====  ========\n";

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
                "%6u  %18s%6u%7u%9u%7d%6u  %s\n",
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
