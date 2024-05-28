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
