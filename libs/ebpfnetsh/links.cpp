// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define WIN32_LEAN_AND_MEAN
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"
#include "ebpf_windows.h"
#include "links.h"
#include "platform.h"
#include "tokens.h"

#include <windows.h>
#include <iomanip>
#include <iostream>
#include <netsh.h>
#include <string>
#include <vector>

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
handle_ebpf_show_links(
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
    std::cout << "   Link  Program  Attach\n";
    std::cout << "     ID       ID  Type\n";
    std::cout << "=======  =======  =============\n";

    uint32_t link_id = 0;
    for (;;) {
        if (bpf_link_get_next_id(link_id, &link_id) < 0) {
            break;
        }

        fd_t link_fd = bpf_link_get_fd_by_id(link_id);
        if (link_fd < 0) {
            break;
        }

        struct bpf_link_info info;
        uint32_t info_size = (uint32_t)sizeof(info);
        if (bpf_obj_get_info_by_fd(link_fd, &info, &info_size) == 0) {
            const char* attach_type_name = ebpf_get_attach_type_name(&info.attach_type_uuid);

            printf("%7u%9u  %s\n", info.id, info.prog_id, attach_type_name);
        }

        Platform::_close(link_fd);
    }
    return EBPF_SUCCESS;
}
