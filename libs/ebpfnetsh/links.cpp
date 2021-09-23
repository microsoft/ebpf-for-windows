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
#include "ebpf_api.h"
#include "ebpf_windows.h"
#include "platform.h"
#include "links.h"
#include "tokens.h"

DWORD
handle_ebpf_show_links(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    std::cout << "\n";
    std::cout << "   Link  Program\n";
    std::cout << "     ID       ID\n";
    std::cout << "=======  =======\n";

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
            printf("%7u%9u\n", info.id, info.prog_id);
        }

        Platform::_close(link_fd);
    }
    return EBPF_SUCCESS;
}
