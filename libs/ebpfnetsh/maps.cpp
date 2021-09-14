// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>
#include <iomanip>
#include <netsh.h>
#include <string>
#include <vector>
#include "ebpf_api.h"
#include "ebpf_windows.h"
#include "platform.h"
#include "maps.h"
#include "tokens.h"

static std::string _map_type_names[] = {
    "Other", "Hash", "Array", "Program array", "Per-CPU hash table", "Per-CPU array", "Hash of maps", "Array of maps"};

static std::string
_get_map_type_name(ebpf_map_type_t type)
{
    int index = (type >= _countof(_map_type_names)) ? 0 : type;
    return _map_type_names[index];
}

DWORD
handle_ebpf_show_maps(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    ebpf_result_t result;

    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    std::cout << "\n";
    std::cout << "                     Key  Value      Max  Inner\n";
    std::cout << "          Map Type  Size   Size  Entries  Index\n";
    std::cout << "==================  ====  =====  =======  =====\n";

    fd_t map_fd = ebpf_fd_invalid;
    for (;;) {
        fd_t next_map_fd;
        result = ebpf_get_next_map(map_fd, &next_map_fd);
        if (result != EBPF_SUCCESS) {
            break;
        }

        if (map_fd != ebpf_fd_invalid) {
            Platform::_close(map_fd);
        }
        map_fd = next_map_fd;

        if (map_fd == ebpf_fd_invalid) {
            break;
        }

        ebpf_map_definition_in_file_t map_definition;
        result = ebpf_map_query_definition(
            map_fd,
            &map_definition.size,
            (uint32_t*)&map_definition.type,
            &map_definition.key_size,
            &map_definition.value_size,
            &map_definition.max_entries,
            &map_definition.inner_map_idx);
        if (result != EBPF_SUCCESS) {
            break;
        }

        std::cout << std::setw(18) << std::right << _get_map_type_name(map_definition.type) << std::setw(6)
                  << std::right << map_definition.key_size << std::setw(7) << std::right << map_definition.value_size
                  << std::setw(9) << std::right << map_definition.max_entries << std::setw(7) << std::right
                  << map_definition.inner_map_idx << "\n";
    }
    if (map_fd != ebpf_fd_invalid) {
        Platform::_close(map_fd);
    }
    return result;
}
