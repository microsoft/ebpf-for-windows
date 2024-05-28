// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "ebpf_api.h"
#include "ebpf_windows.h"
#include "pins.h"
#include "platform.h"
#include "tokens.h"

#include <iomanip>
#include <iostream>
#include <set>
#include <string>
#include <vector>

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
handle_ebpf_show_pins(
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
    std::cout << "     ID     Type  Path\n";
    std::cout << "=======  =======  ==============\n";

    // Read all pin paths.  Currently we get them in a non-deterministic
    // order, so we use a std::set to sort them in code point order.
    char pinpath[EBPF_MAX_PIN_PATH_LENGTH] = "";
    std::set<std::string> paths;
    while (ebpf_get_next_pinned_program_path(pinpath, pinpath) == EBPF_SUCCESS) {
        paths.insert(pinpath);
    }

    // Now walk through all paths in code point order.
    for (auto path : paths) {
        int program_fd = bpf_obj_get(path.c_str());
        if (program_fd < 0) {
            continue;
        }

        struct bpf_prog_info info = {};
        uint32_t info_size = (uint32_t)sizeof(info);
        if (bpf_obj_get_info_by_fd(program_fd, &info, &info_size) == 0) {
            printf("%7u  Program  %s\n", info.id, path.c_str());
        }

        Platform::_close(program_fd);
    }
    return NO_ERROR;
}
