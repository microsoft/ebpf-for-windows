// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>
#include <iomanip>
#include <netsh.h>
#include <set>
#include <string>
#include <vector>
#include "bpf/bpf.h"
#include "ebpf_api.h"
#include "ebpf_windows.h"
#include "pins.h"
#include "platform.h"
#include "tokens.h"

unsigned long
handle_ebpf_show_pins(
    const wchar_t* machine,
    wchar_t** argv,
    unsigned long current_index,
    unsigned long argc,
    unsigned long flags,
    const void* data,
    int* done)
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
    return EBPF_SUCCESS;
}
