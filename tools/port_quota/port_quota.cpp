// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <iostream>
#include <string>
#include <windows.h>
#include "ebpf_api.h"

const unsigned char process_map[] = "port_quota::process_map";
const unsigned char limits_map[] = "port_quota::limits_map";
const unsigned char program_link[] = "port_quota::program_link";

typedef struct _process_entry
{
    uint32_t count;
    wchar_t name[32];
} process_entry_t;

int
load(int argc, char** argv)
{
    ebpf_handle_t program;
    ebpf_handle_t link;
    ebpf_handle_t maps[2];
    uint32_t map_count = _countof(maps);
    const char* error_message = NULL;
    uint32_t result;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    result = ebpf_api_load_program(
        "bindmonitor.o", "bind", EBPF_EXECUTION_INTERPRET, &program, &map_count, maps, &error_message);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to load port quota eBPF program\n");
        fprintf(stderr, "%s", error_message);
        ebpf_free_string(error_message);
        return 1;
    }

    result = ebpf_api_pin_object(maps[0], process_map, sizeof(process_map));
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to pin eBPF program: %d\n", result);
        ebpf_free_string(error_message);
        return 1;
    }
    result = ebpf_api_pin_object(maps[1], limits_map, sizeof(limits_map));
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to pin eBPF program: %d\n", result);
        ebpf_free_string(error_message);
        return 1;
    }

    result = ebpf_api_link_program(program, EBPF_ATTACH_TYPE_BIND, &link);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to attach eBPF program\n");
        return 1;
    }

    result = ebpf_api_pin_object(link, program_link, sizeof(program_link));
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to pin eBPF program: %d\n", result);
        ebpf_free_string(error_message);
        return 1;
    }
    return 0;
}

int
unload(int argc, char** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    ebpf_api_unpin_object(program_link, sizeof(program_link));
    ebpf_api_unpin_object(limits_map, sizeof(limits_map));
    ebpf_api_unpin_object(process_map, sizeof(process_map));
    return 1;
}

int
stats(int argc, char** argv)
{
    ebpf_handle_t map;
    uint32_t result;
    uint64_t pid;
    process_entry_t process_entry;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    result = ebpf_api_get_pinned_map(process_map, sizeof(process_map), &map);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to look up eBPF map: %d\n", result);
        return 1;
    }

    printf("Pid\tCount\tAppId\n");
    result = ebpf_api_get_next_map_key(map, sizeof(uint64_t), nullptr, reinterpret_cast<uint8_t*>(&pid));
    while (result == ERROR_SUCCESS) {
        memset(&process_entry, 0, sizeof(process_entry));
        result = ebpf_api_map_find_element(
            map,
            sizeof(uint64_t),
            reinterpret_cast<uint8_t*>(&pid),
            sizeof(process_entry),
            reinterpret_cast<uint8_t*>(&process_entry));
        if (result != ERROR_SUCCESS) {
            fprintf(stderr, "Failed to look up eBPF map entry: %d\n", result);
            return 1;
        }
        printf("%lld\t%d\t%S\n", pid, process_entry.count, process_entry.name);
        result = ebpf_api_get_next_map_key(
            map, sizeof(uint64_t), reinterpret_cast<uint8_t*>(&pid), reinterpret_cast<uint8_t*>(&pid));
    };
    return 0;
}

int
limit(int argc, char** argv)
{
    uint32_t value;
    if (argc == 0) {
        fprintf(stderr, "limit requires a numerical value\n");
        return 1;
    }
    value = atoi(argv[0]);

    ebpf_handle_t map;
    uint32_t result;
    uint32_t key = 0;

    result = ebpf_api_get_pinned_map(limits_map, sizeof(limits_map), &map);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to look up eBPF map: %d\n", result);
        return 1;
    }

    result = ebpf_api_map_update_element(
        map, sizeof(key), reinterpret_cast<uint8_t*>(&key), sizeof(value), reinterpret_cast<uint8_t*>(&value));
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to update eBPF map element: %d\n", result);
        return 1;
    }

    return 0;
}

typedef int (*operation_t)(int argc, char** argv);
struct
{
    const char* name;
    const char* help;
    operation_t operation;
} commands[]{
    {"load", "load\tLoad the port quota eBPF program", load},
    {"unload", "unload\tUnload the port quota eBPF program", unload},
    {"stats", "stats\tShow stats from the port quota eBPF program", stats},
    {"limit", "limit value\tSet the port quota limit", limit}};

void
print_usage(char* path)
{
    fprintf(stderr, "Usage: %s command\n", path);
    for (auto& cmd : commands) {
        fprintf(stderr, "\t%s\n", cmd.name);
    }
}

int
main(int argc, char** argv)
{
    uint32_t result = ebpf_api_initiate();
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "ebpf_api_initiate failed: %d\n", result);
        return 1;
    }

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    for (const auto& cmd : commands) {
        if (_stricmp(cmd.name, argv[1]) == 0) {
            return cmd.operation(argc - 2, argv + 2);
        }
    }
    print_usage(argv[0]);
    return 1;
}