// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <iostream>
#include <string>
#include <windows.h>
#include "bpf.h"
#include "ebpf_api.h"
#include "libbpf.h"

const char* process_map = "port_quota::process_map";
const char* limits_map = "port_quota::limits_map";
const char* program_link = "port_quota::program_link";

typedef struct _process_entry
{
    uint32_t count;
    wchar_t name[32];
} process_entry_t;

int
load(int argc, char** argv)
{
    const char* error_message = NULL;
    ebpf_result_t result;
    int error;
    bpf_object* object = nullptr;
    bpf_program* program = nullptr;
    bpf_link* link = nullptr;
    fd_t program_fd;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    result = ebpf_program_load(
        "bindmonitor.o", nullptr, nullptr, EBPF_EXECUTION_INTERPRET, &object, &program_fd, &error_message);
    if (result != EBPF_SUCCESS) {
        fprintf(stderr, "Failed to load port quota eBPF program\n");
        fprintf(stderr, "%s", error_message);
        ebpf_free_string(error_message);
        return 1;
    }

    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");
    if (process_map_fd <= 0) {
        fprintf(stderr, "Failed to find eBPF map : %s\n", process_map);
        return 1;
    }
    fd_t limits_map_fd = bpf_object__find_map_fd_by_name(object, "limits_map");
    if (limits_map_fd <= 0) {
        fprintf(stderr, "Failed to find eBPF map : %s\n", limits_map);
        return 1;
    }
    result = ebpf_object_pin(process_map_fd, process_map);
    if (result != EBPF_SUCCESS) {
        fprintf(stderr, "Failed to pin eBPF program: %d\n", result);
        return 1;
    }
    result = ebpf_object_pin(limits_map_fd, limits_map);
    if (result != EBPF_SUCCESS) {
        fprintf(stderr, "Failed to pin eBPF program: %d\n", result);
        return 1;
    }

    program = bpf_program__next(nullptr, object);
    if (program == nullptr) {
        fprintf(stderr, "Failed to find eBPF program from object.\n");
        return 1;
    }
    result = ebpf_program_attach(program, &EBPF_ATTACH_TYPE_BIND, nullptr, 0, &link);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to attach eBPF program\n");
        return 1;
    }

    error = bpf_link__pin(link, program_link);
    if (error != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to pin eBPF program: %d\n", result);
        return 1;
    }
    return 0;
}

int
unload(int argc, char** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    ebpf_object_unpin(program_link);
    ebpf_object_unpin(limits_map);
    ebpf_object_unpin(process_map);
    return 1;
}

int
stats(int argc, char** argv)
{
    fd_t map_fd;
    int result;
    uint64_t pid;
    process_entry_t process_entry;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    map_fd = ebpf_object_get((char*)process_map);
    if (map_fd == ebpf_fd_invalid) {
        fprintf(stderr, "Failed to look up eBPF map\n");
        return 1;
    }

    printf("Pid\tCount\tAppId\n");
    result = bpf_map_get_next_key(map_fd, nullptr, &pid);
    while (result == EBPF_SUCCESS) {
        memset(&process_entry, 0, sizeof(process_entry));
        result = bpf_map_lookup_elem(map_fd, &pid, &process_entry);
        if (result != EBPF_SUCCESS) {
            fprintf(stderr, "Failed to look up eBPF map entry: %d\n", result);
            return 1;
        }
        printf("%lld\t%d\t%S\n", pid, process_entry.count, process_entry.name);
        result = bpf_map_get_next_key(map_fd, &pid, &pid);
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

    fd_t map_fd;
    uint32_t result;
    uint32_t key = 0;

    map_fd = ebpf_object_get((char*)limits_map);
    if (map_fd == ebpf_fd_invalid) {
        fprintf(stderr, "Failed to look up eBPF map.\n");
        return 1;
    }

    result = bpf_map_update_elem(map_fd, &key, &value, EBPF_ANY);
    if (result != EBPF_SUCCESS) {
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
} commands[]{{"load", "load\tLoad the port quota eBPF program", load},
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