// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"

#include <windows.h>
#include <io.h>
#include <iostream>
#include <string>

const char* process_map = "port_quota::process_map";
const char* limits_map = "port_quota::limits_map";
const char* program_path = "port_quota::program";
const char* program_link = "port_quota::program_link";

typedef struct _process_entry
{
    uint32_t count;
    wchar_t name[32];
} process_entry_t;

int
load(int argc, char** argv)
{
    ebpf_result_t result;
    bpf_object* object = nullptr;
    bpf_program* program = nullptr;
    bpf_link* link = nullptr;
    fd_t program_fd;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    // TODO(#1121): update this utility to be capable of using bindmonitor.sys.
    object = bpf_object__open("bindmonitor.o");
    if (object == nullptr) {
        fprintf(stderr, "Failed to open port quota eBPF program\n");
        return 1;
    }

    result = ebpf_object_set_execution_type(object, EBPF_EXECUTION_JIT);
    if (result != EBPF_SUCCESS) {
        fprintf(stderr, "Failed to set execution type\n");
        return 1;
    }
    program = bpf_object__next_program(object, nullptr);
    if (bpf_object__load(object) < 0) {
        fprintf(stderr, "Failed to load port quota eBPF program\n");
        size_t log_buffer_size;
        fprintf(stderr, "%s", bpf_program__log_buf(program, &log_buffer_size));
        bpf_object__close(object);
        return 1;
    }
    program_fd = bpf_program__fd(program);

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
    if (bpf_obj_pin(process_map_fd, process_map) < 0) {
        fprintf(stderr, "Failed to pin eBPF program: %d\n", errno);
        return 1;
    }
    if (bpf_obj_pin(limits_map_fd, limits_map) < 0) {
        fprintf(stderr, "Failed to pin eBPF program: %d\n", errno);
        return 1;
    }

    program = bpf_object__next_program(object, nullptr);
    if (program == nullptr) {
        fprintf(stderr, "Failed to find eBPF program from object.\n");
        return 1;
    }
    result = ebpf_program_attach(program, &EBPF_ATTACH_TYPE_BIND, nullptr, 0, &link);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to attach eBPF program\n");
        return 1;
    }

    if (bpf_link__pin(link, program_link) < 0) {
        fprintf(stderr, "Failed to pin eBPF link: %d\n", errno);
        return 1;
    }

    if (bpf_program__pin(program, program_path) < 0) {
        fprintf(stderr, "Failed to pin eBPF program: %d\n", errno);
        return 1;
    }

    return 0;
}

int
unload(int argc, char** argv)
{
    ebpf_result_t result;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    result = ebpf_object_unpin(program_path);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF program: %d\n", result);
    }
    result = ebpf_object_unpin(program_link);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF link: %d\n", result);
    }
    result = ebpf_object_unpin(limits_map);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF map: %d\n", result);
    }
    result = ebpf_object_unpin(process_map);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to unpin eBPF map: %d\n", result);
    }
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
    map_fd = bpf_obj_get((char*)process_map);
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
    _close(map_fd);
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

    map_fd = bpf_obj_get((char*)limits_map);
    if (map_fd == ebpf_fd_invalid) {
        fprintf(stderr, "Failed to look up eBPF map.\n");
        return 1;
    }

    result = bpf_map_update_elem(map_fd, &key, &value, EBPF_ANY);
    if (result != EBPF_SUCCESS) {
        fprintf(stderr, "Failed to update eBPF map element: %d\n", result);
        return 1;
    }

    _close(map_fd);

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
