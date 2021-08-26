// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <iostream>
#include <string>
#include <windows.h>
#include "bpf.h"
#include "ebpf_api.h"
#include "libbpf.h"
#include "ebpf_nethooks.h"

typedef struct _app_name
{
    wchar_t name[32];
} app_name_t;

int main(int argc, const char** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    const char* error_message = NULL;
    ebpf_result_t result;

    uint32_t initiate_result = ebpf_api_initiate();
    if (initiate_result != ERROR_SUCCESS)
    {
        fprintf(stderr, "ebpf_api_initiate failed: %d\n", initiate_result);
        return 1;
    }

    bpf_object* flow_object = nullptr;
    bpf_program* flow_program = nullptr;
    bpf_link* flow_link = nullptr;
    fd_t flow_program_fd;

    result = ebpf_program_load(
        "associatetoflow.o", &EBPF_PROGRAM_TYPE_FLOW, &EBPF_ATTACH_TYPE_FLOW, EBPF_EXECUTION_JIT, &flow_object, &flow_program_fd, &error_message);
    if (result != EBPF_SUCCESS)
    {
        fprintf(stderr, "Failed to load associatetoflow eBPF program: %s\n", error_message);
        ebpf_free_string(error_message);
        return 1;
    }
    flow_program = bpf_program__next(nullptr, flow_object);
    if (flow_program == nullptr)
    {
        fprintf(stderr, "Failed to find associatetoflow eBPF program from object.\n");
        return 1;
    }
    result = ebpf_program_attach(flow_program, &EBPF_ATTACH_TYPE_FLOW, nullptr, 0, &flow_link);
    if (result != ERROR_SUCCESS)
    {
        fprintf(stderr, "Failed to attach associatetoflow eBPF program: %d\n", result);
        return 1;
    }

    bpf_object* mac_object = nullptr;
    bpf_program* mac_program = nullptr;
    bpf_link* mac_link = nullptr;
    fd_t mac_program_fd;

    result = ebpf_program_load(
        "countbytes.o", &EBPF_PROGRAM_TYPE_MAC, &EBPF_ATTACH_TYPE_MAC, EBPF_EXECUTION_JIT, &mac_object, &mac_program_fd, &error_message);
    if (result != EBPF_SUCCESS)
    {
        fprintf(stderr, "Failed to load countbytes eBPF program: %s\n", error_message);
        ebpf_free_string(error_message);
        return 1;
    }
    mac_program = bpf_program__next(nullptr, mac_object);
    if (mac_program == nullptr)
    {
        fprintf(stderr, "Failed to find countbytes eBPF program from object.\n");
        return 1;
    }
    result = ebpf_program_attach(mac_program, &EBPF_ATTACH_TYPE_MAC, nullptr, 0, &mac_link);
    if (result != ERROR_SUCCESS)
    {
        fprintf(stderr, "Failed to attach countbytes eBPF program: %d\n", result);
        return 1;
    }

    five_tuple_t key = {};
    app_name_t app_name = {};
    uint64_t byte_count = {};
    int query_result;

    // Get map handles
    fd_t flow_map_fd = bpf_object__find_map_fd_by_name(flow_object, "app_map");
    if (flow_map_fd <= 0)
    {
        fprintf(stderr, "Failed to find eBPF map : app_map\n");
        return 1;
    }
    fd_t mac_map_fd = bpf_object__find_map_fd_by_name(mac_object, "byte_map");
    if (mac_map_fd <= 0)
    {
        fprintf(stderr, "Failed to find eBPF map : byte_map\n");
        return 1;
    }

    // Loop every 10 seconds to query data from both maps
    while (true)
    {
        fprintf(stdout, "\nQuerying...\n");

        // Get the first key of the application map
        query_result = bpf_map_get_next_key(flow_map_fd, nullptr, &key);

        // Checks if key exists
        while (query_result == ERROR_SUCCESS)
        {
            // Find application name value using the key
            memset(&app_name, 0, sizeof(app_name));
            query_result = bpf_map_lookup_elem(flow_map_fd, &key, &app_name);
            if (query_result != ERROR_SUCCESS)
            {
                fprintf(stderr, "Failed to look up eBPF map entry: %d\n", query_result);
                ebpf_api_terminate();
                return 1;
            }

            // Find byte count value using the key
            memset(&byte_count, 0, sizeof(byte_count));
            query_result = bpf_map_lookup_elem(mac_map_fd, &key, &byte_count);

            // Both application and byte count are found so print to console
            if (query_result == ERROR_SUCCESS)
            {
                fprintf(stdout, "Application: %S \n", app_name.name);
                fprintf(stdout, "\t- Byte Count: %u \n", (unsigned int)byte_count);
            }

            // Get the next key and loop again
            query_result = bpf_map_get_next_key(flow_map_fd, &key, &key);
        };

        Sleep(10000);
    }
}