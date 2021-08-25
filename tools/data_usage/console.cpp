// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// #include <windows.h>
// #include <iostream>
// #include <string>
// #include "ebpf_api.h"
// #include "ebpf_nethooks.h"


#include <iostream>
#include <string>
#include <windows.h>
#include "bpf.h"
#include "ebpf_api.h"
#include "libbpf.h"
#include "ebpf_nethooks.h"

#define MAP_COUNT 1

int main(int argc, const char** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    uint32_t initiate_result = ebpf_api_initiate();
    if (initiate_result != ERROR_SUCCESS)
    {
        std::cerr << "ebpf_api_initiate failed: " << initiate_result << std::endl;
        return 1;
    }

    const char* error_message = NULL;
    ebpf_result_t result;
    bpf_object* flow_object = nullptr;
    bpf_program* flow_program = nullptr;
    bpf_link* flow_link = nullptr;
    fd_t flow_program_fd;

    result = ebpf_program_load(
        "associatetoflow.o", &EBPF_PROGRAM_TYPE_FLOW, &EBPF_ATTACH_TYPE_FLOW, EBPF_EXECUTION_JIT, &flow_object, &flow_program_fd, &error_message);
    if (result != EBPF_SUCCESS) {
        std::cerr << "Failed to load associatetoflow eBPF program: " << error_message << std::endl;
        ebpf_free_string(error_message);
        return 1;
    }
    flow_program = bpf_program__next(nullptr, flow_object);
    if (flow_program == nullptr) {
        std::cerr << "Failed to find associatetoflow eBPF program from object." << std::endl;
        return 1;
    }
    result = ebpf_program_attach(flow_program, &EBPF_ATTACH_TYPE_FLOW, nullptr, 0, &flow_link);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to attach associatetoflow eBPF program: " << result << std::endl;
        return 1;
    }

    bpf_object* mac_object = nullptr;
    bpf_program* mac_program = nullptr;
    bpf_link* mac_link = nullptr;
    fd_t mac_program_fd;

    result = ebpf_program_load(
        "countbytes.o", &EBPF_PROGRAM_TYPE_MAC, &EBPF_ATTACH_TYPE_MAC, EBPF_EXECUTION_JIT, &mac_object, &mac_program_fd, &error_message);
    if (result != EBPF_SUCCESS) {
        std::cerr << "Failed to load countbytes eBPF program: " << error_message << std::endl;
        ebpf_free_string(error_message);
        return 1;
    }
    mac_program = bpf_program__next(nullptr, mac_object);
    if (mac_program == nullptr) {
        std::cerr << "Failed to find countbytes eBPF program from object." << std::endl;
        return 1;
    }
    result = ebpf_program_attach(mac_program, &EBPF_ATTACH_TYPE_MAC, nullptr, 0, &mac_link);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to attach countbytes eBPF program: " << result << std::endl;
        return 1;
    }

    five_tuple_t key = {};
    app_name_t app_name = {};
    uint64_t byte_count = {};
    int query_result;

    fd_t flow_map_fd = bpf_object__find_map_fd_by_name(flow_object, "app_map");
    if (flow_map_fd <= 0) {
        std::cerr << "Failed to find eBPF map : app_map" << std::endl;
        return 1;
    }
    fd_t mac_map_fd = bpf_object__find_map_fd_by_name(mac_object, "byte_map");
    if (mac_map_fd <= 0) {
        std::cerr << "Failed to find eBPF map : byte_map" << std::endl;
        return 1;
    }

    // Loop every 10 seconds to query data from both maps
    while (true)
    {
        std::cout << "Querying..." << std::endl;

        // Get the first key of the map
        query_result = bpf_map_get_next_key(mac_map_fd, nullptr, reinterpret_cast<uint8_t*>(&key));
        std::cerr << "Five-tuple:" << key.v4 << " " << key.protocol << " " << key.dest_port << " " << key.source_port << " " << key.dest_ip << " " << key.source_ip << std::endl;

        // Checks if next key exists
        while (query_result == ERROR_SUCCESS)
        {
            // Find application id value using the key
            memset(&app_name, 0, sizeof(app_name));
            query_result = bpf_map_lookup_elem(flow_map_fd, reinterpret_cast<uint8_t*>(&key), reinterpret_cast<uint8_t*>(&app_name));
            if (query_result != ERROR_SUCCESS)
            {
                std::cerr << "Failed to look up eBPF map app_name entry: " << query_result << std::endl;
                return 1;
            }
            std::cout << "- Application: " << app_name.name << std::endl;

            // Find byte count value using the key
            memset(&byte_count, 0, sizeof(byte_count));
            query_result = bpf_map_lookup_elem(mac_map_fd, reinterpret_cast<uint8_t*>(&key), reinterpret_cast<uint8_t*>(&byte_count));
            if (query_result != ERROR_SUCCESS)
            {
                std::cerr << "Failed to look up eBPF map byte_count entry: " << query_result << std::endl;
                return 1;
            }
            std::cout << "- Byte Count: " << byte_count << std::endl;
            std::cout << std::endl;

            // Get the next key and loop again
            query_result = bpf_map_get_next_key(mac_map_fd, reinterpret_cast<uint8_t*>(&key), reinterpret_cast<uint8_t*>(&key));
        };

        Sleep(10000);
   }
}