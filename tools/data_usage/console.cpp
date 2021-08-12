// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <windows.h>
#include <iostream>
#include <string>
#include "ebpf_api.h"
#include "ebpf_nethooks.h"

#define MAP_COUNT 1

int main(int argc, const char** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    ebpf_handle_t flow_program_handle;
    ebpf_handle_t flow_map_handle[MAP_COUNT];
    ebpf_handle_t flow_link_handle;

    ebpf_handle_t mac_program_handle;
    ebpf_handle_t mac_map_handle[MAP_COUNT];
    ebpf_handle_t mac_link_handle;

    uint32_t count_of_map_handle = MAP_COUNT;
    const char* error_message = nullptr;

    uint32_t result = ebpf_api_initiate();
    if (result != ERROR_SUCCESS)
    {
        std::cerr << "ebpf_api_initiate failed: " << result << std::endl;
        return 1;
    }

    result = ebpf_api_load_program(
        "associatetoflow.o", "flow", EBPF_EXECUTION_JIT, &flow_program_handle, &count_of_map_handle, flow_map_handle, &error_message);

    if (result != ERROR_SUCCESS)
    {
        std::cerr << "Failed to load associatetoflow eBPF program: " << error_message << std::endl;
        ebpf_free_string(error_message);
        return 1;
    }

    result = ebpf_api_link_program(flow_program_handle, EBPF_ATTACH_TYPE_FLOW, &flow_link_handle);
    if (result != ERROR_SUCCESS)
    {
        std::cerr << "Failed to attach associatetoflow eBPF program: " << result << std::endl;
        return 1;
    }

    result = ebpf_api_load_program(
        "countbytes.o", "mac", EBPF_EXECUTION_JIT, &mac_program_handle, &count_of_map_handle, mac_map_handle, &error_message);

    if (result != ERROR_SUCCESS)
    {
        std::cerr << "Failed to load countbytes eBPF program: " << error_message << std::endl;
        ebpf_free_string(error_message);
        return 1;
    }

    result = ebpf_api_link_program(mac_program_handle, EBPF_ATTACH_TYPE_MAC, &mac_link_handle);
    if (result != ERROR_SUCCESS)
    {
        std::cerr << "Failed to attach countbytes eBPF program: " << result << std::endl;
        return 1;
    }

    five_tuple_t key;
    app_id_t app_id;
    uint64_t byte_count;

    // Loop every 10 seconds to query data from both maps
    while (true)
    {
        // Get the first key of the map
        result = ebpf_api_get_next_map_key(mac_map_handle[0], sizeof(five_tuple_t), NULL, reinterpret_cast<uint8_t*>(&key));

        // Checks if next key exists
        while (result == ERROR_SUCCESS)
        {
            // Find application id value using the key
            memset(&app_id, 0, sizeof(app_id));
            result = ebpf_api_map_find_element(
                flow_map_handle[0], sizeof(five_tuple_t), reinterpret_cast<uint8_t*>(&key), sizeof(app_id_t), reinterpret_cast<uint8_t*>(&app_id));
            if (result != ERROR_SUCCESS)
            {
                std::cerr << "Failed to look up eBPF map app_id entry: " << result << std::endl;
                return 1;
            }
            std::cout << "Application: " << app_id.name << std::endl;

            // Find byte count value using the key
            memset(&byte_count, 0, sizeof(byte_count));
            result = ebpf_api_map_find_element(
                mac_map_handle[0], sizeof(five_tuple_t), reinterpret_cast<uint8_t*>(&key), sizeof(uint64_t), reinterpret_cast<uint8_t*>(&byte_count));
            if (result != ERROR_SUCCESS)
            {
                std::cerr << "Failed to look up eBPF map byte_count entry: " << result << std::endl;
                return 1;
            }
            std::cout << "Byte Count: " << byte_count << std::endl;

            // Get the next key and loop again
            result = ebpf_api_get_next_map_key(
                mac_map_handle[0], sizeof(five_tuple_t), reinterpret_cast<uint8_t*>(&key), reinterpret_cast<uint8_t*>(&key));
        };

        Sleep(10000);
    }
}