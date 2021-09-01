// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <iostream>
#include <string>
#include <windows.h>
#include <unordered_map>
#include "bpf.h"
#include "ebpf_api.h"
#include "libbpf.h"
#include "ebpf_nethooks.h"

const char* app_map = "data_usage::app_map";
const char* byte_map = "data_usage::byte_map";
const char* flow_program_path = "data_usage::flow_program";
const char* flow_program_link = "data_usage::flow_program_link";
const char* mac_program_path = "data_usage::mac_program";
const char* mac_program_link = "data_usage::mac_program_link";

typedef struct _app_name
{
    wchar_t name[32];
} app_name_t;

int load(int /*argc*/, char** /*argv*/)
{
    const char* error_message = nullptr;
    int error = 0;
    ebpf_result_t result{};

    // Load and attach FLOW program

    bpf_object* flow_object = nullptr;
    bpf_program* flow_program = nullptr;
    bpf_link* flow_link = nullptr;
    fd_t flow_program_fd = 0ul;

    result = ebpf_program_load(
        "associatetoflow.o", &EBPF_PROGRAM_TYPE_FLOW, &EBPF_ATTACH_TYPE_FLOW, EBPF_EXECUTION_JIT, &flow_object, &flow_program_fd, &error_message);
    if (result != EBPF_SUCCESS)
    {
        std::cerr << "Failed to load associatetoflow eBPF program:" << error_message << std::endl;
        ebpf_free_string(error_message);
        return 1;
    }
    flow_program = bpf_program__next(nullptr, flow_object);
    if (flow_program == nullptr)
    {
        std::cerr << "Failed to find associatetoflow eBPF program from object." << std::endl;
        return 1;
    }
    result = ebpf_program_attach(flow_program, &EBPF_ATTACH_TYPE_FLOW, nullptr, 0, &flow_link);
    if (result != ERROR_SUCCESS)
    {
        std::cerr << "Failed to attach associatetoflow eBPF program: " << result << std::endl;
        return 1;
    }

    // Load and attach MAC program

    bpf_object* mac_object = nullptr;
    bpf_program* mac_program = nullptr;
    bpf_link* mac_link = nullptr;
    fd_t mac_program_fd = 0ul;

    result = ebpf_program_load(
        "countbytes.o", &EBPF_PROGRAM_TYPE_MAC, &EBPF_ATTACH_TYPE_MAC, EBPF_EXECUTION_JIT, &mac_object, &mac_program_fd, &error_message);
    if (result != EBPF_SUCCESS)
    {
        std::cerr << "Failed to load countbytes eBPF program: " << error_message << std::endl;
        ebpf_free_string(error_message);
        return 1;
    }
    mac_program = bpf_program__next(nullptr, mac_object);
    if (mac_program == nullptr)
    {
        std::cerr << "Failed to find countbytes eBPF program from object." << std::endl;
        return 1;
    }
    result = ebpf_program_attach(mac_program, &EBPF_ATTACH_TYPE_MAC, nullptr, 0, &mac_link);
    if (result != ERROR_SUCCESS)
    {
        std::cerr << "Failed to attach countbytes eBPF program: " << result << std::endl;
        return 1;
    }

    // Get map handles
    fd_t flow_map_fd = bpf_object__find_map_fd_by_name(flow_object, "app_map");
    if (flow_map_fd <= 0)
    {
        std::cerr << "Failed to find eBPF map : app_map" << std::endl;
        return 1;
    }
    fd_t mac_map_fd = bpf_object__find_map_fd_by_name(mac_object, "byte_map");
    if (mac_map_fd <= 0)
    {
        std::cerr << "Failed to find eBPF map : byte_map" << std::endl;
        return 1;
    }

    // Pin maps for later reference
    result = ebpf_object_pin(flow_map_fd, app_map);
    if (result != EBPF_SUCCESS)
    {
        std::cerr << "Failed to pin app_map: " << result << std::endl;
        return 1;
    }
    result = ebpf_object_pin(mac_map_fd, byte_map);
    if (result != EBPF_SUCCESS)
    {
        std::cerr << "Failed to pin byte_map: " << result << std::endl;
        return 1;
    }

    // Pin programs and link
    error = bpf_link__pin(flow_link, flow_program_link);
    if (error != ERROR_SUCCESS)
    {
        std::cerr << "Failed to pin eBPF link: " << error << std::endl;
        return 1;
    }
    error = bpf_program__pin(flow_program, flow_program_path);
    if (error != ERROR_SUCCESS)
    {
        std::cerr << "Failed to pin eBPF program: " << error << std::endl;
        return 1;
    }
    error = bpf_link__pin(mac_link, mac_program_link);
    if (error != ERROR_SUCCESS)
    {
        std::cerr << "Failed to pin eBPF link: " << error << std::endl;
        return 1;
    }
    error = bpf_program__pin(mac_program, mac_program_path);
    if (error != ERROR_SUCCESS)
    {
        std::cerr << "Failed to pin eBPF program: " << error << std::endl;
        return 1;
    }

    return 0;
}

int unload(int /*argc*/, char** /*argv*/)
{
    ebpf_object_unpin(app_map);
    ebpf_object_unpin(byte_map);
    ebpf_object_unpin(flow_program_link);
    ebpf_object_unpin(flow_program_path);
    ebpf_object_unpin(mac_program_link);
    ebpf_object_unpin(mac_program_path);
    ebpf_api_terminate();
    return 0;
}

int query(int /*argc*/, char** /*argv*/)
{
    five_tuple_t key{};
    app_name_t app_name{};
    uint64_t byte_count = 0ull;
    int query_result;

    // Get pinned map handles
    fd_t flow_map_fd = ebpf_object_get((char*)app_map);
    if (flow_map_fd == ebpf_fd_invalid)
    {
        std::cerr << "Failed to look up eBPF app_map" << std::endl;
        return 1;
    }
    fd_t mac_map_fd = ebpf_object_get((char*)byte_map);
    if (mac_map_fd == ebpf_fd_invalid)
    {
        std::cerr << "Failed to look up eBPF byte_map" << std::endl;
        return 1;
    }

    std::unordered_map<std::wstring, uint64_t> data_usage_map;
    std::unordered_map<std::wstring, uint64_t>::iterator itr;

    // Loop every 10 seconds to query data from both maps
    while (true)
    {
        std::cout << std::endl << "Querying..." << std::endl;

        // Get the first key of the application map
        query_result = bpf_map_get_next_key(flow_map_fd, nullptr, &key);

        // Checks if key exists
        while (query_result == ERROR_SUCCESS)
        {
            // Find application name value using the key
            app_name = {};
            query_result = bpf_map_lookup_elem(flow_map_fd, &key, &app_name);
            if (query_result != ERROR_SUCCESS)
            {
                std::cerr << "Failed to look up eBPF map entry: " << query_result << std::endl;
                return 1;
            }
            std::wstring app(app_name.name);
            std::cout << "App entry found: ";
            std::wcout << app << std::endl;

            // Find byte count value using the key
            byte_count = 0ull;
            query_result = bpf_map_lookup_elem(mac_map_fd, &key, &byte_count);

            // Both application and byte count are found so add into map
            if (query_result == ERROR_SUCCESS)
            {
                std::cout << " ... Byte entry found: ";
                std::wcout << byte_count << std::endl;
                if (data_usage_map.find(app) != data_usage_map.end())
                {
                    data_usage_map.at(app) += byte_count;
                }
                else
                {
                    data_usage_map[app] = byte_count;
                }
                bpf_map_delete_elem(mac_map_fd, &key);
            }
            else
            {
                std::cout << " ... Byte entry deleted or not stored. \n";
            }
            // Get the next key and loop again
            query_result = bpf_map_get_next_key(flow_map_fd, &key, &key);
        }

        // Print data usage
        for (itr = data_usage_map.begin(); itr != data_usage_map.end(); itr++)
        {
            std::cout << "Data Usage: ";
            std::wcout << itr->first << " ";
            std::cout << (unsigned int)itr->second << std::endl;
        }

        Sleep(10000);
    }
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
    {"query", "query\tQuery data usage", query}};

void print_usage(char* path)
{
    std::cerr << "Usage: " << path << " command" << std::endl;
    for (auto& cmd : commands)
    {
        std::cerr << "\t" << cmd.name << std::endl;
    }
}

int main(int argc, char** argv)
{
    uint32_t initiate_result = ebpf_api_initiate();
    if (initiate_result != ERROR_SUCCESS)
    {
        std::cerr << "ebpf_api_initiate failed: " << initiate_result << std::endl;
        return 1;
    }

    if (argc < 2)
    {
        print_usage(argv[0]);
        return 1;
    }
    for (const auto& cmd : commands)
    {
        if (_stricmp(cmd.name, argv[1]) == 0)
        {
            return cmd.operation(argc - 2, argv + 2);
        }
    }
    print_usage(argv[0]);
    return 1;
}