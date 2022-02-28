// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "dll_metadata_table.h"

#include <stdexcept>

#include "bpf2c.h"
#include "ebpf_platform.h"
#include "ebpf_core_structs.h"
#include "ebpf_core.h"
#include "ebpf_handle.h"
#include "ebpf_object.h"
#include "platform.h"

extern "C" metadata_table_t*
get_metadata_table(const char* name);
typedef struct _ebpf_core_map ebpf_map_t;
extern "C" ebpf_result_t
ebpf_map_create(
    _In_ const ebpf_utf8_string_t* map_name,
    _In_ const ebpf_map_definition_in_memory_t* ebpf_map_definition,
    ebpf_handle_t inner_map_handle,
    _Outptr_ ebpf_map_t** map);

typedef struct _ebpf_object ebpf_object_t;

dll_metadata_table::dll_metadata_table(const std::string& dll_name, const std::string& table_name)
{
    dll = LoadLibraryA(dll_name.c_str());
    if (dll == nullptr) {
        throw std::runtime_error("Failed to load dll");
    }
    auto get_function = reinterpret_cast<decltype(&get_metadata_table)>(GetProcAddress(dll, "get_metadata_table"));
    if (get_function == nullptr) {
        throw std::runtime_error("Failed to find get_metadata_table");
    }
    table = get_function(table_name.c_str());
    if (table == nullptr) {
        throw std::runtime_error("Failed to find table");
    }
    bind_metadata_table();
    program_entry_t* programs;
    size_t count;
    table->programs(&programs, &count);
    for (size_t i = 0; i < count; i++) {
        loaded_programs[programs->function_name] = programs->function;
    }
}

dll_metadata_table::~dll_metadata_table()
{
    unbind_metadata_table();
    FreeLibrary(dll);
}

uint64_t
dll_metadata_table::invoke(const std::string& name, void* context)
{
    auto program = loaded_programs.find(name);
    if (program == loaded_programs.end()) {
        throw std::runtime_error("Can't find the program");
    }
    return program->second(context);
}

fd_t
dll_metadata_table::get_map(const std::string& name)
{
    return loaded_maps[name];
}

void
dll_metadata_table::bind_metadata_table()
{
    helper_function_entry_t* helpers = nullptr;
    size_t helpers_count = 0;
    map_entry_t* maps = nullptr;
    size_t map_count = 0;
    table->helpers(&helpers, &helpers_count);
    table->maps(&maps, &map_count);

    int client_binding_context = 0;
    ebpf_extension_data_t client_data{};
    ebpf_extension_dispatch_table_t client_dispatch_table = {0, sizeof(ebpf_extension_dispatch_table_t), nullptr};
    void* provider_binding_context = nullptr;
    const ebpf_extension_data_t* returned_provider_data;
    const ebpf_extension_dispatch_table_t* returned_provider_dispatch_table;

    GUID module_id = {};
    if (ebpf_guid_create(&module_id) != EBPF_SUCCESS) {
        throw std::runtime_error("ebpf_guid_create failed");
    }

    if (ebpf_extension_load(
            &client_context,
            &ebpf_general_helper_function_interface_id,
            &module_id,
            &client_binding_context,
            &client_data,
            &client_dispatch_table,
            &provider_binding_context,
            &returned_provider_data,
            &returned_provider_dispatch_table,
            nullptr) != EBPF_SUCCESS) {
        throw std::runtime_error("ebpf_extension_load failed for ebpf_general_helper_function_interface_id");
    }

    ebpf_program_data_t* general_helper_program_data = NULL;
    general_helper_program_data = (ebpf_program_data_t*)returned_provider_data->data;
    if (general_helper_program_data == nullptr) {
        throw std::runtime_error("ebpf_extension_load failed for ebpf_general_helper_function_interface_id");
    }

    for (size_t i = 0; i < helpers_count; i++) {
        if (helpers[i].helper_id >= general_helper_program_data->helper_function_addresses->helper_function_count) {
            throw std::runtime_error("ebpf_extension_load failed for ebpf_general_helper_function_interface_id");
        }
        helpers[i].address = reinterpret_cast<decltype(helpers[i].address)>(
            general_helper_program_data->helper_function_addresses->helper_function_address[helpers[i].helper_id]);
    }

    for (size_t i = 0; i < map_count; i++) {
        const ebpf_utf8_string_t map_name{
            reinterpret_cast<uint8_t*>(const_cast<char*>(maps[i].name)), strlen(maps[i].name)};
        ebpf_map_definition_in_memory_t mem_map_definition{
            sizeof(mem_map_definition),
            static_cast<ebpf_map_type_t>(maps[i].definition.type),
            maps[i].definition.key_size,
            maps[i].definition.value_size,
            maps[i].definition.max_entries,
            maps[i].definition.inner_id,
            static_cast<ebpf_pin_type_t>(maps[i].definition.pinning)};

        if (ebpf_map_create(
                &map_name,
                &mem_map_definition,
                ebpf_handle_invalid,
                reinterpret_cast<ebpf_map_t**>(&maps[i].address)) != EBPF_SUCCESS) {
            throw std::runtime_error("ebpf_extension_load failed for ebpf_general_helper_function_interface_id");
        }
        ebpf_handle_t handle;
        if (ebpf_handle_create(&handle, reinterpret_cast<ebpf_object_t*>(maps[i].address)) != EBPF_SUCCESS) {
            throw std::runtime_error("ebpf_handle_create failed");
        }
        fd_t fd = Platform::_open_osfhandle(handle, 0);
        loaded_maps[std::string(maps[i].name)] = fd;
    }
}

void
dll_metadata_table::unbind_metadata_table()
{
    helper_function_entry_t* helpers = nullptr;
    size_t helpers_count = 0;
    map_entry_t* maps = nullptr;
    size_t map_count = 0;
    table->helpers(&helpers, &helpers_count);
    table->maps(&maps, &map_count);

    for (size_t i = 0; i < helpers_count; i++) {
        helpers[i].address = nullptr;
    }

    for (size_t i = 0; i < map_count; i++) {
        ebpf_object_release_reference(reinterpret_cast<ebpf_object_t*>(maps[i].address));
        maps[i].address = nullptr;
    }
    for (auto& [name, fd] : loaded_maps) {
        Platform::_close(fd);
    }
    ebpf_extension_unload(client_context);
}