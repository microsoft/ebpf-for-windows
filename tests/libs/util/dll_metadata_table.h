// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <map>
#include <string>
#include <Windows.h>

#include "bpf2c.h"
#include "ebpf_platform.h"
typedef int32_t fd_t;

#pragma once

class dll_metadata_table
{
  public:
    /**
     * @brief Load the named metadata_table from the DLL.
     *
     * @param[in] dll_name Name of a DLL containing an eBPF program.
     * @param[in] table_name Metadata table to load.
     */
    dll_metadata_table(const std::string& dll_name, const std::string& table_name);

    /**
     * @brief Unload the metadata_table and unload the DLL.
     *
     */
    ~dll_metadata_table();

    /**
     * @brief Invoke the specified eBPF program.
     *
     * @param[in] name eBPF program name.
     * @param[in] context Pointer to the context variable to pass to the eBPF
     * program.
     * @return uint64_t Value returned from the eBPF program.
     */
    uint64_t
    invoke(const std::string& name, void* context);

    fd_t
    get_map(const std::string& name);

  private:
    /**
     * @brief Use NMR to bind to helper function and create maps.
     *
     */
    void
    bind_metadata_table();

    /**
     * @brief Unbind from NMR and destroy maps.
     *
     */
    void
    unbind_metadata_table();

    HMODULE dll;
    metadata_table_t* table;
    ebpf_extension_client_t* client_context;

    std::map<std::string, uint64_t (*)(void*)> loaded_programs;
    std::map<std::string, fd_t> loaded_maps;
};
