// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_platform.h"

#include <DbgHelp.h>
#include <optional>

inline ebpf_result_t
_ebpf_symbol_decoder_initialize()
{
    // Initialize DbgHelp.dll.
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    if (!SymInitialize(GetCurrentProcess(), nullptr, TRUE)) {
        return EBPF_NO_MEMORY;
    }
    return EBPF_SUCCESS;
}

inline void
_ebpf_symbol_decoder_deinitialize()
{
    SymCleanup(GetCurrentProcess());
}

inline ebpf_result_t
_ebpf_decode_symbol(
    uintptr_t address,
    std::string& name,
    uint64_t& displacement,
    std::optional<uint32_t>& line_number,
    std::optional<std::string>& file_name)
{
    try {

        std::vector<uint8_t> symbol_buffer(sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR));
        SYMBOL_INFO* symbol = reinterpret_cast<SYMBOL_INFO*>(symbol_buffer.data());
        IMAGEHLP_LINE64 line;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYM_NAME;

        if (!SymFromAddr(GetCurrentProcess(), address, &displacement, symbol)) {
            return EBPF_NO_MEMORY;
        }

        name = symbol->Name;
        DWORD displacement32 = (DWORD)displacement;

        if (!SymGetLineFromAddr64(GetCurrentProcess(), address, &displacement32, &line)) {
            line_number = std::nullopt;
            file_name = std::nullopt;
            return EBPF_SUCCESS;
        }

        line_number = line.LineNumber;
        file_name = line.FileName;
        return EBPF_SUCCESS;
    } catch (std::bad_alloc&) {
        return EBPF_NO_MEMORY;
    }
}