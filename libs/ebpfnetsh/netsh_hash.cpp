// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_api.h"
#include "netsh_hash.h"
#include "platform.h"
#include "tokens.h"
#include "utilities.h"

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

// The following function uses Windows-specific types as inputs to match
// the definition of "FN_HANDLE_CMD" in the public NetSh.h file.
unsigned long
handle_ebpf_show_hash(
    IN LPCWSTR machine,
    _Inout_updates_(argc) LPWSTR* argv,
    IN DWORD current_index,
    IN DWORD argc,
    IN DWORD flags,
    IN LPCVOID data,
    OUT BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {
        {TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
        {TOKEN_HASHONLY, NS_REQ_ZERO, FALSE},
    };
    const int FILENAME_INDEX = 0;
    const int HASHONLY_INDEX = 1;

    unsigned long tag_type[_countof(tags)] = {0};

    unsigned long status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    std::string filename;
    bool hash_only = false;
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case FILENAME_INDEX: {
            filename = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case HASHONLY_INDEX: {
            hash_only = true;
            break;
        }
        default:
            status = ERROR_INVALID_SYNTAX;
            break;
        }
    }

    if (status != NO_ERROR) {
        return status;
    }

    // First get the size of the hash section.
    size_t hash_size = 0;
    ebpf_result_t result = ebpf_api_get_data_section(filename.c_str(), "hash", nullptr, &hash_size);

    if (result == EBPF_INVALID_OBJECT) {
        std::cout << "Error: No such file or directory opening " << filename << std::endl;
        return ERROR_SUPPRESS_OUTPUT;
    } else if (result == EBPF_OBJECT_NOT_FOUND) {
        std::cout << "Error: No hash section found in " << filename << std::endl;
        return ERROR_SUPPRESS_OUTPUT;
    } else if (result != EBPF_SUCCESS) {
        std::cout << "Error: Reading hash from " << filename << " failed: " << result << std::endl;
        return ERROR_SUPPRESS_OUTPUT;
    }

    if (hash_size == 0) {
        std::cout << "Error: Hash section is empty in " << filename << std::endl;
        return ERROR_SUPPRESS_OUTPUT;
    }

    // Allocate buffer and get the hash data.
    std::vector<uint8_t> hash_data(hash_size);
    result = ebpf_api_get_data_section(filename.c_str(), "hash", hash_data.data(), &hash_size);

    if (result != EBPF_SUCCESS) {
        std::cout << "Error: Reading hash data from " << filename << " failed: " << result << std::endl;
        return ERROR_SUPPRESS_OUTPUT;
    }

    // Truncate hash to size of a SHA-256 hash if larger.
    if (hash_size > 32) {
        std::cerr << "Warning: Hash data (" << hash_size << " bytes) truncated to 32 bytes (SHA-256 size)."
                  << std::endl;
        hash_size = 32;
    }

    // Resize vector to actual hash size.
    hash_data.resize(hash_size);

    if (hash_only) {
        // Print hash in PowerShell Get-FileHash format (uppercase, no spaces).
        for (size_t i = 0; i < hash_size; i++) {
            std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned int>(hash_data[i]);
        }
        std::cout << std::dec << std::nouppercase << std::endl; // Reset formatting.
    } else {
        // Print detailed hash information.
        std::cout << "Hash for " << filename << ":" << std::endl;
        std::cout << "Size: " << hash_size << " bytes" << std::endl;
        std::cout << "Data: ";

        // Print hash in hexadecimal format with spaces.
        for (size_t i = 0; i < hash_size; i++) {
            if (i > 0 && i % 16 == 0) {
                std::cout << std::endl << "      ";
            }
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(hash_data[i]);
            if (i < hash_size - 1) {
                std::cout << " ";
            }
        }
        std::cout << std::dec << std::endl; // Reset to decimal format.
    }

    return NO_ERROR;
}