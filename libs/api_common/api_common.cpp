// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdint.h>
#include <string>
#include <vector>
#include <Windows.h>
#pragma warning(push)
#pragma warning(disable : 4100) // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244) // 'conversion' conversion from 'type1' to
                                // 'type2', possible loss of data
#undef VOID
#include "ebpf_verifier.hpp"
#pragma warning(pop)

const char*
allocate_error_string(const std::string& str, uint32_t* length = nullptr)
{
    char* error_message;
    size_t error_message_length = str.size() + 1;
    error_message = (char*)malloc(error_message_length);
    if (error_message != nullptr) {
        strcpy_s(error_message, error_message_length, str.c_str());
        if (length != nullptr) {
            *length = (uint32_t)error_message_length;
        }
    }
    return error_message; // Error;
}

std::vector<uint8_t>
convert_ebpf_program_to_bytes(const std::vector<ebpf_inst>& instructions)
{
    return {reinterpret_cast<const uint8_t*>(instructions.data()),
            reinterpret_cast<const uint8_t*>(instructions.data()) + instructions.size() * sizeof(ebpf_inst)};
}

int
get_file_size(const char* filename, size_t* byte_code_size)
{
    int result = 0;
    *byte_code_size = NULL;
    struct stat st = {0};
    result = stat(filename, &st);
    if (!result) {
        std::cout << "file size " << st.st_size << std::endl;
        *byte_code_size = st.st_size;
    }

    return result;
}
