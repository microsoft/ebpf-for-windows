/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#include "ebpf_verifier.hpp"
#include "windows/windows_platform.hpp"
#include "Verifier.h"
#include <sstream>
#include <iostream>
#include <filesystem>
#include <sys/stat.h>


int get_file_size(char* filename, size_t* byte_code_size)
{
    int result = 0;
    *byte_code_size = NULL;
    struct stat st = { 0 };
    result = stat(filename, &st);
    if (!result)
    {
        std::cout << "file size " << st.st_size << std::endl;
        *byte_code_size = st.st_size;
    }

    return result;
}

static char * allocate_error_string(const std::string& str)
{
    char* retval;
    size_t error_message_length = str.size() + 1;
    retval = (char*)malloc(error_message_length);
    if (retval != nullptr)
    {
        strcpy_s(retval, error_message_length, str.c_str());
    }
    return retval; // Error;
}

static int analyze(raw_program& raw_prog, char ** error_message)
{
    std::ostringstream oss;
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;

    std::variant<InstructionSeq, std::string> prog_or_error = unmarshal(raw_prog, platform);
    if (!std::holds_alternative<InstructionSeq>(prog_or_error)) {
        *error_message = allocate_error_string(std::get<std::string>(prog_or_error));
        return 1; // Error;
    }
    auto& prog = std::get<InstructionSeq>(prog_or_error);
    cfg_t cfg = prepare_cfg(prog, raw_prog.info, true);
    ebpf_verifier_options_t options{ true, false, true };
    bool res = run_ebpf_analysis(oss, cfg, raw_prog.info, &options);
    if (!res) {
        *error_message = allocate_error_string(oss.str());
        return 1; // Error;
    }
    return 0; // Success.
}

int verify(const char* filename, const char* sectionname, uint8_t* byte_code, size_t* byte_code_size, map_create_fp map_create_function, char** error_message)
{
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;

    auto raw_progs = read_elf(filename, sectionname, reinterpret_cast<MapFd*>(map_create_function), nullptr, platform);
    if (raw_progs.size() != 1) {
        return 1; // Error
    }
    raw_program raw_prog = raw_progs.back();

    // copy out the bytecode for the jitter
    if (byte_code) {
        size_t ebpf_bytes = raw_prog.prog.size() * sizeof(ebpf_inst);
        int i = 0;
        for (ebpf_inst inst : raw_prog.prog) {
            char* buf = (char*)&inst;
            for (int j = 0; j < sizeof(ebpf_inst) && i < ebpf_bytes; i++, j++) {
                byte_code[i] = buf[j];
            }                        
        }

        *byte_code_size = ebpf_bytes;        
    }

    return analyze(raw_prog, error_message);
}

int verify_byte_code(const char* path, const char* section_name, const uint8_t* byte_code, size_t byte_code_size, char** error_message)
{
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;
    std::vector<ebpf_inst> instructions { (ebpf_inst*)byte_code, (ebpf_inst*)byte_code + byte_code_size / sizeof(ebpf_inst) };
    program_info info{ platform };
    info.type = platform->get_program_type(section_name, path);

    raw_program raw_prog{ path, section_name, instructions, info };


    return analyze(raw_prog, error_message);
}