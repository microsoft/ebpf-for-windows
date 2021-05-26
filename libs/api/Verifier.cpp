/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include <filesystem>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include "api_common.hpp"
#include "api_internal.h"
#include "ebpf_api.h"
#include "ebpf_bind_program_data.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#pragma warning(push)
#pragma warning(disable : 4100) // 'identifier' : unreferenced formal parameter
#pragma warning(disable : 4244) // 'conversion' conversion from 'type1' to
                                // 'type2', possible loss of data
#undef VOID
#include "ebpf_verifier.hpp"
#pragma warning(pop)
#include "ebpf_xdp_program_data.h"
#include "platform.hpp"
#include "tlv.h"
#include "windows_platform.hpp"
#include "Verifier.h"

int
load_byte_code(
    const char* filename,
    const char* sectionname,
    ebpf_verifier_options_t* verifier_options,
    uint8_t* byte_code,
    size_t* byte_code_size,
    ebpf_program_type_t* program_type,
    const char** error_message)
{
    try {

        const ebpf_platform_t* platform = &g_ebpf_platform_windows;

        auto raw_progs = read_elf(filename, sectionname, verifier_options, platform);
        if (raw_progs.size() != 1) {
            return 1; // Error
        }
        raw_program raw_prog = raw_progs.back();

        // Sanity check that we have a program type GUID.
        if (raw_prog.info.type.platform_specific_data == 0) {
            return 1; // Error
        }

        // copy out the bytecode for the jitter
        size_t ebpf_bytes = raw_prog.prog.size() * sizeof(ebpf_inst);
        int i = 0;
        for (ebpf_inst inst : raw_prog.prog) {
            char* buf = (char*)&inst;
            for (int j = 0; j < sizeof(ebpf_inst) && i < ebpf_bytes; i++, j++) {
                byte_code[i] = buf[j];
            }
        }

        *byte_code_size = ebpf_bytes;
        *program_type = *(const GUID*)raw_prog.info.type.platform_specific_data;
    } catch (std::runtime_error& err) {
        auto message = err.what();
        auto message_length = strlen(message) + 1;
        char* error = reinterpret_cast<char*>(calloc(message_length + 1, sizeof(char)));
        if (error) {
            strcpy_s(error, message_length, message);
        }
        *error_message = error;
        return ERROR_INVALID_PARAMETER;
    }

    return 0;
}

uint32_t
ebpf_api_elf_enumerate_sections(
    const char* file,
    const char* section,
    bool verbose,
    const struct _tlv_type_length_value** data,
    const char** error_message)
{
    ebpf_verifier_options_t verifier_options{false, false, false, false, true};
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;
    std::ostringstream str;
    try {
        auto raw_programs = read_elf(file, section ? std::string(section) : std::string(), &verifier_options, platform);
        tlv_sequence sequence;
        for (const auto& raw_program : raw_programs) {
            tlv_sequence stats_sequence;
            if (verbose) {
                std::variant<InstructionSeq, std::string> programOrError = unmarshal(raw_program);
                if (std::holds_alternative<std::string>(programOrError)) {
                    std::cout << "parse failure: " << std::get<std::string>(programOrError) << "\n";
                    return 1;
                }
                auto& program = std::get<InstructionSeq>(programOrError);
                cfg_t controlFlowGraph = prepare_cfg(program, raw_program.info, true);
                std::map<std::string, int> stats = collect_stats(controlFlowGraph);
                for (const auto& [key, value] : stats) {
                    stats_sequence.emplace_back(tlv_pack<tlv_sequence>({tlv_pack(key.c_str()), tlv_pack(value)}));
                }
            }

            sequence.emplace_back(tlv_pack<tlv_sequence>({tlv_pack(raw_program.section.c_str()),
                                                          tlv_pack(raw_program.info.type.platform_specific_data),
                                                          tlv_pack(raw_program.info.map_descriptors.size()),
                                                          tlv_pack(convert_ebpf_program_to_bytes(raw_program.prog)),
                                                          tlv_pack(stats_sequence)}));
        }

        auto retval = tlv_pack(sequence);
        auto local_data = reinterpret_cast<tlv_type_length_value_t*>(malloc(retval.size()));
        memcpy(local_data, retval.data(), retval.size());
        *data = local_data;
    } catch (std::runtime_error e) {
        str << "error: " << e.what();
        *error_message = allocate_error_string(str.str());
        return 1;
    }

    return 0;
}

uint32_t
ebpf_api_elf_disassemble_section(
    const char* file, const char* section, const char** disassembly, const char** error_message)
{
    ebpf_verifier_options_t verifier_options = ebpf_verifier_default_options;
    const ebpf_platform_t* platform = &g_ebpf_platform_windows;
    std::ostringstream error;
    std::ostringstream output;
    try {
        auto raw_programs = read_elf(file, section, &verifier_options, platform);
        raw_program raw_program = raw_programs.back();
        std::variant<InstructionSeq, std::string> programOrError = unmarshal(raw_program);
        if (std::holds_alternative<std::string>(programOrError)) {
            error << "parse failure: " << std::get<std::string>(programOrError);
            *error_message = allocate_error_string(error.str());
            return 1;
        }
        auto& program = std::get<InstructionSeq>(programOrError);
        print(program, output, {});
        *disassembly = allocate_error_string(output.str());
    } catch (std::runtime_error e) {
        error << "error: " << e.what();
        *error_message = allocate_error_string(error.str());
        return 1;
    } catch (std::exception ex) {
        error << "Failed to load eBPF program from " << file;
        *error_message = allocate_error_string(error.str());
        return 1;
    }
    return 0;
}

struct guid_compare
{
    bool
    operator()(const GUID& a, const GUID& b) const
    {
        return (memcmp(&a, &b, sizeof(GUID)) < 0);
    }
};

thread_local std::map<GUID, ebpf_helper::ebpf_memory_ptr, guid_compare> g_program_information_cache;

ebpf_result_t
get_program_type_info(const ebpf_program_information_t** info)
{
    const GUID* program_type = reinterpret_cast<const GUID*>(global_program_info.type.platform_specific_data);
    ebpf_result_t result;
    ebpf_program_information_t* program_information;
    const uint8_t* encoded_data = nullptr;
    size_t encoded_data_size = 0;

    // See if we already have the program information cached.
    auto it = g_program_information_cache.find(*program_type);
    if (it == g_program_information_cache.end()) {
        // Try to query the information from the execution context.
        ebpf_extension_data_t* program_information_data;
        uint32_t error = get_program_information_data(*program_type, &program_information_data);
        if (error == ERROR_SUCCESS) {
            encoded_data = program_information_data->data;
            encoded_data_size = program_information_data->size;
        } else {
            // Fall back to using static data so that verification can be tried
            // (e.g., from a netsh command) even if the execution context isn't running.
            // TODO: remove this in the future.
            if (memcmp(program_type, &EBPF_PROGRAM_TYPE_XDP, sizeof(*program_type)) == 0) {
                encoded_data = _ebpf_encoded_xdp_program_information_data;
                encoded_data_size = sizeof(_ebpf_encoded_xdp_program_information_data);
            } else if (memcmp(program_type, &EBPF_ATTACH_TYPE_BIND, sizeof(*program_type)) == 0) {
                encoded_data = _ebpf_encoded_bind_program_information_data;
                encoded_data_size = sizeof(_ebpf_encoded_bind_program_information_data);
            }
        }
        if (encoded_data == nullptr) {
            return EBPF_INVALID_ARGUMENT;
        }

        result = ebpf_program_information_decode(&program_information, encoded_data, (unsigned long)encoded_data_size);
        if (result != EBPF_SUCCESS) {
            return result;
        }

        g_program_information_cache[*program_type] = ebpf_helper::ebpf_memory_ptr(program_information);
    }

    *info = (const ebpf_program_information_t*)g_program_information_cache[*program_type].get();

    return EBPF_SUCCESS;
}

uint32_t
ebpf_api_elf_verify_section(
    const char* file, const char* section, bool verbose, const char** report, const char** error_message)
{
    std::ostringstream error;

    std::ostringstream output;

    try {
        const ebpf_platform_t* platform = &g_ebpf_platform_windows;
        ebpf_verifier_options_t verifier_options = ebpf_verifier_default_options;
        verifier_options.check_termination = true;
        verifier_options.print_invariants = verbose;
        verifier_options.print_failures = true;
        verifier_options.mock_map_fds = true;

        auto raw_programs = read_elf(file, section, &verifier_options, platform);
        raw_program raw_program = raw_programs.back();
        std::variant<InstructionSeq, std::string> programOrError = unmarshal(raw_program);
        if (std::holds_alternative<std::string>(programOrError)) {
            error << "parse failure: " << std::get<std::string>(programOrError);
            *error_message = allocate_error_string(error.str());
            return 1;
        }
        auto& program = std::get<InstructionSeq>(programOrError);

        // Try again without simplifying.
        verifier_options.no_simplify = true;
        bool res = ebpf_verify_program(output, program, raw_program.info, &verifier_options);
        if (!res) {
            error << "Verification failed";
            *error_message = allocate_error_string(error.str());
            *report = allocate_error_string(output.str());
            return 1;
        }

        output << "Verification succeeded";
        *report = allocate_error_string(output.str());
        return 0;
    } catch (std::runtime_error e) {
        error << "error: " << e.what();
        *error_message = allocate_error_string(error.str());
        return 1;
    } catch (std::exception ex) {
        error << "Failed to load eBPF program from " << file;
        *error_message = allocate_error_string(error.str());
    }

    return 0;
}

void
ebpf_api_elf_free(const tlv_type_length_value_t* data)
{
    free(const_cast<tlv_type_length_value_t*>(data));
}
