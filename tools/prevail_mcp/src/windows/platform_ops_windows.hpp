// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/// @file Windows PlatformOps implementation using ebpf-for-windows APIs.
/// Provides EverParse ELF validation, program enumeration via the C API,
/// Windows TLS management, and fallback verification for clean error messages.

#pragma once

#include "api_common.hpp"
#include "ebpf_api.h"
#include "platform_ops.hpp"

#ifdef _WIN32
#include <ElfWrapper.h>
#endif

namespace prevail_mcp {

/// PlatformOps implementation using ebpf-for-windows APIs.
/// Matches bpf2c's behavior for ELF validation, program enumeration,
/// and error reporting.
class WindowsPlatformOps : public PlatformOps
{
  public:
    explicit WindowsPlatformOps(const prevail::ebpf_platform_t* platform) : platform_(platform) {}

    const prevail::ebpf_platform_t*
    platform() const override
    {
        return platform_;
    }

    std::vector<ProgramEntry>
    list_programs(const std::string& elf_path) override
    {
        ebpf_api_program_info_t* infos = nullptr;
        const char* error_message = nullptr;
        ebpf_result_t result = ebpf_enumerate_programs(elf_path.c_str(), false, &infos, &error_message);
        if (result != EBPF_SUCCESS) {
            std::string err = error_message ? error_message : "Unknown error";
            ebpf_free_string(error_message);
            throw std::runtime_error("Failed to enumerate programs: " + err);
        }

        std::vector<ProgramEntry> entries;
        for (const ebpf_api_program_info_t* p = infos; p != nullptr; p = p->next) {
            entries.push_back({p->section_name ? p->section_name : "", p->program_name ? p->program_name : ""});
        }
        ebpf_free_programs(infos);
        return entries;
    }

    bool
    validate_elf(const std::string& data) override
    {
#ifdef _WIN32
        // ElfCheckElf takes non-const uint8_t* despite not modifying the data.
        return ElfCheckElf(
            data.size(),
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(data.data())),
            static_cast<uint32_t>(data.size()));
#else
        (void)data;
        return true;
#endif
    }

    void
    prepare_tls(const std::string& type_override) override
    {
        ebpf_clear_thread_local_storage();

        if (!type_override.empty()) {
            ebpf_program_type_t program_type{};
            ebpf_attach_type_t attach_type{};
            if (ebpf_get_program_type_by_name(type_override.c_str(), &program_type, &attach_type) != EBPF_SUCCESS) {
                throw std::runtime_error("Unknown program type: " + type_override);
            }
            set_global_program_and_attach_type(&program_type, &attach_type);
        } else {
            set_global_program_and_attach_type(nullptr, nullptr);
        }
    }

    prevail::ebpf_verifier_options_t
    default_options() override
    {
        return ebpf_get_default_verifier_options();
    }

    std::string
    fallback_verify(
        const std::string& data,
        const std::string& section,
        const std::string& program,
        const std::string& type) override
    {
        ebpf_clear_thread_local_storage();
        if (!type.empty()) {
            ebpf_program_type_t type_override{};
            ebpf_attach_type_t attach_override{};
            if (ebpf_get_program_type_by_name(type.c_str(), &type_override, &attach_override) == EBPF_SUCCESS) {
                set_global_program_and_attach_type(&type_override, &attach_override);
            }
        }

        const char* report = nullptr;
        const char* error_msg = nullptr;
        ebpf_api_verifier_stats_t stats{};

        uint32_t verify_result = ebpf_api_elf_verify_program_from_memory(
            data.c_str(),
            data.size(),
            section.empty() ? nullptr : section.c_str(),
            program.empty() ? nullptr : program.c_str(),
            nullptr,
            EBPF_VERIFICATION_VERBOSITY_NORMAL,
            &report,
            &error_msg,
            &stats);

        std::string result_str;
        if (verify_result != 0 && error_msg) {
            result_str = error_msg;
        }
        ebpf_free_string(error_msg);
        ebpf_free_string(report);
        return result_str;
    }

  private:
    const prevail::ebpf_platform_t* platform_;
};

} // namespace prevail_mcp
