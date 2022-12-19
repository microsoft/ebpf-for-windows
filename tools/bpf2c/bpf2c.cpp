// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include <Windows.h>
#include <bcrypt.h>
#include <codecvt>
#include <functional>
#include <fstream>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

#undef max
#include "bpf_code_generator.h"
#include "ebpf_api.h"
#include "ebpf_program_types.h"
#include "ElfWrapper.h"

#define elf_everparse_error ElfEverParseError
#define elf_everparse_verify ElfCheckElf

#pragma comment(lib, "Bcrypt.lib")

const char copyright_notice[] = "// Copyright (c) Microsoft Corporation\n// SPDX-License-Identifier: MIT\n";

const char bpf2c_driver[] =
#include "bpf2c_driver.template"
    ;

const char bpf2c_dll[] =
#include "bpf2c_dll.template"
    ;

typedef class _hash
{
  public:
    typedef std::vector<std::tuple<const uint8_t*, size_t>> byte_range_t;
    template <typename T>
    static void
    append_byte_range(byte_range_t& byte_range, const T& value)
    {
        if constexpr (std::is_same<T, const char*>::value) {
            byte_range.push_back({reinterpret_cast<const uint8_t*>(value), strlen(value)});
        } else if constexpr (std::is_same<T, const std::string>::value || std::is_same<T, std::string>::value) {
            byte_range.push_back({reinterpret_cast<const uint8_t*>(value.data()), value.size()});
        } else if constexpr (std::is_pointer<T>::value) {
            throw std::runtime_error("Can't hash pointer");
        } else {
            byte_range.push_back({reinterpret_cast<const uint8_t*>(&value), sizeof(value)});
        }
    }
    _hash(const std::string& algorithm)
    {
        HRESULT hr;
        std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
        std::wstring wide_algorithm = converter.from_bytes(algorithm);

        hr = BCryptOpenAlgorithmProvider(&algorithm_handle, wide_algorithm.c_str(), nullptr, BCRYPT_HASH_REUSABLE_FLAG);
        if (!SUCCEEDED(hr)) {
            throw std::runtime_error(
                std::string("BCryptOpenAlgorithmProvider failed with algorithm: ") + algorithm +
                " HR=" + std::to_string(hr));
        }
    }
    ~_hash() { BCryptCloseAlgorithmProvider(algorithm_handle, 0); }

    std::vector<uint8_t>
    hash_string(const std::string& data)
    {
        byte_range_t byte_range;
        append_byte_range(byte_range, data);
        return hash_byte_ranges(byte_range);
    }

    std::vector<uint8_t>
    hash_byte_ranges(const byte_range_t& byte_ranges)
    {
        uint32_t hash_length;
        std::vector<uint8_t> hash;
        BCRYPT_HASH_HANDLE hash_handle;
        HRESULT hr;
        hr = BCryptCreateHash(algorithm_handle, &hash_handle, nullptr, 0, nullptr, 0, 0);
        if (!SUCCEEDED(hr)) {
            throw std::runtime_error(std::string("BCryptCreateHash failed with HR=") + std::to_string(hr));
        }

        for (const auto& [data, length] : byte_ranges) {
            hr = BCryptHashData(hash_handle, const_cast<uint8_t*>(data), static_cast<unsigned long>(length), 0);
            if (!SUCCEEDED(hr)) {
                BCryptDestroyHash(hash_handle);
                throw std::runtime_error(std::string("BCryptHashData failed with HR=") + std::to_string(hr));
            }
        }

        unsigned long bytes_written;
        hr = BCryptGetProperty(
            algorithm_handle,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<uint8_t*>(&hash_length),
            sizeof(hash_length),
            &bytes_written,
            0);
        if (!SUCCEEDED(hr)) {
            BCryptDestroyHash(hash_handle);
            throw std::runtime_error(
                std::string("BCryptGetProperty failed with BCRYPT_HASH_LENGTH  HR=") + std::to_string(hr));
        }
        hash.resize(hash_length);
        hr = BCryptFinishHash(hash_handle, hash.data(), static_cast<unsigned long>(hash.size()), 0);
        BCryptDestroyHash(hash_handle);
        if (!SUCCEEDED(hr)) {
            throw std::runtime_error(std::string("BCryptFinishHash failed with HR=") + std::to_string(hr));
        }
        return hash;
    }

  private:
    BCRYPT_ALG_HANDLE algorithm_handle;
} hash_t;

void
emit_skeleton(const std::string& c_name, const std::string& code)
{
    auto output = std::regex_replace(code, std::regex(std::string("___METADATA_TABLE___")), c_name);
    output = output.substr(strlen(copyright_notice) + 1);
    std::cout << output << std::endl;
}

std::string
load_file_to_memory(const std::string& path)
{
    struct stat st;
    if (stat(path.c_str(), &st)) {
        throw std::runtime_error(std::string("Failed to read file: ") + path);
    }
    if (std::ifstream stream{path, std::ios::in | std::ios::binary}) {
        std::string data;
        data.resize(st.st_size);
        if (!stream.read(data.data(), data.size())) {
            throw std::runtime_error(std::string("Failed to read file: ") + path);
        }
        return data;
    }
    throw std::runtime_error(std::string("Failed to read file: ") + path);
}

extern "C" void
elf_everparse_error(_In_ const char* struct_name, _In_ const char* field_name, _In_ const char* reason);

void
elf_everparse_error(_In_ const char* struct_name, _In_ const char* field_name, _In_ const char* reason)
{
    std::cerr << "Failed parsing in struct " << struct_name << " field " << field_name << " reason " << reason
              << std::endl;
}

std::vector<uint8_t>
get_program_info_type_hash(const std::string& algorithm)
{
    std::map<uint32_t, size_t> helper_id_ordering;
    const ebpf_program_info_t* program_info;
    ebpf_result_t result = ebpf_get_program_info_from_verifier(&program_info);
    if (result != EBPF_SUCCESS) {
        throw std::runtime_error(std::string("Failed to get program information"));
    }

    // Note:
    // Order and fields being hashed is important. The order and fields being hashed must match the order and fields
    // being hashed in _ebpf_program_verify_program_info_hash. If new fields are added to the program info, then the
    // hash must be updated to include the new fields, both here and in _ebpf_program_verify_program_info_hash.
    hash_t::byte_range_t byte_range;
    hash_t::append_byte_range(byte_range, program_info->program_type_descriptor.name);
    hash_t::append_byte_range(byte_range, *program_info->program_type_descriptor.context_descriptor);
    hash_t::append_byte_range(byte_range, program_info->program_type_descriptor.program_type);
    hash_t::append_byte_range(byte_range, program_info->program_type_descriptor.bpf_prog_type);
    hash_t::append_byte_range(byte_range, program_info->program_type_descriptor.is_privileged);
    hash_t::append_byte_range(byte_range, program_info->count_of_helpers);
    for (size_t index = 0; index < program_info->count_of_helpers; index++) {
        helper_id_ordering[program_info->helper_prototype[index].helper_id] = index;
    }
    // Hash helper ids in increasing helper_id order
    for (auto [helper_id, index] : helper_id_ordering) {
        hash_t::append_byte_range(byte_range, program_info->helper_prototype[index].helper_id);
        hash_t::append_byte_range(byte_range, program_info->helper_prototype[index].name);
        hash_t::append_byte_range(byte_range, program_info->helper_prototype[index].return_type);
        for (size_t argument = 0; argument < _countof(program_info->helper_prototype[index].arguments); argument++) {
            hash_t::append_byte_range(byte_range, program_info->helper_prototype[index].arguments[argument]);
        }
    }
    hash_t hash(algorithm);
    return hash.hash_byte_ranges(byte_range);
}

int
main(int argc, char** argv)
{
    try {
        enum class output_type
        {
            Bare,
            KernelPE,
            UserPE,
        } type = output_type::Bare;
        std::string verifier_output_file;
        std::string file;
        std::string type_string = "";
        std::string hash_algorithm = "SHA256";
        bool verify_programs = true;
        std::vector<std::string> parameters(argv + 1, argv + argc);
        auto iter = parameters.begin();
        auto iter_end = parameters.end();
        std::map<std::string, std::tuple<std::string, std::function<bool()>>> options = {
            {"--sys",
             {"Generate code for a Windows driver",
              [&]() {
                  type = output_type::KernelPE;
                  return true;
              }}},
            {"--dll",
             {"Generate code for a Windows DLL",
              [&]() {
                  type = output_type::UserPE;
                  return true;
              }}},
#if defined(ENABLE_SKIP_VERIFY)
            {"--no-verify",
             {"Skip validating code using verifier",
              [&]() {
                  verify_programs = false;
                  return true;
              }}},
#endif
            {"--bpf",
             {"Input ELF file containing BPF byte code",
              [&]() {
                  ++iter;
                  if (iter == iter_end) {
                      std::cerr << "Invalid --bpf option" << std::endl;
                      return false;
                  } else {
                      file = *iter;
                      return true;
                  }
              }}},
            {"--type",
             {"Type string for the eBPF programs",
              [&]() {
                  ++iter;
                  if (iter == iter_end) {
                      std::cerr << "Invalid --type option" << std::endl;
                      return false;
                  } else {
                      type_string = *iter;
                      return true;
                  }
              }}},
            {"--hash",
             {"Algorithm used to hash ELF file",
              [&]() {
                  ++iter;
                  if (iter == iter_end) {
                      std::cerr << "Invalid --hash option" << std::endl;
                      return false;
                  } else {
                      hash_algorithm = *iter;
                      return true;
                  }
              }}},
            {"--help",
             {"This help menu",
              [&]() {
                  std::cerr << argv[0]
                            << " is a tool to generate C code"
                               "from an ELF file containing BPF byte code."
                            << std::endl;
                  std::cerr << "Options are:" << std::endl;
                  for (auto [option, tuple] : options) {
                      auto [help, _] = tuple;
                      std::cerr << option.c_str() << "\t" << help.c_str() << std::endl;
                  }
                  return false;
              }}},
        };

        for (; iter != iter_end; ++iter) {
            auto option = options.find(*iter);
            if (option == options.end()) {
                option = options.find("--help");
            }
            auto [_, function] = option->second;
            if (!function()) {
                return 1;
            }
        }

        std::string c_name = file.substr(file.find_last_of("\\") + 1);
        c_name = c_name.substr(0, c_name.find("."));
        auto data = load_file_to_memory(file);
        std::optional<std::vector<uint8_t>> hash_value;
        if (hash_algorithm != "none") {

            _hash hash(hash_algorithm);
            hash_value = hash.hash_string(data);
        }
        auto stream = std::stringstream(data);

        if (!ElfCheckElf(data.size(), reinterpret_cast<uint8_t*>(data.data()), static_cast<uint32_t>(data.size()))) {
            std::cerr << "ELF file is invalid" << std::endl;
            return 1;
        }

        bpf_code_generator generator(stream, c_name, {hash_value});

        // Capture list of sections.
        std::vector<bpf_code_generator::unsafe_string> sections = generator.program_sections();

        if (verify_programs && sections.size() == 0) {
            std::cerr << "ELF " << file << " file contains no program sections" << std::endl;
            return 1;
        }

        // Parse global data.
        generator.parse();

        // Get global program and attach types, if any.
        ebpf_program_type_t program_type;
        ebpf_attach_type_t attach_type;
        bool global_program_type_set = false;
        if (type_string != "") {
            if (ebpf_get_program_type_by_name(type_string.c_str(), &program_type, &attach_type) != EBPF_SUCCESS) {
                std::cerr << "Program type not found for type string " << type_string << std::endl;
                return 1;
            }
            global_program_type_set = true;
        }

        // Parse per-section data.
        for (const auto& section : sections) {
            if (!global_program_type_set) {
                if (ebpf_get_program_type_by_name(section.raw().c_str(), &program_type, &attach_type) != EBPF_SUCCESS) {
                    std::cerr << "Program type not found for section name " << section.raw() << std::endl;
                    return 1;
                }
            }

            const char* report = nullptr;
            const char* error_message = nullptr;
            ebpf_api_verifier_stats_t stats;
            std::optional<std::vector<uint8_t>> program_info_hash;
            if (verify_programs && ebpf_api_elf_verify_section_from_memory(
                                       data.c_str(),
                                       data.size(),
                                       section.raw().c_str(),
                                       &program_type,
                                       false,
                                       &report,
                                       &error_message,
                                       &stats) != 0) {
                report = ((report == nullptr) ? "" : report);
                throw std::runtime_error(
                    std::string("Verification failed for ") + section.raw() + std::string(" with error ") +
                    std::string(error_message) + std::string("\n Report:\n") + std::string(report));
            }
            if (verify_programs && (hash_algorithm != "none")) {
                program_info_hash = get_program_info_type_hash(hash_algorithm);
            }
            generator.parse(section, program_type, attach_type, program_info_hash);
        }

        for (const auto& section : sections) {
            generator.generate(section);
        }

        std::cout << copyright_notice << std::endl;
        std::cout << "// Do not alter this generated file." << std::endl;
        std::cout << "// This file was generated from " << file << std::endl << std::endl;
        switch (type) {
        case output_type::Bare:
            break;
        case output_type::KernelPE:
            emit_skeleton(c_name, bpf2c_driver);
            break;
        case output_type::UserPE:
            emit_skeleton(c_name, bpf2c_dll);
            break;
        }
        generator.emit_c_code(std::cout);
    } catch (std::runtime_error err) {
        std::cerr << err.what() << std::endl;
        return 1;
    }
    return 0;
}
