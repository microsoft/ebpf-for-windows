// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN
#include <optional>
#include <map>
#include <string>

#include "catch_wrapper.hpp"
extern "C"
{
#include "bpf.h"
#include "libbpf.h"
}

#include "sample_extension_helper.h"

typedef class _ebpf_driver_test_state
{
  public:
    _ebpf_driver_test_state(
        std::string elf_file,
        ebpf_execution_type_t execution_type,
        std::optional<std::map<std::string, std::map<std::vector<uint8_t>, std::vector<uint8_t>>>> map_data)
        : program(nullptr), program_fd(ebpf_fd_invalid)
    {
        const char* log_buffer = nullptr;
        ebpf_result_t result = ebpf_program_load(
            elf_file.c_str(),
            &EBPF_PROGRAM_TYPE_SAMPLE,
            &EBPF_ATTACH_TYPE_SAMPLE,
            execution_type,
            &program,
            &program_fd,
            &log_buffer);
        REQUIRE(log_buffer == nullptr);
        REQUIRE(result == EBPF_SUCCESS);

        if (map_data.has_value()) {
            for (auto& [name, values] : map_data.value()) {
                auto map = bpf_object__find_map_by_name(program, "test_map");
                REQUIRE(map != nullptr);
                auto map_fd = bpf_map__fd(map);
                REQUIRE(map_fd != ebpf_fd_invalid);
                auto key_size = bpf_map__key_size(map);
                auto value_size = bpf_map__value_size(map);
                for (auto& [key, value] : values) {
                    REQUIRE(key_size == key.size());
                    REQUIRE(value_size == value.size());
                    bpf_map_update_elem(map_fd, key.data(), value.data(), EBPF_ANY);
                }
            }
        }
    }

    uint64_t
    profile_bpf_program(std::vector<char> data, uint64_t iterations, uint64_t flags)
    {
        return sample_ext_driver.invoke_profile(data, iterations, flags);
    }
    ~_ebpf_driver_test_state() {}

  private:
    sample_extension_helper_t sample_ext_driver;
    bpf_object* program;
    fd_t program_fd;
} ebpf_program_test_state_t;

TEST_CASE("droppacket", "[kernel]")
{
    ebpf_program_test_state_t _test("droppacket.o", EBPF_EXECUTION_JIT, {});
    _test.profile_bpf_program({}, 1, SAMPLE_EBPF_EXT_FLAG_DISPATCH);
}