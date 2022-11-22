// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <ranges>
#include <thread>
#include <vector>

#include "api_internal.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "device_helper.hpp"
#include "helpers.h"
#include "ebpf_core.h"
#include "mock.h"
#include "platform.h"
#include "test_helper.hpp"

#define ONE_MB_IN_BYTE (1024 * 1024)

std::vector<ebpf_handle_t>
get_handles()
{
    std::vector<ebpf_handle_t> handles;
    const char* error_message = nullptr;
    bpf_object* object = nullptr;
    bpf_link* link;
    fd_t program_fd;
    std::vector<std::string> map_names{
        "ARRAY",
        "HASH",
        "LRU_HASH",
        "LRU_PERCPU_HASH",
        "PERCPU_ARRAY",
        "PERCPU_HASH",
        "QUEUE",
        "STACK",
    };

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    object = bpf_object__open("map.o");
    REQUIRE(object != nullptr);
    bpf_program* program = bpf_object__next_program(object, nullptr);
    int error = bpf_object__load(object);
    size_t error_message_size;
    error_message = bpf_program__log_buf(program, &error_message_size);
    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
    }
    REQUIRE(error == 0);
    program_fd = bpf_program__fd(program);
    for (const auto& name : map_names) {
        fd_t map_fd = bpf_object__find_map_fd_by_name(object, (name + "_map").c_str());
        handles.push_back(Platform::_get_osfhandle(map_fd));
    }
    uint32_t if_index = 1;

    // Attach only to the single interface being tested.
    REQUIRE(hook.attach_link(program_fd, &if_index, sizeof(if_index), &link) == EBPF_SUCCESS);
    fd_t link_fd = bpf_link__fd(link);

    handles.push_back(Platform::_get_osfhandle(program_fd));
    handles.push_back(Platform::_get_osfhandle(link_fd));
    return handles;
}

extern "C" bool ebpf_fuzzing_enabled;

std::vector<std::mt19937::result_type>
create_random_seed()
{
    std::random_device source;
    std::vector<std::mt19937::result_type> random_data(std::mt19937::state_size);
    for (auto& value : random_data) {
        value = source();
    }
    return random_data;
}

std::vector<std::mt19937::result_type>
load_random_seed(const std::filesystem::path& file)
{
    std::ifstream input(file);
    std::vector<std::mt19937::result_type> random_data(std::mt19937::state_size);
    for (auto& value : random_data) {
        input >> std::hex >> value;
        random_data.emplace_back(value);
    }
    return random_data;
}

std::mt19937
seed_random_engine()
{
    std::vector<std::mt19937::result_type> random_data;
    char* buffer;
    size_t buffer_size;
    REQUIRE(_dupenv_s(&buffer, &buffer_size, "RANDOM_SEED") == 0);
    if (buffer) {
        random_data = load_random_seed(buffer);
    } else {
        random_data = create_random_seed();
    }

    std::cout << "[Begin random seed]" << std::endl;
    size_t i = 0;
    for (auto& value : random_data) {
        std::cout << std::hex << std::setw(8) << std::setfill('0') << value << ' ';
        if (++i % 8 == 0) {
            std::cout << std::endl;
        }
    }
    std::cout << "[End random seed]" << std::endl;

    std::seed_seq seeds(std::begin(random_data), std::end(random_data));
    return std::mt19937(seeds);
}

TEST_CASE("execution_context_direct", "[fuzz]")
{
    _test_helper_end_to_end test_helper;
    const size_t iterations = 10000000;
    auto handles = get_handles();
    ebpf_fuzzing_enabled = true;
    auto mt = seed_random_engine();

    // Limit this processes memory to 50MB
    HANDLE job = CreateJobObject(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.ProcessMemoryLimit = 50 * ONE_MB_IN_BYTE;
    REQUIRE(job != INVALID_HANDLE_VALUE);

    REQUIRE(SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)));
    REQUIRE(AssignProcessToJobObject(job, GetCurrentProcess()));

    ebpf_protocol_buffer_t request;
    ebpf_protocol_buffer_t reply;

    request.reserve(UINT16_MAX);
    reply.reserve(UINT16_MAX);
    for (size_t i = 0; i < iterations; i++) {
        ebpf_operation_id_t operation_id =
            static_cast<ebpf_operation_id_t>(mt() % (EBPF_OPERATION_LOAD_NATIVE_PROGRAMS + 1));
        size_t minimum_request_size;
        size_t minimum_reply_size;
        bool async;
        if (i % (iterations / 100) == 0) {
            std::cout << std::dec << (i * 100) / iterations << "% completed" << std::endl;
        }

        if (ebpf_core_get_protocol_handler_properties(
                operation_id, &minimum_request_size, &minimum_reply_size, &async) != EBPF_SUCCESS) {
            continue;
        }

        // TODO - Add support for fuzzing async requests.
        // https://github.com/microsoft/ebpf-for-windows/issues/897
        if (async) {
            continue;
        }

        // The strategy for fuzzing this API surface is:
        // 1. Create an input buffer of size minimum_request_size + [0,1023].
        // 2. Fill buffer with random values.
        // 3. Insert a handle value at offset 0 in the request.
        request.resize(minimum_request_size + mt() % 1024);
        for (auto& b : request) {
            b = static_cast<uint8_t>(mt());
        }
        auto header = reinterpret_cast<ebpf_operation_header_t*>(request.data());
        header->id = operation_id;
        header->length = static_cast<uint16_t>(request.size());
        *reinterpret_cast<ebpf_handle_t*>(request.data() + sizeof(ebpf_operation_header_t)) =
            handles[mt() % handles.size()];
        if (minimum_reply_size != 0) {
            reply.resize(minimum_reply_size + mt() % 1024);
            invoke_ioctl(request, reply);
        } else {
            invoke_ioctl(request);
        }
    }
}