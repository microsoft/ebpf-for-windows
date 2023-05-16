// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_mt_stress.h"
#include "program_helper.h"
#include "test_helper.hpp"

// Data returned by a successful _program_load() call.
struct program_object_info
{
    fd_t fd{0};
    bpf_object_ptr object{nullptr};
};

enum class log_string_flag : bool
{
    LOG_STRING_NEEDED = true,
    LOG_STRING_NOT_NEEDED = false
};

static std::pair<std::variant<int, program_object_info>, std::optional<std::string>>
_program_load(
    const std::string& file_name,
    bpf_prog_type prog_type,
    ebpf_execution_type_t execution_type,
    log_string_flag error_log_flag = log_string_flag::LOG_STRING_NOT_NEEDED)
{
    REQUIRE(file_name.size() != 0);

    program_object_info local_object_info{};
    local_object_info.object.reset(bpf_object__open(file_name.c_str()));
    if (local_object_info.object == nullptr) {
        return {-errno, std::nullopt};
    }

    REQUIRE(ebpf_object_set_execution_type(local_object_info.object.get(), execution_type) == EBPF_SUCCESS);
    struct bpf_program* program{nullptr};
    program = bpf_object__next_program(local_object_info.object.get(), nullptr);
    REQUIRE(program != nullptr);
    if (prog_type != BPF_PROG_TYPE_UNSPEC) {
        bpf_program__set_type(program, prog_type);
    }
    int error = bpf_object__load(local_object_info.object.get());
    if (error < 0) {
        if (error_log_flag != log_string_flag::LOG_STRING_NEEDED) {
            return {-errno, std::nullopt};
        }

        size_t log_buffer_size{0};
        const char* log_buffer_str = bpf_program__log_buf(program, &log_buffer_size);
        std::string local_log_buffer{};
        if (log_buffer_str != nullptr) {
            local_log_buffer = log_buffer_str;
        }

        return {error, local_log_buffer};
    }

    local_object_info.fd = bpf_program__fd(program);
    return {std::move(local_object_info), std::nullopt};
}

static void
_bindmonitor_tailcall_stress_thread_function(const stress_test_thread_context& test_params)
{
    uint32_t count{0};
    using sc = std::chrono::steady_clock;
    auto endtime = sc::now() + std::chrono::minutes(test_params.duration_minutes);
    while (sc::now() < endtime) {

        LOG_VERBOSE(
            "{}({}): Instantiating _program_load. Iteration #: {}", __func__, test_params.thread_index, count++);

        auto [result, _] = _program_load(test_params.file_name, test_params.program_type, test_params.execution_type);
        if (std::holds_alternative<int>(result)) {
            auto error = std::get<int>(result);
            REQUIRE(error == 0);
        }

        const auto& local_program_object_info = std::get<program_object_info>(result);

        // Set up tail calls.
        struct bpf_program* callee0 =
            bpf_object__find_program_by_name(local_program_object_info.object.get(), "BindMonitor_Callee0");
        REQUIRE(callee0 != nullptr);
        fd_t callee0_fd = bpf_program__fd(callee0);
        REQUIRE(callee0_fd > 0);

        struct bpf_program* callee1 =
            bpf_object__find_program_by_name(local_program_object_info.object.get(), "BindMonitor_Callee1");
        REQUIRE(callee1 != nullptr);
        fd_t callee1_fd = bpf_program__fd(callee1);
        REQUIRE(callee1_fd > 0);

        fd_t prog_map_fd = bpf_object__find_map_fd_by_name(local_program_object_info.object.get(), "prog_array_map");
        REQUIRE(prog_map_fd > 0);

        // Set up tail calls.
        uint32_t index = 0;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee0_fd, 0) == 0);
        index = 1;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

        // Attach and detach link.
        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
        uint32_t ifindex = test_params.thread_index;
        bpf_link* link = nullptr;
        REQUIRE(hook.attach_link(local_program_object_info.fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

        hook.detach_link(link);
        hook.close_link(link);

        // Tear down tail calls.
        index = 0;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
        index = 1;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    }

    LOG_INFO("{} done. Iterations: {}", test_params.file_name.c_str(), count);
}

static void
_droppacket_stress_thread_function(const stress_test_thread_context& test_params)
{
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    UNREFERENCED_PARAMETER(test_params);
    uint32_t count{0};
    using sc = std::chrono::steady_clock;
    auto endtime = sc::now() + std::chrono::minutes(test_params.duration_minutes);
    while (sc::now() < endtime) {

        LOG_VERBOSE(
            "{}({}): Instantiating _program_load. Iteration #: {}", __func__, test_params.thread_index, count++);

        auto [result, _] = _program_load(test_params.file_name, test_params.program_type, test_params.execution_type);
        if (std::holds_alternative<int>(result)) {
            auto error = std::get<int>(result);
            REQUIRE(error == 0);
        }

        const auto& local_program_object_info = std::get<program_object_info>(result);

        // Set interface to filter on.
        fd_t interface_index_map_fd =
            bpf_object__find_map_fd_by_name(local_program_object_info.object.get(), "interface_index_map");
        uint32_t key = 0;

        // We need the interface index number to be a non-negative value, unique to each thread.  Although meant for a
        // different purpose, the 'thread_index' member of the test_params struct happens to fit this requirement,
        // so we use it here as well.
        uint32_t if_index = test_params.thread_index;
        REQUIRE(bpf_map_update_elem(interface_index_map_fd, &key, &if_index, EBPF_ANY) == EBPF_SUCCESS);

        // Attach only to the single interface being tested.
        bpf_link* link = nullptr;
        REQUIRE(hook.attach_link(local_program_object_info.fd, &if_index, sizeof(if_index), &link) == EBPF_SUCCESS);

        // Do a basic map i/o test.
        fd_t dropped_packet_map_fd =
            bpf_object__find_map_fd_by_name(local_program_object_info.object.get(), "dropped_packet_map");
        REQUIRE(dropped_packet_map_fd > 0);

        key = 0;
        uint64_t value = 1000;
        REQUIRE(bpf_map_update_elem(dropped_packet_map_fd, &key, &value, EBPF_ANY) == EBPF_SUCCESS);

        REQUIRE(bpf_map_lookup_elem(dropped_packet_map_fd, &key, &value) == EBPF_SUCCESS);
        REQUIRE(value == 1000);

        // Do some more basic validations.
        REQUIRE(bpf_map_delete_elem(dropped_packet_map_fd, &key) == EBPF_SUCCESS);

        REQUIRE(bpf_map_lookup_elem(dropped_packet_map_fd, &key, &value) == EBPF_SUCCESS);
        REQUIRE(value == 0);

        // Detach link.
        hook.detach_link(link);
        hook.close_link(link);
    }

    LOG_INFO("{} done. Iterations: {}", test_params.file_name.c_str(), count);
}

// Note: The 'native_file_name' and 'extension_name' members of the _test_program_info struct is not used by the
// user-mode tests.
static const std::map<std::string, test_program_attributes> _test_program_info = {
    {{"droppacket"},
     {{"droppacket.o"}, {}, {}, _droppacket_stress_thread_function, BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_JIT}},
    {{"bindmonitor_tailcall"},
     {{"bindmonitor_tailcall.o"},
      {},
      {},
      _bindmonitor_tailcall_stress_thread_function,
      BPF_PROG_TYPE_UNSPEC,
      EBPF_EXECUTION_JIT}}};

// This call is called by the common test initialization code to get a list of programs supported by the user mode or
// kernel mode test suites.  (For example, some programs could be meant for kernel mode stress testing only).
const std::vector<std::string>
query_supported_program_names()
{
    std::vector<std::string> program_names{};

    for (const auto& program_info : _test_program_info) {
        program_names.push_back(program_info.first);
    }

    return program_names;
}

// These objects should be created just _once_ per (test) process. This is only needed for user mode tests that use the
// user mode 'mock' framework.  Note that these cannot be created globally and _must_ be created in the context of a
// a Catch2 test 'session' (Per Catch2 documentation, Catch2's exception framework is apparently not quite ready until
// then).  This is an issue in our usage as we make extensive use of Catch2's REQUIRE verification/validation macros
// (based on this framework) during the creation of these objects;
static _test_helper_end_to_end* _test_helper{nullptr};
static program_info_provider_t* _bind_program_info_provider{nullptr};
static program_info_provider_t* _xdp_program_info_provider{nullptr};
static test_control_info _test_control_info{0};

static std::once_flag _um_test_init_done;
static void
um_test_init()
{
    std::call_once(_um_test_init_done, [&]() {
        _test_helper = new _test_helper_end_to_end;
        REQUIRE(_test_helper != nullptr);

        _bind_program_info_provider = new program_info_provider_t(EBPF_PROGRAM_TYPE_BIND);
        REQUIRE(_bind_program_info_provider != nullptr);

        _xdp_program_info_provider = new program_info_provider_t(EBPF_PROGRAM_TYPE_XDP);
        REQUIRE(_xdp_program_info_provider != nullptr);

        _test_control_info = get_test_control_info();
        if (_test_control_info.programs.size()) {

            // Paranoia check - ensure that the program(s) we got back is/are indeed from our supported list.
            for (const auto& program : _test_control_info.programs) {
                if (std::find(_test_control_info.programs.begin(), _test_control_info.programs.end(), program) ==
                    _test_control_info.programs.end()) {
                    LOG_INFO("ERROR: Uexpected program: {}", program);
                    REQUIRE(0);
                }
            }
        } else {

            // No programs specified on the command line, so use the preferred default.
            _test_control_info.programs.push_back({"droppacket"});
        }

        LOG_INFO("test programs:");
        for (const auto& program : _test_control_info.programs) {
            LOG_INFO("\t{}", program);
        }
        LOG_INFO("test threads per program  : {}", _test_control_info.threads_count);
        LOG_INFO("test duration (in minutes): {}", _test_control_info.duration_minutes);
        LOG_INFO("test verbose output       : {}", _test_control_info.verbose_output);
    });
}

TEST_CASE("load_attach_detach_unload_sequential_test", "[mt_stress_test]")
{
    um_test_init();

    LOG_VERBOSE("Starting test: {}", Catch::getResultCapture().getCurrentTestName());

    // Maintain an incrementing interface index counter to ensure that _each_ running thread gets a unique interface id.
    // It is critical that a given interface index is associated with one and only one 'link' object in the entire set
    // of running threads.
    // The start value of 1 is for debugging purposes only. The user mode 'mock' framework does not validate this value
    // in any fashion.
    uint32_t if_index{1};

    // This lambda creates the context for each thread, updates per-thread data therein and spawns the thread.  It also
    // returns thread handle and thread context vectors for the created threads.
    auto spawn_test_threads = [&](test_thread_function_t test_thread_function,
                                  stress_test_thread_context& test_thread_context,
                                  uint32_t test_thread_count) {
        LOG_INFO("spawning stress test threads for {}...", test_thread_context.file_name.c_str());
        std::vector<std::thread> tv(test_thread_count);
        std::vector<stress_test_thread_context> ttc(test_thread_count);

        for (uint32_t i = 0; i < test_thread_count; i++) {
            LOG_VERBOSE("\t{}({}): Interface Index: {}", test_thread_context.file_name.c_str(), i, if_index);
            ttc[i] = test_thread_context;
            ttc[i].thread_index = if_index++;
            tv[i] = std::thread(test_thread_function, ttc[i]);
        }
        return std::pair<std::vector<std::thread>, std::vector<stress_test_thread_context>>(std::move(tv), ttc);
    };

    std::vector<stress_test_thread_context> test_thread_contexts{};
    std::vector<std::thread> test_threads{};

    for (const auto& program : _test_control_info.programs) {

        // Prepare the common part of the test context for all threads of this program...
        const auto& program_attributes = _test_program_info.at(program);
        stress_test_thread_context local_context{};
        local_context.file_name = program_attributes.jit_file_name;
        local_context.program_type = program_attributes.program_type;
        local_context.execution_type = program_attributes.execution_type;
        local_context.duration_minutes = _test_control_info.duration_minutes;

        // ...And spawn the required test threads.
        auto [tv, ttc] = spawn_test_threads(
            program_attributes.test_thread_function, local_context, _test_control_info.threads_count);

        // Append the returned thread handle and thread context vectors to their respective 'master' lists.  The
        // thread handles are needed so that we can wait for all running threads to terminate and the thread context
        // master list ensures that each thread context stays 'alive' for the lifetime of its associated thread.
        test_threads.insert(test_threads.end(), std::make_move_iterator(tv.begin()), std::make_move_iterator(tv.end()));
        test_thread_contexts.insert(
            test_thread_contexts.end(), std::make_move_iterator(ttc.begin()), std::make_move_iterator(ttc.end()));
    }

    LOG_INFO("waiting on {} threads...", test_threads.size());
    for (auto& t : test_threads) {
        t.join();
    }
}
