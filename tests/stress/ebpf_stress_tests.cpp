// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_RUNNER

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "program_helper.h"
#include "test_helper.hpp"

#include <chrono>
#include <format>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>

// Note that the default values for the # of test threads and the runtime of each thread are deliberately set on the
// extreme side to model a real-world stress scenario, both in terms of sustained overload of the available CPU cores
// and the duration thereof.
constexpr uint32_t DEFAULT_JIT_THREADS{64}; // Should easily swamp all available CPU cores in most typical servers.
constexpr uint32_t DEFAULT_JIT_TEST_DURATION{600}; // 10 minutes

// Command line option: '-jtp' or '--jit-test-programs'.
// Usage: -jtp="droppacket, bindmonitor_tailcall" OR --jit-test-programs="droppacket, bindmonitor_tailcall".
// This option specifies a comma separated list of JIT compiled programs to load.
// Note that these programs must be from the list of supported programs. The currently supported programs are listed in
// the _jit_program_info std::map variable declaration further down.
std::string _jit_test_program_list_arg{};

// Command line option: '-jtt' OR '--jit-test-threads'.
// Usage: -jtt=16 OR --jit-test-threads=16.
// This option specifies the number of threads allocated per jit program.
uint32_t _jit_test_threads_count_arg{DEFAULT_JIT_THREADS};

// Command line option: '-jtd' OR '--jit-test-duration'
// Usage: -jtd=300 OR --jit-test-duration=300
// This option specifies the run time for each jit program test in seconds.
uint32_t _jit_test_duration_arg{DEFAULT_JIT_TEST_DURATION};

// Command line option: '-jtv' OR '--jit-test-verbose-output'.
// Usage: -jtv=<1|true> OR --jit-test-verbose-output=<1|true>
// This option enables verbose progress output.
bool _jit_test_verbose_output_arg{false};

// Parsed vector of programs specified on the command line.  We load 'droppacket.o' by default if no programs were
// specified on the command-line.
static std::vector<std::string> _jit_programs{"droppacket"};

// Logging support
enum class log_level : uint32_t
{
    LOG_ERROR = 1,
    LOG_WARN,
    LOG_INFO,
    LOG_VERBOSE,
    LOG_DEBUG
};

static log_level _cur_log_level = log_level::LOG_INFO;

template <typename... Args>
static void
_log(log_level msg_level, const std::string_view& fmt, Args&&... args)
{
    if (msg_level <= _cur_log_level) {
        std::cout << std::vformat(fmt, std::make_format_args(args...)) << "\n";
    }
}

#define LOG_ERROR(fmt, ...) _log(log_level::LOG_ERROR, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) _log(log_level::LOG_WARN, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) _log(log_level::LOG_INFO, fmt, ##__VA_ARGS__)
#define LOG_VERBOSE(fmt, ...) _log(log_level::LOG_VERBOSE, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) _log(log_level::LOG_DEBUG, fmt, ##__VA_ARGS__)

// Data returned by a successful _program_load() call.
struct free_bpf_object_ptr
{
    void
    operator()(_In_opt_ _Post_invalid_ bpf_object* raw_ptr)
    {
        if (raw_ptr != nullptr) {
            bpf_object__close(raw_ptr);
        }
    }
};

using bpf_object_ptr = std::unique_ptr<bpf_object, free_bpf_object_ptr>;
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

// Thread context. One instance per test thread
struct stress_test_thread_context
{
    uint32_t thread_index{0};
    std::string file_name;
    bpf_prog_type prog_type;
    ebpf_execution_type_t execution_type;
    uint32_t runtime{0};
    ebpf_result_t result;
};

static void
_bindmonitor_tailcall_stress_thread_function(const stress_test_thread_context& test_params)
{
    uint32_t count{0};
    using sc = std::chrono::steady_clock;
    auto endtime = sc::now() + std::chrono::seconds(test_params.runtime);
    while (sc::now() < endtime) {

        LOG_VERBOSE(
            "{}({}): Instantiating _program_load. Iteration #: {}", __func__, test_params.thread_index, count++);

        auto [result, _] = _program_load(test_params.file_name, test_params.prog_type, test_params.execution_type);
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
    uint32_t count{0};
    using sc = std::chrono::steady_clock;
    auto endtime = sc::now() + std::chrono::seconds(test_params.runtime);
    while (sc::now() < endtime) {
        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);

        LOG_VERBOSE(
            "{}({}): Instantiating _program_load. Iteration #: {}", __func__, test_params.thread_index, count++);

        auto [result, _] = _program_load(test_params.file_name, test_params.prog_type, test_params.execution_type);
        if (std::holds_alternative<int>(result)) {
            auto error = std::get<int>(result);
            REQUIRE(error == 0);
        }

        const auto& local_program_object_info = std::get<program_object_info>(result);

        // Set interface to filter on.
        fd_t interface_index_map_fd =
            bpf_object__find_map_fd_by_name(local_program_object_info.object.get(), "interface_index_map");
        uint32_t key = 0;
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

// These objects should be created just _once_ per (test) process. This is only needed for user mode tests that use the
// user mode 'mock' framework.  Note that these cannot be created globally and _must_ be created in the context of a
// a Catch2 test 'session' (Per Catch2 documentation, Catch2's exception framework is apparently not quite ready until
// then).  This is an issue in our usage as we make extensive use of Catch2's REQUIRE verification/validation macros
// (based on this framework) during the creation of these objects;
static _test_helper_end_to_end* _test_helper{nullptr};
static program_info_provider_t* _bind_program_info{nullptr};
static program_info_provider_t* _xdp_program_info{nullptr};

static std::once_flag _um_test_init_done;
static void
um_test_init()
{
    std::call_once(_um_test_init_done, [&]() {
        _test_helper = new _test_helper_end_to_end;
        REQUIRE(_test_helper != nullptr);

        _bind_program_info = new program_info_provider_t(EBPF_PROGRAM_TYPE_BIND);
        REQUIRE(_bind_program_info != nullptr);

        _xdp_program_info = new program_info_provider_t(EBPF_PROGRAM_TYPE_XDP);
        REQUIRE(_xdp_program_info != nullptr);

        LOG_INFO("One time initialization complete");
    });
}

using test_thread_function_t = void (*)(const stress_test_thread_context& test_params);
struct jit_prog_attributes
{
    std::string file_name;
    test_thread_function_t test_thread_function;
    bpf_prog_type prog_type;
    ebpf_execution_type_t execution_type;
};

static std::map<std::string, jit_prog_attributes> _jit_program_info = {
    {{"bindmonitor_tailcall"},
     {{"bindmonitor_tailcall.o"},
      _bindmonitor_tailcall_stress_thread_function,
      BPF_PROG_TYPE_UNSPEC,
      EBPF_EXECUTION_JIT}},
    {{"droppacket"}, {{"droppacket.o"}, _droppacket_stress_thread_function, BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_JIT}}};

TEST_CASE("load_attach_detach_unload_test", "[stress_test]")
{
    LOG_INFO("jit test programs:");
    for (const auto& prog : _jit_programs) {
        LOG_INFO("\t{}", prog);
    }
    LOG_INFO("jit test threads per program: {}", _jit_test_threads_count_arg);
    LOG_INFO("jit test duration: {}", _jit_test_duration_arg);
    LOG_INFO("jit test verbose output: {}", _jit_test_verbose_output_arg);

    um_test_init();

    // Maintain an incrementing interface index counter to ensure that _each_ running thread gets a unique interface id.
    // It is critical that a given interface index is associated with one and only one 'link' object in the entire set
    // of running threads.
    // The start value of 1 is for debugging purposes only. The user mode 'mock' framework does not validate this value
    // in any fashion.
    uint32_t if_index{1};

    // This lambda creates the context for each thread, updates per-thread data therein and spawns the thread.  It also
    // returns thread handle and thread context vectors for the created threads.
    auto do_test = [&](test_thread_function_t test_thread_function,
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

    for (const auto& prog : _jit_programs) {

        // Prepare the common part of the test context for all threads of this program...
        const auto& prog_attribs = _jit_program_info[prog];
        stress_test_thread_context local_context{};
        local_context.file_name = prog_attribs.file_name;
        local_context.prog_type = prog_attribs.prog_type;
        local_context.execution_type = prog_attribs.execution_type;
        local_context.runtime = _jit_test_duration_arg;

        // ...And spawn the required test threads.
        auto [tv, ttc] = do_test(prog_attribs.test_thread_function, local_context, _jit_test_threads_count_arg);

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

std::variant<std::vector<std::string>, bool>
_validate_jit_command_line_programs()
{
    std::vector<std::string> programs{};
    std::istringstream prog_stream(_jit_test_program_list_arg);
    std::string prog;
    std::set<std::string> progs_seen{};
    while (std::getline(prog_stream, prog, ',')) {

        // Trim leading, trailing whitespace.
        prog.erase(0, prog.find_first_not_of("\t "));
        prog.erase(prog.find_last_not_of("\t ") + 1);

        // Verify this is a 'known' program.
        if (_jit_program_info.find(prog) == _jit_program_info.end()) {
            LOG_ERROR("ERROR: Unknown program: {}", prog);
            return false;
        }

        // Verify this program has not been specified more than once.
        if (progs_seen.find(prog) != progs_seen.end()) {
            LOG_ERROR("ERROR: Program specified multiple times: {}", prog);
            return false;
        }

        progs_seen.insert(prog);

        // Everything's good, so stash this program name.
        programs.push_back(prog);
    }

    return (programs);
}

int
main(int argc, char* argv[])
{
    Catch::Session session;

    // Use Catch's composite command line parser.
    using namespace Catch::Clara;
    auto cli =
        session.cli() |
        Opt(_jit_test_program_list_arg,
            "jit program names")["-jtp"]["--jit-test-programs"]("Comma separated JIT compiled program names") |
        Opt(_jit_test_threads_count_arg, "thread count")["-jtt"]["--jit-test-threads"]("Count of threads per test") |
        Opt(_jit_test_duration_arg,
            "test duration")["-jtd"]["--jit-test-duration"]("Test duration (per-test) in seconds") |
        Opt(_jit_test_verbose_output_arg, "verbosity flag")["-jtv"]["--jit-test-verbose-output"](
            "Verbosity flag (1 to enable, 0 to disable(default))");

    session.cli(cli);

    int status = session.applyCommandLine(argc, argv);
    if (status != 0) {
        return status;
    }

    auto result = _validate_jit_command_line_programs();
    if (std::holds_alternative<bool>(result)) {
        return -1;
    }

    // Either we have a vector with the specified programs or an empty vector (no programs listed on command line).
    auto programs = std::get<std::vector<std::string>>(result);
    if (programs.size()) {
        _jit_programs = programs;
    }

    if (_jit_test_verbose_output_arg) {
        _cur_log_level = log_level::LOG_VERBOSE;
    }

    session.run();
}
