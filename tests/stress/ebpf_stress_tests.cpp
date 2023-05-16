// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_RUNNER

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "ebpf_mt_stress.h"
#include "program_helper.h"
#include "test_helper.hpp"

// Note that the default values for the # of test threads and the runtime of each thread are deliberately set on the
// extreme side to model a real-world stress scenario, both in terms of sustained overload of the available CPU cores
// and the duration thereof.
constexpr uint32_t DEFAULT_TEST_THREADS{32};  // Should easily swamp all available CPU cores in most typical servers.
constexpr uint32_t DEFAULT_TEST_DURATION{10}; // 10 minutes.
constexpr uint32_t DEFAULT_EXTENSION_RESTART_DELAY{1000}; // 1 second.

// Command line option: '-tp' or '--test-programs'.
// Usage: -tp="droppacket, bindmonitor_tailcall" OR --test-programs="droppacket, bindmonitor_tailcall".
// This option specifies a comma separated list programs to load.
// Note that these programs must be from the list of supported programs. The currently supported programs are listed in
// the _jit_program_info std::map variable declaration further down.
std::string _test_program_list_arg{};

// Command line option: '-tt' OR '--test-threads'.
// Usage: -tt=16 OR --test-threads=16.
// This option specifies the number of test threads allocated per program.
uint32_t _test_threads_count_arg{DEFAULT_TEST_THREADS};

// Command line option: '-td' OR '--test-duration'
// Usage: -td=5 OR --test-duration=5
// This option specifies the run time for each jit program test in minutes.
uint32_t _test_duration_arg{DEFAULT_TEST_DURATION};

// Command line option: '-vo' OR '--verbose-output'.
// Usage: -vo=<[1|true][0|false]> OR --verbose-output=<[1|true][0|false]>
// This option enables verbose progress output.
bool _test_verbose_output_arg{false};

// Command line option: '-er' OR '--extension-restart'.
// Usage: -er=<[1|true][0|false]> OR --extension-restart=<[1|true][0|false]>
// This option enables continuous restarting of the extension driver in a thread running in parallel to test threads.
bool _extension_restart_arg{false};

// Command line option: '-erd' OR '--extension-restart-delay'.
// Usage: -erd=<NN> OR --extension-restart-delay=<NN>
// This option specifies the delay (in milliseconds) between stopping and restarting of the extension driver.
uint32_t _extension_restart_delay_arg{DEFAULT_EXTENSION_RESTART_DELAY};

// Parsed vector of programs specified on the command line.  We load 'droppacket.o' by default if no programs were
// specified on the command-line.
static std::vector<std::string> _jit_programs{};

// Logging level trigger - logs at this level and below are printed.
log_level cur_log_level = log_level::LOG_INFO;

test_control_info
get_test_control_info()
{
    test_control_info test_control{0};

    test_control.threads_count = _test_threads_count_arg;
    test_control.duration_minutes = _test_duration_arg;
    test_control.verbose_output = _test_verbose_output_arg;
    test_control.extension_restart_enabled = _extension_restart_arg;
    test_control.extension_restart_delay_ms = _extension_restart_delay_arg;
    test_control.programs = _jit_programs;

    return test_control;
}

std::variant<std::vector<std::string>, bool>
_validate_jit_command_line_programs(const std::vector<std::string>& supported_programs)
{
    std::istringstream prog_stream(_test_program_list_arg);
    std::vector<std::string> test_programs{};
    std::string program;
    std::set<std::string> programs_seen{};
    while (std::getline(prog_stream, program, ',')) {

        // Trim leading, trailing whitespace.
        program.erase(0, program.find_first_not_of("\t "));
        program.erase(program.find_last_not_of("\t ") + 1);

        // Verify this is a 'known' program.
        if (std::find(supported_programs.begin(), supported_programs.end(), program) == supported_programs.end()) {
            LOG_ERROR("ERROR: Unknown program: {}", program);
            return false;
        }

        // Verify this program has not been specified more than once.
        if (programs_seen.find(program) != programs_seen.end()) {
            LOG_ERROR("ERROR: Program specified multiple times: {}", program);
            return false;
        }

        // Everything's good, so stash this program name.
        programs_seen.insert(program);
        test_programs.push_back(program);
    }

    return (test_programs);
}

int
main(int argc, char* argv[])
{
    Catch::Session session;

    // Use Catch's composite command line parser.
    using namespace Catch::Clara;
    auto cli =
        session.cli() |
        Opt(_test_program_list_arg,
            "program names")["-tp"]["--test-programs"]("Comma separated JIT compiled program names") |
        Opt(_test_threads_count_arg, "thread count")["-tt"]["--test-threads"]("Count of threads per test") |
        Opt(_test_duration_arg, "test duration")["-td"]["--test-duration"]("Test duration (per-test) in seconds") |
        Opt(_test_verbose_output_arg,
            "verbosity flag")["-vo"]["--verbose-output"]("Verbosity flag (1 to enable, 0 to disable(default))") |
        Opt(_extension_restart_arg, "restart extension/provider flag")["-er"]["--extension-restart"](
            "Enable 'restart extension' thread flag ([1|true] to enable, [0|false] to disable(default))") |
        Opt(_extension_restart_delay_arg, "restart extension/provider delay")["-erd"]["--extension-restart-delay"](
            "Restart delay (in milliseconds) after stopping an extension");

    session.cli(cli);

    int status = session.applyCommandLine(argc, argv);
    if (status != 0) {
        return status;
    }

    auto supported_programs = query_supported_program_names();
    if (!supported_programs.size()) {
        LOG_ERROR("ERROR: No supported programs found");
        return false;
    }

    auto result = _validate_jit_command_line_programs(supported_programs);
    if (std::holds_alternative<bool>(result)) {
        return -1;
    }

    // Either we have a vector with the specified programs or an empty vector (no programs listed on command line).
    auto test_programs = std::get<std::vector<std::string>>(result);
    if (test_programs.size()) {
        _jit_programs = test_programs;
    }

    if (_test_verbose_output_arg) {
        cur_log_level = log_level::LOG_VERBOSE;
    }

    session.run();
}
