// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_RUNNER

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "ebpf_mt_stress.h"
#include "program_helper.h"
#include "test_helper.hpp"

constexpr uint32_t DEFAULT_TEST_THREADS{0};
constexpr uint32_t DEFAULT_TEST_DURATION{0};
constexpr uint32_t DEFAULT_ATTACH_DETACH_DELAY{10};       // 10 milliseconds.
constexpr uint32_t DEFAULT_EXTENSION_RESTART_DELAY{1000}; // 1 second.

// Command line option: '-tt' OR '--test-threads'.
// Usage: -tt=16 OR --test-threads=16.
// This option specifies the number of test threads allocated per program.
// If not provided (or 0), each test suite uses its own default thread count.
uint32_t _test_threads_count_arg{DEFAULT_TEST_THREADS};

// Command line option: '-td' OR '--test-duration'
// Usage: -td=5 OR --test-duration=5
// This option specifies the run time for each stress test in minutes.
// If not provided (or 0), each test suite uses its own default duration.
uint32_t _test_duration_arg{DEFAULT_TEST_DURATION};

// Command line option: '-ad' OR '--attach-detach-delay'.
// Usage: -ad=10 OR --attach-detach-delay=10
// This option specifies delay in milliseconds between detach and attach operations.
uint32_t _attach_detach_delay_arg{DEFAULT_ATTACH_DETACH_DELAY};

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
    test_control.attach_detach_delay_ms = _attach_detach_delay_arg;
    return test_control;
}

int
main(int argc, char* argv[])
{
    Catch::Session session;

    // Use Catch's composite command line parser.
    using namespace Catch::Clara;
    auto cli =
        session.cli() |
        Opt(_test_threads_count_arg, "thread count")["-tt"]["--test-threads"]("Count of threads per test") |
        Opt(_test_duration_arg, "test duration")["-td"]["--test-duration"]("Test duration (per-test) in minutes") |
        Opt(_attach_detach_delay_arg, "attach-detach delay")["-ad"]["--attach-detach-delay"](
            "Delay in milliseconds between detach and attach operations") |
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

    if (_test_verbose_output_arg) {
        cur_log_level = log_level::LOG_VERBOSE;
    }

    int test_result = session.run();

    // Tests that run against the 'usersim' framework need explicit clean-up before process
    // termination. This clean-up is handled by the OS and/or the in-kernel eBPF components for
    // tests that run against the kernel components.
    test_process_cleanup();

    return test_result;
}
