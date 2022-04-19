// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <cstdarg>
#include <stdio.h>
#include <string>
#include "capture_helper.hpp"
#include "catch_wrapper.hpp"
#include "ebpf_api.h"

// Run a given command and return the output and exit code.
std::string
run_command(_In_ PCSTR command_line, _Out_ int* result)
{
    capture_helper_t capture;
    errno_t error = capture.begin_capture();
    if (error != NO_ERROR) {
        *result = error;
        return "Couldn't capture output\n";
    }

    STARTUPINFOA startup_info = {0};
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    startup_info.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup_info.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION process_info;
    PSTR writable_command_line = _strdup(command_line);
    BOOL ok = CreateProcessA(
        nullptr, writable_command_line, nullptr, nullptr, true, 0, nullptr, nullptr, &startup_info, &process_info);
    free(writable_command_line);
    if (!ok) {
        *result = GetLastError();
        return "Couldn't start bpftool.exe\n";
    }

    WaitForSingleObject(process_info.hProcess, INFINITE);

    DWORD exit_code;
    if (!GetExitCodeProcess(process_info.hProcess, &exit_code)) {
        exit_code = GetLastError();
    }

    CloseHandle(process_info.hProcess);
    CloseHandle(process_info.hThread);

    std::string stderr_contents = capture.get_stderr_contents();
    std::string stdout_contents = capture.get_stdout_contents();

    *result = exit_code;
    return stdout_contents + stderr_contents;
}

TEST_CASE("help", "[help]")
{
    int result;
    std::string output = run_command("bpftool help", &result);
    REQUIRE(
        output == "Usage: bpftool [OPTIONS] OBJECT { COMMAND | help }\n"
                  "       bpftool batch file FILE\n"
                  "       bpftool version\n"
                  "\n"
                  "       OBJECT := { prog | map | link | net }\n"
                  "       OPTIONS := { {-j|--json} [{-p|--pretty}] | {-d|--debug} | {-l|--legacy} |\n"
                  "                    {-V|--version} }\n");
    REQUIRE(result == 0);
}

TEST_CASE("prog help", "[prog][help]")
{
    int result;
    std::string output = run_command("bpftool prog help", &result);
    REQUIRE(
        output == "Usage: bpftool prog { show | list } [PROG]\n"
                  "       bpftool prog pin   PROG FILE\n"
                  "       bpftool prog { load | loadall } OBJ  PATH \\\n"
                  "                         [type TYPE] [dev NAME] \\\n"
                  "                         [map { idx IDX | name NAME } MAP]\\\n"
                  "                         [pinmaps MAP_DIR]\n"
                  "       bpftool prog help\n"
                  "\n"
                  "       MAP := { id MAP_ID | pinned FILE | name MAP_NAME }\n"
                  "       PROG := { id PROG_ID | pinned FILE | name PROG_NAME }\n"
                  "       TYPE := { bind | xdp }\n"
                  "       OPTIONS := { {-j|--json} [{-p|--pretty}] | {-d|--debug} | {-l|--legacy} |\n"
                  "                    {-m|--mapcompat} | \n");
    REQUIRE(result == 0);
}

// The !shouldfail tag indicates that this test is known to fail
// even though the test code is probably correct.  The tag should
// be removed once the code it tests is fixed.
TEST_CASE("prog load map_in_map.o", "[!shouldfail][prog][load]")
{
    int result;
    std::string output;

    output = run_command("bpftool prog show", &result);
    REQUIRE(output == "");
    REQUIRE(result == 0);

    output = run_command("bpftool prog load map_in_map.o map_in_map", &result);
    REQUIRE(output == "");
    REQUIRE(result == 0);

    output = run_command("netsh ebpf sh prog", &result);
    REQUIRE(
        output == "    ID  Pins  Links  Mode       Type           Name\n"
                  "======  ====  =====  =========  =============  ====================\n"
                  "196609     1      0  JIT        xdp            lookup\n\n");
    REQUIRE(result == 0);

    output = run_command("bpftool prog show", &result);
    REQUIRE(output == "196609: xdp  name lookup\n\n");
    REQUIRE(result == 0);

    // Netsh currently outputs a spurious "Program not found" after the delete.
    output = run_command("netsh ebpf delete prog 196609", &result);
    REQUIRE(
        output == "Unpinned 196609 from map_in_map\n"
                  "Program not found\n\n");
    REQUIRE(result == 0);

    output = run_command("bpftool prog show", &result);
    REQUIRE(output == "");
    REQUIRE(result == 0);
}

TEST_CASE("map create", "[!shouldfail][map]")
{
    int status;
    std::string output =
        run_command("bpftool map create FileName type array key 4 value 4 entries 2 name Name", &status);
    REQUIRE(output == "");
    REQUIRE(status == 0);

    output = run_command("bpftool map dump id 65537", &status);
    REQUIRE(
        output == "key: 00 00 00 00  value: 00 00 00 00\n"
                  "key: 01 00 00 00  value: 00 00 00 00\n"
                  "Found 2 elements\n");
    REQUIRE(status == 0);

    ebpf_result_t result = ebpf_object_unpin("FileName");
    REQUIRE(result == EBPF_SUCCESS);
}

TEST_CASE("prog show id 1", "[prog][show]")
{
    int result;
    std::string output = run_command("bpftool prog show id 1", &result);
    REQUIRE(output == "Error: get by id (1): No such file or directory\n");
    REQUIRE(result == -1);
}