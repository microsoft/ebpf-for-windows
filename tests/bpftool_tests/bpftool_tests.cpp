// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "capture_helper.hpp"
#include "catch_wrapper.hpp"
#include "ebpf_api.h"
#include "native_helper.hpp"

#include <cstdarg>
#include <filesystem>
#include <fstream>
#include <stdio.h>
#include <string>

// Run a given command and return the output and exit code.
std::string
run_command(_In_z_ const char* command_line, _Out_ int* result)
{
    printf("Running command: %s\n\n", command_line);

    capture_helper_t capture;
    errno_t error = capture.begin_capture();
    if (error != NO_ERROR) {
        *result = error;
        return "Couldn't capture output\n";
    }

    *result = system(command_line);

    std::string stderr_contents = capture.get_stderr_contents();
    std::string stdout_contents = capture.get_stdout_contents();

    printf("Command output:\n%s\n%s\n", stdout_contents.c_str(), stderr_contents.c_str());

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
                  "                         [type TYPE] \\\n"
                  "                         [pinmaps MAP_DIR]\n"
                  "       bpftool prog help\n"
                  "\n"
                  "       PROG := { id PROG_ID | pinned FILE | name PROG_NAME }\n"
                  "       TYPE := { bind | cgroup/connect4 | cgroup/connect6 | xdp }\n"
                  "       OPTIONS := { {-j|--json} [{-p|--pretty}] | {-d|--debug} | {-l|--legacy} |\n"
                  "                    {-m|--mapcompat} | \n");
    REQUIRE(result == 0);
}

TEST_CASE("prog load map_in_map", "[prog][load]")
{
    int result;
    std::string output;

    output = run_command("bpftool prog show", &result);
    REQUIRE(output == "");
    REQUIRE(result == 0);

    char command[80];
    sprintf_s(
        command,
        sizeof(command),
        "bpftool --legacy prog load map_in_map_btf%s map_in_map",
        EBPF_PROGRAM_FILE_EXTENSION);
    output = run_command(command, &result);
    REQUIRE(output == "");
    REQUIRE(result == 0);

    output = run_command("bpftool prog show", &result);
    REQUIRE(result == 0);
    std::string id = std::to_string(atoi(output.c_str()));
    size_t offset = output.find(" map_ids ");
    REQUIRE(offset != std::string::npos);
    std::string map_id = std::to_string(atoi(output.substr(offset + 9).c_str()));
    REQUIRE(output == id + ": sample  name lookup  \n  map_ids " + map_id + "\n");

    output = run_command(("bpftool prog pin id " + id + " pin2").c_str(), &result);
    REQUIRE(output == "");
    REQUIRE(result == 0);

    std::string expected_output = "\n\n     ID     Type  Path\n";
    expected_output += "=======  =======  ==============\n";
    expected_output += std::format("{:>7s}  Program  map_in_map\n", id);
    expected_output += std::format("{:>7s}  Program  pin2\n", id);

    output = run_command("netsh ebpf show pins", &result);
    REQUIRE(output == expected_output);
    REQUIRE(result == 0);

    output = run_command(("netsh ebpf delete prog " + id).c_str(), &result);
    REQUIRE(
        output == "\nUnpinned " + id +
                      " from map_in_map\n"
                      "Unpinned " +
                      id + " from pin2\n");
    REQUIRE(result == 0);

    output = run_command("bpftool prog show", &result);
    REQUIRE(output == "");
    REQUIRE(result == 0);
}

#if 0
// TODO(#2974): Once XDP support has fully migrated to xdp-for-windows repo, these tests should be migrated.
TEST_CASE("prog attach by interface alias", "[prog][load]")
{
    int result;
    std::string output;
    char command[80];
    sprintf_s(
        command, sizeof(command), "bpftool --legacy prog load droppacket%s droppacket", EBPF_PROGRAM_FILE_EXTENSION);

    output = run_command(command, &result);
    REQUIRE(output == "");
    REQUIRE(result == 0);

    output = run_command("bpftool prog show", &result);
    REQUIRE(result == 0);
    std::string id = std::to_string(atoi(output.c_str()));
    size_t offset = output.find(" map_ids ");
    REQUIRE(offset != std::string::npos);
    std::string map_id1 = std::to_string(atoi(output.substr(offset + 9).c_str()));
    offset = output.find(",");
    REQUIRE(offset != std::string::npos);
    std::string map_id2 = std::to_string(atoi(output.substr(offset + 1).c_str()));
    REQUIRE(output == id + ": xdp  name DropPacket  \n  map_ids " + map_id1 + "," + map_id2 + "\n");

    // Try attaching to an interface by friendly name.
    output = run_command(("bpftool net attach xdp id " + id + " dev \"Loopback Pseudo-Interface 1\"").c_str(),
    &result); REQUIRE(result == 0);

    output = run_command(("netsh ebpf delete prog " + id).c_str(), &result);
    REQUIRE(output == "\nUnpinned " + id + " from droppacket\n");
    REQUIRE(result == 0);

    output = run_command("bpftool prog show", &result);
    REQUIRE(output == "");
    REQUIRE(result == 0);
}
#endif

TEST_CASE("map create", "[map]")
{
    int status;
    std::string output =
        run_command("bpftool map create FileName type array key 4 value 4 entries 2 name Name", &status);
    REQUIRE(output == "");
    REQUIRE(status == 0);

    output = run_command("bpftool map show", &status);
    REQUIRE(status == 0);
    std::string id = std::to_string(atoi(output.c_str()));
    REQUIRE(output == id + ": array  name Name  flags 0x0\n\tkey 4B  value 4B  max_entries 2\n");

    output = run_command(("bpftool map dump id " + id).c_str(), &status);
    REQUIRE(
        output == "key: 00 00 00 00  value: 00 00 00 00\n"
                  "key: 01 00 00 00  value: 00 00 00 00\n"
                  "Found 2 elements\n");
    REQUIRE(status == 0);

    REQUIRE(ebpf_object_unpin("FileName") == EBPF_SUCCESS);
}

TEST_CASE("map show pinned", "[map]")
{
    int status;
    std::string output =
        run_command("bpftool map create \\\\test_map type hash key 4 value 4 entries 10 name testing", &status);
    REQUIRE(output == "");
    REQUIRE(status == 0);

    output = run_command("bpftool map show name testing", &status);
    REQUIRE(status == 0);
    std::string id = std::to_string(atoi(output.c_str()));
    REQUIRE(output == id + ": hash  name testing  flags 0x0\n\tkey 4B  value 4B  max_entries 10\n");

    output = run_command("bpftool map show pinned \\\\test_map", &status);
    REQUIRE(status == 0);
    REQUIRE(output == id + ": hash  name testing  flags 0x0\n\tkey 4B  value 4B  max_entries 10\n");

    REQUIRE(ebpf_object_unpin("\\\\test_map") == EBPF_SUCCESS);
}

TEST_CASE("prog show id 1", "[prog][show]")
{
    int result;
    std::string output = run_command("bpftool prog show id 1", &result);
    REQUIRE(output == "Error: get by id (1): No such file or directory\n");
    REQUIRE(result == -1);
}

TEST_CASE("prog prog run", "[prog][load]")
{
    int result;
    std::string output;
    char command[80];
    sprintf_s(
        command,
        sizeof(command),
        "bpftool --legacy prog load test_sample_ebpf%s test_sample_ebpf",
        EBPF_PROGRAM_FILE_EXTENSION);

    output = run_command(command, &result);
    REQUIRE(output == "");
    REQUIRE(result == 0);

    output = run_command("bpftool prog show", &result);
    REQUIRE(result == 0);
    std::string id = std::to_string(atoi(output.c_str()));
    size_t offset = output.find(" map_ids ");
    REQUIRE(offset != std::string::npos);
    std::string map_id1 = std::to_string(atoi(output.substr(offset + 9).c_str()));

    // The sample program is expected to have a single map. The output format
    // differs based on whether the program is loaded as a native driver or not.
    if (std::string(EBPF_PROGRAM_FILE_EXTENSION) == ".sys") {
        REQUIRE(output == id + ": sample  name test_program_entry  \n  map_ids " + map_id1 + "\n");
    } else {
        offset = output.find(",");
        REQUIRE(offset != std::string::npos);
        std::string map_id2 = std::to_string(atoi(output.substr(offset + 1).c_str()));
        REQUIRE(output == id + ": sample  name test_program_entry  \n  map_ids " + map_id1 + "," + map_id2 + "\n");
    }

    std::filesystem::path input_file = "ctx_in.txt";
    std::filesystem::path output_file = "ctx_out.txt";

    // Write input data to file.
    std::ofstream output_stream(input_file, std::ios::out | std::ios::binary);

    // Write 1000 bytes of data.
    for (int i = 0; i < 1000; i++) {
        output_stream << "a";
    }
    output_stream.close();

    // Run program
    output = run_command(
        ("bpftool prog run id " + id + " ctx_in \"" + input_file.string() + "\" ctx_out \"" + output_file.string() +
         "\" repeat 1000000")
            .c_str(),
        &result);
    REQUIRE(result == 0);

    // Check if output contains: "Return value: 42, duration (average): 222ns"
    REQUIRE(output.find("Return value: 42, duration (average): ") != std::string::npos);

    output = run_command(("netsh ebpf delete prog " + id).c_str(), &result);
    REQUIRE(output == "\nUnpinned " + id + " from test_sample_ebpf\n");
    REQUIRE(result == 0);

    output = run_command("bpftool prog show", &result);
    REQUIRE(output == "");
    REQUIRE(result == 0);
}
