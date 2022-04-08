// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This module facilitates testing various socket related eBPF program types and hooks.

#define CATCH_CONFIG_RUNNER

#include "bpf/bpf.h"
#pragma warning(push)
#pragma warning(disable : 4200)
#include "bpf/libbpf.h"
#pragma warning(pop)
#include "catch_wrapper.hpp"
#include "ebpf_structs.h"
#include "socket_tests.h"

#include <mstcpip.h>

TEST_CASE("attach_programs", "[socket_tests]")
{
    struct bpf_object* object;
    int program_fd;
    int result = bpf_prog_load("cgroup_sock_addr.o", BPF_PROG_TYPE_CGROUP_SOCK_ADDR, &object, &program_fd);
    REQUIRE(result == 0);
    REQUIRE(object != nullptr);

    bpf_program* connect4_program = bpf_object__find_program_by_name(object, "authorize_connect4");
    REQUIRE(connect4_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect4_program)), 0, BPF_CGROUP_INET4_CONNECT, 0);
    REQUIRE(result == 0);

    bpf_program* recv_accept4_program = bpf_object__find_program_by_name(object, "authorize_recv_accept4");
    REQUIRE(recv_accept4_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept4_program)), 0, BPF_CGROUP_INET4_RECV_ACCEPT, 0);
    REQUIRE(result == 0);

    bpf_program* connect6_program = bpf_object__find_program_by_name(object, "authorize_connect6");
    REQUIRE(connect6_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(connect6_program)), 0, BPF_CGROUP_INET6_CONNECT, 0);
    REQUIRE(result == 0);

    bpf_program* recv_accept6_program = bpf_object__find_program_by_name(object, "authorize_recv_accept6");
    REQUIRE(recv_accept6_program != nullptr);

    result = bpf_prog_attach(
        bpf_program__fd(const_cast<const bpf_program*>(recv_accept6_program)), 0, BPF_CGROUP_INET6_RECV_ACCEPT, 0);
    REQUIRE(result == 0);

    bpf_object__close(object);
}

int
main(int argc, char* argv[])
{
    WSAData data;

    int error = WSAStartup(2, &data);
    if (error != 0) {
        printf("Unable to load Winsock: %d\n", error);
        return 1;
    }

    int result = Catch::Session().run(argc, argv);

    WSACleanup();

    return result;
}