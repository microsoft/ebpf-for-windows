// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_test.h"
#include "api_test_jit.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "program_helper.h"
#include "sample_test_common.h"
#include "socket_helper.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <mstcpip.h>
#include <vector>

static void
_test_program_load(
    const char* file_name, bpf_prog_type program_type, ebpf_execution_type_t execution_type, int expected_load_result)
{
    struct bpf_object* object = nullptr;
    fd_t program_fd;

    int result = program_load_helper(file_name, program_type, execution_type, &object, &program_fd);
    REQUIRE(result == expected_load_result);
    if (expected_load_result != 0) {
        return;
    }

    REQUIRE(program_fd > 0);
    uint32_t next_id;
    REQUIRE(bpf_prog_get_next_id(0, &next_id) == 0);

    program_fd = bpf_prog_get_fd_by_id(next_id);
    REQUIRE(program_fd > 0);

    const char* program_file_name = nullptr;
    const char* program_section_name = nullptr;
    ebpf_execution_type_t program_execution_type;
    REQUIRE(
        ebpf_program_query_info(program_fd, &program_execution_type, &program_file_name, &program_section_name) ==
        EBPF_SUCCESS);
    _close(program_fd);

    if (execution_type == EBPF_EXECUTION_ANY) {
        execution_type = EBPF_EXECUTION_JIT;
    }
    REQUIRE(program_execution_type == execution_type);
    if (execution_type != EBPF_EXECUTION_NATIVE) {
        REQUIRE(strcmp(program_file_name, file_name) == 0);
    }

    ebpf_free_string(program_file_name);
    ebpf_free_string(program_section_name);
    uint32_t previous_id = next_id;
    REQUIRE(bpf_prog_get_next_id(previous_id, &next_id) == -ENOENT);

    bpf_object__close(object);
    REQUIRE(bpf_prog_get_next_id(0, &next_id) == -ENOENT);
}

#define DECLARE_LOAD_TEST_CASE(file, program_type, execution_type, expected_result)  \
    TEST_CASE("test_ebpf_program_load-" #file "-" #program_type "-" #execution_type) \
    {                                                                                \
        _test_program_load(file, program_type, execution_type, expected_result);     \
    }

#if defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define INTERPRET_LOAD_RESULT -ENOTSUP
#else
#define INTERPRET_LOAD_RESULT 0
#endif

// Program and map enumeration for bindmonitor belongs with the network extension tests.
#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("bind_program_next_previous_jit", "[netebpfext]")
{
    test_program_next_previous("bindmonitor.o", BIND_MONITOR_PROGRAM_COUNT);
}

TEST_CASE("bind_map_next_previous_jit", "[netebpfext]")
{
    test_map_next_previous("bindmonitor.o", BIND_MONITOR_MAP_COUNT);
}
#endif

TEST_CASE("bind_program_next_previous_native", "[netebpfext]")
{
    test_program_next_previous("bindmonitor.sys", BIND_MONITOR_PROGRAM_COUNT);
}

TEST_CASE("bind_map_next_previous_native", "[netebpfext]")
{
    test_map_next_previous("bindmonitor.sys", BIND_MONITOR_MAP_COUNT);
}

DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_JIT, JIT_LOAD_RESULT);
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_INTERPRET, INTERPRET_LOAD_RESULT);
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_BIND, EBPF_EXECUTION_JIT, JIT_LOAD_RESULT);
DECLARE_LOAD_TEST_CASE("bindmonitor.o", BPF_PROG_TYPE_SAMPLE, EBPF_EXECUTION_ANY, get_expected_jit_result(-EACCES));

TEST_CASE("netebpfext_enumerate_programs", "[netebpfext]")
{
    ebpf_api_program_info_t* program_infos = nullptr;
    const char* error_message = nullptr;

    ebpf_result_t result = ebpf_enumerate_programs("bindmonitor.o", false, &program_infos, &error_message);
    if (result == EBPF_SUCCESS && program_infos != nullptr) {
        REQUIRE(program_infos->section_name != nullptr);
        REQUIRE(std::string(program_infos->section_name) == "bind");
        REQUIRE(std::string(program_infos->program_name) == "BindMonitor");
        REQUIRE(program_infos->program_type == EBPF_PROGRAM_TYPE_BIND);
        REQUIRE(program_infos->expected_attach_type == EBPF_ATTACH_TYPE_BIND);
        ebpf_free_programs(program_infos);
    }
    ebpf_free_string(error_message);
}

static int
_perform_bind(_Out_ SOCKET* socket, uint16_t port_number)
{
    *socket = WSASocket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, 0);
    REQUIRE(*socket != INVALID_SOCKET);
    SOCKADDR_STORAGE sock_addr;
    sock_addr.ss_family = AF_INET6;
    INETADDR_SETANY((PSOCKADDR)&sock_addr);

    ((PSOCKADDR_IN6)&sock_addr)->sin6_port = htons(port_number);
    return bind(*socket, (PSOCKADDR)&sock_addr, sizeof(sock_addr));
}

static void
_test_bindmonitor_program(_In_ struct bpf_object* object)
{
    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");
    REQUIRE(process_map_fd > 0);

    fd_t limits_map_fd = bpf_object__find_map_fd_by_name(object, "limits_map");
    REQUIRE(limits_map_fd > 0);

    // Set the limit to 2. The third bind from the same app should fail.
    uint32_t key = 0;
    uint32_t value = 2;
    REQUIRE(bpf_map_update_elem(limits_map_fd, &key, &value, 0) == 0);

    WSAData data{};
    SOCKET sockets[3]{};
    REQUIRE(WSAStartup(2, &data) == 0);
    auto winsock_cleanup = std::unique_ptr<void, void (*)(void*)>(
        reinterpret_cast<void*>(1), [](void*) { WSACleanup(); });

    REQUIRE(_perform_bind(&sockets[0], 30000) == 0);
    REQUIRE(_perform_bind(&sockets[1], 30001) == 0);
    REQUIRE(_perform_bind(&sockets[2], 30002) != 0);
    for (SOCKET socket : sockets) {
        if (socket != INVALID_SOCKET) {
            closesocket(socket);
        }
    }
}

TEST_CASE("bindmonitor_native_test", "[netebpfext]")
{
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t helper;
    native_module_helper_t native_helper;
    native_helper.initialize("bindmonitor", EBPF_EXECUTION_NATIVE);
    helper.initialize(
        native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_BIND,
        "BindMonitor",
        EBPF_EXECUTION_NATIVE,
        nullptr,
        0,
        hook);

    _test_bindmonitor_program(helper.get_object());
}

TEST_CASE("bindmonitor_tailcall_native_test", "[netebpfext]")
{
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t helper;
    native_module_helper_t native_helper;
    native_helper.initialize("bindmonitor_tailcall", EBPF_EXECUTION_NATIVE);
    helper.initialize(
        native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_BIND,
        "BindMonitor",
        EBPF_EXECUTION_NATIVE,
        nullptr,
        0,
        hook);
    bpf_object* object = helper.get_object();

    bpf_program* callee0 = bpf_object__find_program_by_name(object, "BindMonitor_Callee0");
    REQUIRE(callee0 != nullptr);
    fd_t callee0_fd = bpf_program__fd(callee0);
    REQUIRE(callee0_fd > 0);

    bpf_program* callee1 = bpf_object__find_program_by_name(object, "BindMonitor_Callee1");
    REQUIRE(callee1 != nullptr);
    fd_t callee1_fd = bpf_program__fd(callee1);
    REQUIRE(callee1_fd > 0);

    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(object, "prog_array_map");
    REQUIRE(prog_map_fd > 0);
    uint32_t index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee0_fd, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    _test_bindmonitor_program(object);

    auto cleanup = [&]() {
        index = 0;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
        index = 1;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    };

    REQUIRE(bpf_object__find_map_by_name(object, "dummy_outer_map") != nullptr);
    REQUIRE(bpf_object__find_map_by_name(object, "dummy_outer_idx_map") != nullptr);
    cleanup();
}

struct _ebpf_program_load_test_parameters
{
    _Field_z_ const char* file_name;
    bpf_prog_type prog_type;
};

static void
_test_multiple_programs_load(
    int program_count,
    _In_reads_(program_count) const struct _ebpf_program_load_test_parameters* parameters,
    ebpf_execution_type_t execution_type,
    int expected_load_result)
{
    int result;
    std::vector<struct bpf_object*> objects;

    for (int i = 0; i < program_count; i++) {
        const char* file_name = parameters[i].file_name;
        bpf_prog_type program_type = parameters[i].prog_type;
        struct bpf_object* object;
        fd_t program_fd;

        result = program_load_helper(file_name, program_type, execution_type, &object, &program_fd);
        CAPTURE(file_name);
        REQUIRE(expected_load_result == result);
        if (expected_load_result == 0) {
            REQUIRE(program_fd > 0);
        } else {
            continue;
        }

        objects.push_back(object);
    }

    if (expected_load_result != 0) {
        return;
    }

    for (int i = 0; i < program_count; i++) {
        bpf_object__close(objects[i]);
    }
}

TEST_CASE("load_all_sample_programs", "[native_tests]")
{
    struct _ebpf_program_load_test_parameters test_parameters[] = {
        {"bindmonitor.sys", BPF_PROG_TYPE_UNSPEC},
        {"bindmonitor_bpf2bpf.sys", BPF_PROG_TYPE_UNSPEC},
        {"bindmonitor_mt_tailcall.sys", BPF_PROG_TYPE_UNSPEC},
        {"bindmonitor_perf_event_array.sys", BPF_PROG_TYPE_UNSPEC},
        {"bindmonitor_ringbuf.sys", BPF_PROG_TYPE_UNSPEC},
        {"bindmonitor_tailcall.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_count_connect4.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_count_connect6.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_mt_connect4.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_mt_connect6.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_sock_addr.sys", BPF_PROG_TYPE_UNSPEC},
        {"cgroup_sock_addr2.sys", BPF_PROG_TYPE_UNSPEC},
        {"process_start_key.sys", BPF_PROG_TYPE_UNSPEC},
        {"sockops.sys", BPF_PROG_TYPE_UNSPEC},
        {"thread_start_time.sys", BPF_PROG_TYPE_UNSPEC}};

    _test_multiple_programs_load(_countof(test_parameters), test_parameters, EBPF_EXECUTION_NATIVE, 0);
}

static uint64_t
read_pid_tgid(struct bpf_object* object)
{
    struct bpf_map* map = bpf_object__find_map_by_name(object, "pidtgid_map");
    REQUIRE(map != nullptr);
    uint32_t key = 0;
    uint64_t pid_tgid = 0;
    REQUIRE(bpf_map_lookup_elem(bpf_map__fd(map), &key, &pid_tgid) == 0);
    return pid_tgid;
}

TEST_CASE("bpf_get_current_pid_tgid_sock_addr", "[helpers]")
{
    native_module_helper_t native_helper;
    native_helper.initialize("pidtgid_netebpf", EBPF_EXECUTION_NATIVE);

    hook_helper_t hook(EBPF_ATTACH_TYPE_CGROUP_INET4_BIND);
    program_load_attach_helper_t helper;
    uint32_t compartment_id = 0;
    helper.initialize(
        native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        "sock_addr_program",
        EBPF_EXECUTION_NATIVE,
        &compartment_id,
        sizeof(compartment_id),
        hook);

    wsa_helper_t wsa_helper;
    REQUIRE(wsa_helper.initialize() == 0);
    datagram_client_socket_t bound_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT, IPv4);

    uint64_t pid_tgid = read_pid_tgid(helper.get_object());
    REQUIRE(static_cast<uint32_t>(pid_tgid >> 32) == GetCurrentProcessId());
    REQUIRE(static_cast<uint32_t>(pid_tgid) == GetCurrentThreadId());
}

TEST_CASE("bpf_get_current_pid_tgid_sock_ops", "[helpers]")
{
    native_module_helper_t native_helper;
    native_helper.initialize("pidtgid_netebpf", EBPF_EXECUTION_NATIVE);

    hook_helper_t hook(EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS);
    program_load_attach_helper_t helper;
    uint32_t compartment_id = 0;
    helper.initialize(
        native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_SOCK_OPS,
        "sock_ops_program",
        EBPF_EXECUTION_NATIVE,
        &compartment_id,
        sizeof(compartment_id),
        hook);

    wsa_helper_t wsa_helper;
    REQUIRE(wsa_helper.initialize() == 0);
    datagram_server_socket_t server_socket(SOCK_DGRAM, IPPROTO_UDP, SOCKET_TEST_PORT);
    datagram_client_socket_t client_socket(SOCK_DGRAM, IPPROTO_UDP, 0);
    sockaddr_storage destination_address{};
    IN6ADDR_SETV4MAPPED(
        reinterpret_cast<PSOCKADDR_IN6>(&destination_address), &in4addr_loopback, scopeid_unspecified, 0);
    client_socket.send_message_to_remote_host(CLIENT_MESSAGE, destination_address, SOCKET_TEST_PORT);

    uint64_t pid_tgid = read_pid_tgid(helper.get_object());
    REQUIRE(static_cast<uint32_t>(pid_tgid >> 32) == GetCurrentProcessId());
    REQUIRE(static_cast<uint32_t>(pid_tgid) != 0);
}

// Intentionally leaves BIND program resources open to exercise core cleanup at process exit.
TEST_CASE("close_unload_test", "[native_tests][native_close_cleanup_tests]")
{
    hook_helper_t hook(EBPF_ATTACH_TYPE_BIND);
    program_load_attach_helper_t helper;
    native_module_helper_t native_helper;
    native_helper.initialize("bindmonitor_tailcall", EBPF_EXECUTION_NATIVE);
    helper.initialize(
        native_helper.get_file_name().c_str(),
        BPF_PROG_TYPE_BIND,
        "BindMonitor",
        EBPF_EXECUTION_NATIVE,
        nullptr,
        0,
        hook);
    bpf_object* object = helper.get_object();

    bpf_program* callee0 = bpf_object__find_program_by_name(object, "BindMonitor_Callee0");
    REQUIRE(callee0 != nullptr);
    fd_t callee0_fd = bpf_program__fd(callee0);
    REQUIRE(callee0_fd > 0);

    bpf_program* callee1 = bpf_object__find_program_by_name(object, "BindMonitor_Callee1");
    REQUIRE(callee1 != nullptr);
    fd_t callee1_fd = bpf_program__fd(callee1);
    REQUIRE(callee1_fd > 0);

    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(object, "prog_array_map");
    REQUIRE(prog_map_fd > 0);
    uint32_t index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee0_fd, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);
    index = 2;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);
    index = 4;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);
    index = 7;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    _test_bindmonitor_program(object);

    // The block of commented code after this comment is for documentation purposes only.
    //
    // A well-behaved user mode application _should_ call these calls to correctly free the allocated objects. In case
    // of careless applications that do not do so (or even well behaved applications, when they crash or terminate for
    // some reason before getting to this point), the 'premature application close' event handling _should_ take care
    // of reclaiming and free'ing such objects. All unit tests belonging to the '[native_close_cleanup_tests]'
    // unit-test class simulate this behavior by _not_ calling the clean-up api calls.
    //
    // For native tests (meant for execution on the kernel mode ebpf-for-windows driver), this event will be handled
    // by the ebpf-core kernel mode driver on test application termination.
    //
    // The success/failure of the [native_close_cleanup_tests] tests can only be (indirectly) checked by attempting to
    // stop the ebpf-core driver after executing this class of tests. If the clean-up by the ebpf-core driver is not
    // successful, it cannot be stopped/unloaded. This step is performed automatically by the CI/CD test pass runs and
    // will need to be performed as an explicit manual step after a manually initiated test-run.
    //
    // On a final note, each test in the [native_close_cleanup_tests] set _must_ load a .sys driver (if it needs one)
    // that either has not been loaded yet, or was loaded but has since been unloaded (before start of the test). Given
    // that we deliberately skip the clean-up API calls, the drivers stay loaded at the end of the individual test. An
    // attempt to (re)load the same driver again (by the next test) will fail (as it should), but leads to spurious
    // test failures (by way of an assert due to an error returned by bpf_object__load() in the
    // program_load_attach_helper_t constructor).

    /*
        --- DO NOT REMOVE OR UN-COMMENT ---

    auto cleanup = [prog_map_fd, &index]() {
        index = 0;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);

        index = 1;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);

        index = 2;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);

        index = 4;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);

        index = 7;
        REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    };

    // Clean up tail calls.
    cleanup();

    // Free the program as well.
    bpf_object__close(object);
    */
}
