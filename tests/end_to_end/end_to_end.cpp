// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include "api_common.hpp"
#include "api_internal.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "bpf2c.h"
#include "capture_helper.hpp"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_core.h"
#include "helpers.h"
#include "ioctl_helper.h"
#include "mock.h"
namespace ebpf {
#include "net/if_ether.h"
#include "net/ip.h"
#include "net/udp.h"
}; // namespace ebpf
#include "passed_test_log.h"
#include "platform.h"
#include "program_helper.h"
#include "sample_test_common.h"
#include "test_helper.hpp"
#include "usersim/ke.h"
#include "watchdog.h"
#include "xdp_tests_common.h"

#include <WinSock2.h>
#include <in6addr.h>
#include <array>
#include <cguid.h>
#include <chrono>
#include <mutex>
#include <ntsecapi.h>
#include <thread>

using namespace Platform;

CATCH_REGISTER_LISTENER(_passed_test_log)
CATCH_REGISTER_LISTENER(_watchdog)

#define NATIVE_DRIVER_SERVICE_NAME L"test_service"
#define NATIVE_DRIVER_SERVICE_NAME_2 L"test_service2"
#define SERVICE_PATH_PREFIX L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"
#define PARAMETERS_PATH_PREFIX L"System\\CurrentControlSet\\Services\\"
#define SERVICE_PARAMETERS L"Parameters"
#define NPI_MODULE_ID L"NpiModuleId"

#define BPF_PROG_TYPE_INVALID 100
#define BPF_ATTACH_TYPE_INVALID 100

#define CONCAT(s1, s2) s1 s2
#define DECLARE_TEST_CASE(_name, _group, _function, _suffix, _execution_type) \
    TEST_CASE(CONCAT(_name, _suffix), _group) { _function(_execution_type); }
#define DECLARE_NATIVE_TEST(_name, _group, _function) \
    DECLARE_TEST_CASE(_name, _group, _function, "-native", EBPF_EXECUTION_NATIVE)
#if !defined(CONFIG_BPF_JIT_DISABLED)
#define DECLARE_JIT_TEST(_name, _group, _function) \
    DECLARE_TEST_CASE(_name, _group, _function, "-jit", EBPF_EXECUTION_JIT)
#else
#define DECLARE_JIT_TEST(_name, _group, _function)
#endif
#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define DECLARE_INTERPRET_TEST(_name, _group, _function) \
    DECLARE_TEST_CASE(_name, _group, _function, "-interpret", EBPF_EXECUTION_INTERPRET)
#else
#define DECLARE_INTERPRET_TEST(_name, _group, _function)
#endif

#define DECLARE_ALL_TEST_CASES(_name, _group, _function) \
    DECLARE_JIT_TEST(_name, _group, _function)           \
    DECLARE_NATIVE_TEST(_name, _group, _function)        \
    DECLARE_INTERPRET_TEST(_name, _group, _function)

#define DECLARE_JIT_TEST_CASES(_name, _group, _function) \
    DECLARE_JIT_TEST(_name, _group, _function)           \
    DECLARE_NATIVE_TEST(_name, _group, _function)

std::vector<uint8_t>
prepare_ip_packet(uint16_t ethernet_type)
{
    std::vector<uint8_t> packet(
        sizeof(ebpf::ETHERNET_HEADER) +
        ((ethernet_type == ETHERNET_TYPE_IPV4) ? sizeof(ebpf::IPV4_HEADER) : sizeof(ebpf::IPV6_HEADER)));
    auto ethernet_header = reinterpret_cast<ebpf::ETHERNET_HEADER*>(packet.data());
    if (ethernet_type == ETHERNET_TYPE_IPV4) {
        auto ipv4_header = reinterpret_cast<ebpf::IPV4_HEADER*>(ethernet_header + 1);
        ipv4_header->HeaderLength = sizeof(ebpf::IPV4_HEADER) / sizeof(uint32_t);
    }
    ethernet_header->Type = ntohs(ethernet_type);

    return packet;
}

void
append_udp_header(uint16_t udp_length, std::vector<uint8_t>& ip_packet)
{
    ip_packet.resize(ip_packet.size() + sizeof(ebpf::UDP_HEADER));
    auto ethernet_header = reinterpret_cast<ebpf::ETHERNET_HEADER*>(ip_packet.data());
    ebpf::UDP_HEADER* udp;
    if (ethernet_header->Type == ntohs(ETHERNET_TYPE_IPV4)) {
        auto ipv4_header = reinterpret_cast<ebpf::IPV4_HEADER*>(ethernet_header + 1);
        ipv4_header->Protocol = IPPROTO_UDP;
        udp = reinterpret_cast<ebpf::UDP_HEADER*>(ipv4_header + 1);
    } else {
        auto ipv6 = reinterpret_cast<ebpf::IPV6_HEADER*>(ethernet_header + 1);
        ipv6->NextHeader = IPPROTO_UDP;
        udp = reinterpret_cast<ebpf::UDP_HEADER*>(ipv6 + 1);
    }
    udp->length = udp_length;
}

std::vector<uint8_t>
prepare_udp_packet(uint16_t udp_length, uint16_t ethernet_type)
{
    auto packet = prepare_ip_packet(ethernet_type);
    append_udp_header(udp_length, packet);
    return packet;
}

static inline int
_get_total_map_count()
{
    ebpf_id_t start_id = 0;
    ebpf_id_t end_id = 0;
    int map_count = 0;
    while (bpf_map_get_next_id(start_id, &end_id) == 0) {
        map_count++;
        start_id = end_id;
    }

    return map_count;
}

const std::array<uint8_t, 6> _test_source_mac = {0, 1, 2, 3, 4, 5};
const std::array<uint8_t, 6> _test_destination_mac = {0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

struct _ipv4_address_pair
{
    const in_addr& source;
    const in_addr& destination;
};

struct _ipv6_address_pair
{
    const in6_addr& source;
    const in6_addr& destination;
};

const in_addr _test_source_ipv4 = {10, 0, 0, 1};
const in_addr _test_destination_ipv4 = {20, 0, 0, 1};
const struct _ipv4_address_pair _test_ipv4_addrs = {_test_source_ipv4, _test_destination_ipv4};

const in_addr _test2_source_ipv4 = {30, 0, 0, 1};
const in_addr _test2_destination_ipv4 = {40, 0, 0, 1};
const struct _ipv4_address_pair _test2_ipv4_addrs = {_test2_source_ipv4, _test2_destination_ipv4};

const in6_addr _test_source_ipv6 = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2e, 0xfe, 0x12, 0x34};
const in6_addr _test_destination_ipv6 = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2e, 0xfe, 0x56, 0x78};
const struct _ipv6_address_pair _test_ipv6_addrs = {_test_source_ipv6, _test_destination_ipv6};

const in6_addr _test2_source_ipv6 = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2e, 0xfe, 0x9a, 0xbc};
const in6_addr _test2_destination_ipv6 = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2e, 0xfe, 0xde, 0xf0};
const struct _ipv6_address_pair _test2_ipv6_addrs = {_test2_source_ipv6, _test2_destination_ipv6};

typedef class _ip_packet
{
  public:
    _ip_packet(
        ADDRESS_FAMILY address_family,
        _In_ const std::array<uint8_t, 6>& source_mac,
        _In_ const std::array<uint8_t, 6>& destination_mac,
        _In_opt_ const void* ip_addresses)
        : _address_family(address_family)
    {
        _packet = prepare_ip_packet((address_family == AF_INET) ? ETHERNET_TYPE_IPV4 : ETHERNET_TYPE_IPV6);
        set_mac_addresses(source_mac, destination_mac);
        if (_address_family == AF_INET) {
            (ip_addresses == nullptr) ? set_ipv4_addresses(&_test_ipv4_addrs.source, &_test_ipv4_addrs.destination)
                                      : set_ipv4_addresses(
                                            &(reinterpret_cast<const _ipv4_address_pair*>(ip_addresses))->source,
                                            &(reinterpret_cast<const _ipv4_address_pair*>(ip_addresses))->destination);
        } else {
            (ip_addresses == nullptr) ? set_ipv6_addresses(&_test_ipv6_addrs.source, &_test_ipv6_addrs.destination)
                                      : set_ipv6_addresses(
                                            &(reinterpret_cast<const _ipv6_address_pair*>(ip_addresses))->source,
                                            &(reinterpret_cast<const _ipv6_address_pair*>(ip_addresses))->destination);
        }
    }
    uint8_t*
    data()
    {
        return _packet.data();
    }
    size_t
    size()
    {
        return _packet.size();
    }

    std::vector<uint8_t>&
    packet()
    {
        return _packet;
    }

    void
    set_mac_addresses(_In_ const std::array<uint8_t, 6>& source_mac, _In_ const std::array<uint8_t, 6>& destination_mac)
    {
        auto ethernet_header = reinterpret_cast<ebpf::ETHERNET_HEADER*>(_packet.data());
        memcpy(ethernet_header->Source, source_mac.data(), sizeof(ethernet_header->Source));
        memcpy(ethernet_header->Destination, destination_mac.data(), sizeof(ethernet_header->Destination));
    }
    void
    set_ipv4_addresses(_In_ const in_addr* source_address, _In_ const in_addr* destination_address)
    {
        auto ethernet_header = reinterpret_cast<ebpf::ETHERNET_HEADER*>(_packet.data());
        auto ipv4_header = reinterpret_cast<ebpf::IPV4_HEADER*>(ethernet_header + 1);

        ipv4_header->SourceAddress = source_address->s_addr;
        ipv4_header->DestinationAddress = destination_address->s_addr;
    }
    void
    set_ipv6_addresses(_In_ const in6_addr* source_address, _In_ const in6_addr* destination_address)
    {
        auto ethernet_header = reinterpret_cast<ebpf::ETHERNET_HEADER*>(_packet.data());
        auto ipv6 = reinterpret_cast<ebpf::IPV6_HEADER*>(ethernet_header + 1);

        memcpy(ipv6->SourceAddress, source_address, sizeof(ebpf::ipv6_address_t));
        memcpy(ipv6->DestinationAddress, destination_address, sizeof(ebpf::ipv6_address_t));
    }

    ADDRESS_FAMILY _address_family;
    std::vector<uint8_t> _packet;

} ip_packet_t;

typedef class _udp_packet : public ip_packet_t
{
  public:
    _udp_packet(
        ADDRESS_FAMILY address_family,
        _In_ const std::array<uint8_t, 6>& source_mac = _test_source_mac,
        _In_ const std::array<uint8_t, 6>& destination_mac = _test_destination_mac,
        _In_opt_ const void* ip_addresses = nullptr,
        uint16_t datagram_length = 1024)
        : ip_packet_t{address_family, source_mac, destination_mac, ip_addresses}
    {
        append_udp_header(sizeof(ebpf::UDP_HEADER) + datagram_length, _packet);
    }

    static const ebpf::UDP_HEADER*
    _get_udp_header(_In_ const uint8_t* packet_buffer, ADDRESS_FAMILY address_family)
    {
        auto ethernet_header = reinterpret_cast<const ebpf::ETHERNET_HEADER*>(packet_buffer);
        const ebpf::UDP_HEADER* udp = nullptr;
        if (address_family == AF_INET) {
            auto ip = reinterpret_cast<const ebpf::IPV4_HEADER*>(ethernet_header + 1);
            udp = reinterpret_cast<const ebpf::UDP_HEADER*>(ip + 1);
        } else {
            REQUIRE(address_family == AF_INET6);
            auto ip = reinterpret_cast<const ebpf::IPV6_HEADER*>(ethernet_header + 1);
            udp = reinterpret_cast<const ebpf::UDP_HEADER*>(ip + 1);
        }
        return udp;
    }

    void
    set_source_port(uint16_t source_port)
    {
        auto udp = const_cast<ebpf::UDP_HEADER*>(_get_udp_header(_packet.data(), _address_family));
        udp->srcPort = source_port;
    }

    void
    set_destination_port(uint16_t destination_port)
    {
        auto udp = const_cast<ebpf::UDP_HEADER*>(_get_udp_header(_packet.data(), _address_family));
        udp->destPort = destination_port;
    }

} udp_packet_t;

typedef class _ip_in_ip_packet : public ip_packet_t
{
  public:
    _ip_in_ip_packet(
        ADDRESS_FAMILY address_family,
        _In_ const std::array<uint8_t, 6>& source_mac = _test_source_mac,
        _In_ const std::array<uint8_t, 6>& destination_mac = _test_destination_mac,
        _In_opt_ const void* outer_ip_addresses = nullptr,
        _In_opt_ const void* inner_ip_addresses = nullptr)
        : ip_packet_t{address_family, source_mac, destination_mac, outer_ip_addresses}
    {
        if (_address_family == AF_INET) {
            _packet.resize(_packet.size() + sizeof(ebpf::IPV4_HEADER));

            (inner_ip_addresses == nullptr)
                ? set_inner_ipv4_addresses(&_test2_ipv4_addrs.source, &_test2_ipv4_addrs.destination)
                : set_inner_ipv4_addresses(
                      &(reinterpret_cast<const _ipv4_address_pair*>(inner_ip_addresses))->source,
                      &(reinterpret_cast<const _ipv4_address_pair*>(inner_ip_addresses))->destination);
        } else {
            _packet.resize(_packet.size() + sizeof(ebpf::IPV6_HEADER));

            (inner_ip_addresses == nullptr)
                ? set_inner_ipv6_addresses(&_test2_ipv6_addrs.source, &_test2_ipv6_addrs.destination)
                : set_inner_ipv6_addresses(
                      &(reinterpret_cast<const _ipv6_address_pair*>(inner_ip_addresses))->source,
                      &(reinterpret_cast<const _ipv6_address_pair*>(inner_ip_addresses))->destination);
        }
    }

    void
    set_inner_ipv4_addresses(_In_ const in_addr* source_address, _In_ const in_addr* destination_address)
    {
        auto ethernet_header = reinterpret_cast<ebpf::ETHERNET_HEADER*>(_packet.data());
        auto outer_ipv4_header = reinterpret_cast<ebpf::IPV4_HEADER*>(ethernet_header + 1);
        outer_ipv4_header->Protocol = IPPROTO_IPV4;
        // Test code assumes length of IP header = sizeof(IPV4_HEADER).
        auto inner_ipv4_header = outer_ipv4_header + 1;
        inner_ipv4_header->SourceAddress = source_address->s_addr;
        inner_ipv4_header->DestinationAddress = destination_address->s_addr;
    }
    void
    set_inner_ipv6_addresses(_In_ const in6_addr* source_address, _In_ const in6_addr* destination_address)
    {
        auto ethernet_header = reinterpret_cast<ebpf::ETHERNET_HEADER*>(_packet.data());
        auto outer_ipv6 = reinterpret_cast<ebpf::IPV6_HEADER*>(ethernet_header + 1);
        outer_ipv6->NextHeader = IPPROTO_IPV6;
        auto inner_ipv6 = outer_ipv6 + 1;
        memcpy(inner_ipv6->SourceAddress, source_address, sizeof(ebpf::ipv6_address_t));
        memcpy(inner_ipv6->DestinationAddress, destination_address, sizeof(ebpf::ipv6_address_t));
    }

} ip_in_ip_packet_t;

#define SAMPLE_PATH ""
#define TEST_IFINDEX 17

int
ebpf_program_load(
    _In_z_ const char* file_name,
    bpf_prog_type prog_type,
    ebpf_execution_type_t execution_type,
    _Out_ bpf_object_ptr* unique_object,
    _Out_ fd_t* program_fd,
    _Outptr_opt_result_maybenull_z_ const char** log_buffer)
{
    *program_fd = ebpf_fd_invalid;
    if (log_buffer) {
        *log_buffer = nullptr;
    }

    unique_object->reset(nullptr);

    bpf_object* new_object = bpf_object__open(file_name);
    if (new_object == nullptr) {
        return -errno;
    }
    REQUIRE(ebpf_object_set_execution_type(new_object, execution_type) == EBPF_SUCCESS);
    bpf_program* program = bpf_object__next_program(new_object, nullptr);
    if (prog_type != BPF_PROG_TYPE_UNSPEC) {
        bpf_program__set_type(program, prog_type);
    }
    int error = bpf_object__load(new_object);
    if (error < 0) {
        if (log_buffer) {
            size_t log_buffer_size;
            if (program != nullptr) {
                const char* log_buffer_str = bpf_program__log_buf(program, &log_buffer_size);
                if (log_buffer_str != nullptr) {
                    *log_buffer = ebpf_duplicate_string(log_buffer_str);
                }
            }
        }
        bpf_object__close(new_object);
        return error;
    }

    *program_fd = bpf_program__fd(program);
    unique_object->reset(new_object);
    return 0;
}

void
droppacket_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;

    int result;
    const char* error_message = nullptr;
    bpf_object_ptr unique_object;
    fd_t program_fd;
    bpf_link_ptr link;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "droppacket_um.dll" : "droppacket.o");
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);
    fd_t dropped_packet_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "dropped_packet_map");

    // Tell the program which interface to filter on.
    fd_t interface_index_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "interface_index_map");
    uint32_t key = 0;
    uint32_t if_index = TEST_IFINDEX;
    REQUIRE(bpf_map_update_elem(interface_index_map_fd, &key, &if_index, EBPF_ANY) == EBPF_SUCCESS);

    // Attach only to the single interface being tested.
    REQUIRE(hook.attach_link(program_fd, &if_index, sizeof(if_index), &link) == EBPF_SUCCESS);

    // Create a 0-byte UDP packet.
    auto packet0 = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);

    uint64_t value = 1000;
    REQUIRE(bpf_map_update_elem(dropped_packet_map_fd, &key, &value, EBPF_ANY) == EBPF_SUCCESS);

    // Test that we drop the packet and increment the map
    xdp_md_t ctx0{packet0.data(), packet0.data() + packet0.size(), 0, TEST_IFINDEX};

    uint32_t hook_result;
    REQUIRE(hook.fire(&ctx0, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == XDP_DROP);

    REQUIRE(bpf_map_lookup_elem(dropped_packet_map_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value == 1001);

    REQUIRE(bpf_map_delete_elem(dropped_packet_map_fd, &key) == EBPF_SUCCESS);

    REQUIRE(bpf_map_lookup_elem(dropped_packet_map_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value == 0);

    // Create a normal (not 0-byte) UDP packet.
    auto packet10 = prepare_udp_packet(10, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx10{packet10.data(), packet10.data() + packet10.size(), 0, TEST_IFINDEX};

    // Test that we don't drop the normal packet.
    REQUIRE(hook.fire(&ctx10, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == XDP_PASS);

    REQUIRE(bpf_map_lookup_elem(dropped_packet_map_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value == 0);

    // Reattach to all interfaces so we can test the ingress_ifindex field passed to the program.
    hook.detach_and_close_link(&link);
    if_index = 0;
    REQUIRE(hook.attach_link(program_fd, &if_index, sizeof(if_index), &link) == EBPF_SUCCESS);

    // Fire a 0-length UDP packet on the interface index in the map, which should be dropped.
    REQUIRE(hook.fire(&ctx0, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == XDP_DROP);
    REQUIRE(bpf_map_lookup_elem(dropped_packet_map_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value == 1);

    // Reset the count of dropped packets.
    REQUIRE(bpf_map_delete_elem(dropped_packet_map_fd, &key) == EBPF_SUCCESS);

    {
        // Negative test: State is too small.
        uint8_t state[sizeof(ebpf_execution_context_state_t) - 1] = {0};
        REQUIRE(hook.batch_begin(sizeof(state), state) == EBPF_INVALID_ARGUMENT);
    }

    // Fire a 0-length UDP packet on the interface index in the map, using batch mode, which should be dropped.
    uint8_t state[sizeof(ebpf_execution_context_state_t)] = {0};
    REQUIRE(hook.batch_begin(sizeof(state), state) == EBPF_SUCCESS);
    // Process 10 packets in batch mode.
    for (int i = 0; i < 10; i++) {
        REQUIRE(hook.batch_invoke(&ctx0, &hook_result, state) == EBPF_SUCCESS);
        REQUIRE(hook_result == XDP_DROP);
    }
    REQUIRE(hook.batch_end(state) == EBPF_SUCCESS);
    REQUIRE(bpf_map_lookup_elem(dropped_packet_map_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value == 10);

    // Reset the count of dropped packets.
    REQUIRE(bpf_map_delete_elem(dropped_packet_map_fd, &key) == EBPF_SUCCESS);

    // Fire a 0-length packet on any interface that is not in the map, which should be allowed.
    xdp_md_t ctx4{packet0.data(), packet0.data() + packet0.size(), 0, if_index + 1};
    REQUIRE(hook.fire(&ctx4, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == XDP_PASS);
    REQUIRE(bpf_map_lookup_elem(dropped_packet_map_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value == 0);

    hook.detach_and_close_link(&link);

    bpf_object__close(unique_object.release());
}

// See also divide_by_zero_test_km in api_test.cpp for the kernel-mode equivalent.
void
divide_by_zero_test_um(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;

    int result;
    const char* error_message = nullptr;
    bpf_object_ptr unique_object;
    fd_t program_fd;
    bpf_link_ptr link;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "divide_by_zero_um.dll" : "divide_by_zero.o");
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);
    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);

    // Test that we drop the packet and increment the map
    xdp_md_t ctx{packet.data(), packet.data() + packet.size(), 0, TEST_IFINDEX};

    uint32_t hook_result;
    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);

    REQUIRE(hook_result == 0);

    hook.detach_and_close_link(&link);

    bpf_object__close(unique_object.release());
}

void
bad_map_name_um(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;

    int result;
    const char* error_message = nullptr;
    bpf_object_ptr unique_object;
    fd_t program_fd;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "bad_map_name_um.dll" : "bad_map_name.o");

    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == -EINVAL);

    bpf_object__close(unique_object.release());
}

typedef struct _process_entry
{
    uint32_t count;
    uint8_t name[64];
} process_entry_t;

typedef struct _audit_entry
{
    uint64_t logon_id;
    int32_t is_admin;
} audit_entry_t;

uint32_t
get_bind_count_for_pid(fd_t map_fd, uint64_t pid)
{
    process_entry_t entry{};
    bpf_map_lookup_elem(map_fd, &pid, &entry);

    return entry.count;
}

static void
_validate_bind_audit_entry(fd_t map_fd, uint64_t pid)
{
    audit_entry_t entry = {0};
    int result = bpf_map_lookup_elem(map_fd, &pid, &entry);
    REQUIRE(result == 0);

    REQUIRE(entry.is_admin == -1);

    REQUIRE(entry.logon_id != 0);
    SECURITY_LOGON_SESSION_DATA* data = NULL;
    result = LsaGetLogonSessionData((PLUID)&entry.logon_id, &data);
    REQUIRE(result == ERROR_SUCCESS);

    LsaFreeReturnBuffer(data);
}

bind_action_t
emulate_bind(std::function<ebpf_result_t(void*, uint32_t*)>& invoke, uint64_t pid, const char* appid)
{
    uint32_t result;
    std::string app_id = appid;
    bind_md_t ctx{0};
    ctx.app_id_start = (uint8_t*)app_id.c_str();
    ctx.app_id_end = (uint8_t*)(app_id.c_str()) + app_id.size();
    ctx.process_id = pid;
    ctx.operation = BIND_OPERATION_BIND;
    REQUIRE(invoke(reinterpret_cast<void*>(&ctx), &result) == EBPF_SUCCESS);
    return static_cast<bind_action_t>(result);
}

void
emulate_unbind(std::function<ebpf_result_t(void*, uint32_t*)>& invoke, uint64_t pid, const char* appid)
{
    uint32_t result;
    std::string app_id = appid;
    bind_md_t ctx{0};
    ctx.process_id = pid;
    ctx.operation = BIND_OPERATION_UNBIND;
    REQUIRE(invoke(&ctx, &result) == EBPF_SUCCESS);
}

void
set_bind_limit(fd_t map_fd, uint32_t limit)
{
    uint32_t limit_key = 0;
    REQUIRE(bpf_map_update_elem(map_fd, &limit_key, &limit, EBPF_ANY) == EBPF_SUCCESS);
}

static uint64_t
_get_current_pid_tgid()
{
    return ((uint64_t)GetCurrentProcessId() << 32 | GetCurrentThreadId());
}

void
bindmonitor_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    uint64_t fake_pid = 12345;
    int result;
    bpf_object_ptr unique_object;
    bpf_link_ptr link;
    fd_t program_fd;
    uint64_t process_id = _get_current_pid_tgid();

    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);

    // Note: We are deliberately using "bindmonitor_um.dll" here as we want the programs to be loaded from
    // the individual dll, instead of the combined DLL. This helps in testing the DLL stub which is generated
    // bpf2c.exe tool.
    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "bindmonitor_um.dll" : "bindmonitor.o");

    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);
    fd_t limit_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "limits_map");
    REQUIRE(limit_map_fd > 0);
    fd_t process_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "process_map");
    REQUIRE(process_map_fd > 0);
    fd_t audit_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "audit_map");
    REQUIRE(audit_map_fd > 0);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // Apply policy of maximum 2 binds per process
    set_bind_limit(limit_map_fd, 2);

    std::function<ebpf_result_t(void*, uint32_t*)> invoke =
        [&hook](_Inout_ void* context, _Out_ uint32_t* result) -> ebpf_result_t { return hook.fire(context, result); };
    // Bind first port - success
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);
    _validate_bind_audit_entry(audit_map_fd, process_id);

    // Bind second port - success
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 2);
    _validate_bind_audit_entry(audit_map_fd, process_id);

    // Bind third port - blocked
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_DENY);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 2);
    _validate_bind_audit_entry(audit_map_fd, process_id);

    // Unbind second port
    emulate_unbind(invoke, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);
    _validate_bind_audit_entry(audit_map_fd, process_id);

    // Unbind first port
    emulate_unbind(invoke, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 0);
    _validate_bind_audit_entry(audit_map_fd, process_id);

    // Bind from two apps to test enumeration
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);
    _validate_bind_audit_entry(audit_map_fd, process_id);

    fake_pid = 54321;
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_2") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);
    _validate_bind_audit_entry(audit_map_fd, process_id);

    uint64_t pid;
    REQUIRE(bpf_map_get_next_key(process_map_fd, NULL, &pid) == 0);
    REQUIRE(pid != 0);
    REQUIRE(bpf_map_get_next_key(process_map_fd, &pid, &pid) == 0);
    REQUIRE(pid != 0);
    REQUIRE(bpf_map_get_next_key(process_map_fd, &pid, &pid) < 0);
    REQUIRE(errno == ENOENT);

    hook.detach_and_close_link(&link);

    bpf_object__close(unique_object.release());
}

void
bindmonitor_tailcall_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    uint64_t fake_pid = 12345;
    int result;
    bpf_object_ptr unique_object;
    bpf_link_ptr link;
    fd_t program_fd;

    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);

    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE ? "bindmonitor_tailcall_um.dll" : "bindmonitor_tailcall.o");
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);
    fd_t limit_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "limits_map");
    REQUIRE(limit_map_fd > 0);
    fd_t process_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "process_map");
    REQUIRE(process_map_fd > 0);

    // Set up tail calls.
    struct bpf_program* callee0 = bpf_object__find_program_by_name(unique_object.get(), "BindMonitor_Callee0");
    REQUIRE(callee0 != nullptr);
    fd_t callee0_fd = bpf_program__fd(callee0);
    REQUIRE(callee0_fd > 0);

    struct bpf_program* callee1 = bpf_object__find_program_by_name(unique_object.get(), "BindMonitor_Callee1");
    REQUIRE(callee1 != nullptr);
    fd_t callee1_fd = bpf_program__fd(callee1);
    REQUIRE(callee1_fd > 0);

    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "prog_array_map");
    REQUIRE(prog_map_fd > 0);

    uint32_t index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee0_fd, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    // Validate various maps.

    // Validate map-in-maps with "inner_id".
    struct bpf_map* outer_map = bpf_object__find_map_by_name(unique_object.get(), "dummy_outer_map");
    REQUIRE(outer_map != nullptr);

    int outer_map_fd = bpf_map__fd(outer_map);
    REQUIRE(outer_map_fd > 0);

    // Validate map-in-maps with "inner_idx".
    struct bpf_map* outer_idx_map = bpf_object__find_map_by_name(unique_object.get(), "dummy_outer_idx_map");
    REQUIRE(outer_idx_map != nullptr);

    int outer_idx_map_fd = bpf_map__fd(outer_idx_map);
    REQUIRE(outer_idx_map_fd > 0);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // Apply policy of maximum 2 binds per process
    set_bind_limit(limit_map_fd, 2);

    std::function<ebpf_result_t(void*, uint32_t*)> invoke =
        [&hook](_Inout_ void* context, _Out_ uint32_t* result) -> ebpf_result_t { return hook.fire(context, result); };
    // Bind first port - success
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);

    // Bind second port - success
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 2);

    // Bind third port - blocked
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_DENY);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 2);

    // Unbind second port
    emulate_unbind(invoke, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);

    // Unbind first port
    emulate_unbind(invoke, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 0);

    // Bind from two apps to test enumeration
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);

    fake_pid = 54321;
    REQUIRE(emulate_bind(invoke, fake_pid, "fake_app_2") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);

    uint64_t pid;
    REQUIRE(bpf_map_get_next_key(process_map_fd, NULL, &pid) == 0);
    REQUIRE(pid != 0);
    REQUIRE(bpf_map_get_next_key(process_map_fd, &pid, &pid) == 0);
    REQUIRE(pid != 0);
    REQUIRE(bpf_map_get_next_key(process_map_fd, &pid, &pid) < 0);
    REQUIRE(errno == ENOENT);

    hook.detach_and_close_link(&link);

    index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);

    bpf_object__close(unique_object.release());
}

void
bindmonitor_ring_buffer_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    int result;
    bpf_object_ptr unique_object;
    bpf_link_ptr link;
    fd_t program_fd;

    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);

    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE ? "bindmonitor_ringbuf_um.dll" : "bindmonitor_ringbuf.o");

    // Load and attach a bind eBPF program that uses a ring buffer map to notify about bind operations.
    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    fd_t process_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "process_map");
    REQUIRE(process_map_fd > 0);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    REQUIRE(hook.attach_link(program_fd, nullptr, 0, &link) == EBPF_SUCCESS);

    // Create a list of fake app IDs and set it to event context.
    std::string fake_app_ids_prefix = "fake_app";
    std::vector<std::vector<char>> fake_app_ids;
    for (int i = 0; i < RING_BUFFER_TEST_EVENT_COUNT; i++) {
        std::string temp = fake_app_ids_prefix + std::to_string(i);
        std::vector<char> fake_app_id(temp.begin(), temp.end());
        fake_app_ids.push_back(fake_app_id);
    }

    uint64_t fake_pid = 12345;
    std::function<ebpf_result_t(void*, uint32_t*)> invoke =
        [&hook](_Inout_ void* context, _Out_ uint32_t* result) -> ebpf_result_t { return hook.fire(context, result); };

    ring_buffer_api_test_helper(process_map_fd, fake_app_ids, [&](int i) {
        // Emulate bind operation.
        std::vector<char> fake_app_id = fake_app_ids[i];
        fake_app_id.push_back('\0');
        REQUIRE(emulate_bind(invoke, fake_pid + i, fake_app_id.data()) == BIND_PERMIT);
    });

    hook.detach_and_close_link(&link);

    bpf_object__close(unique_object.release());
}

static void
_utility_helper_functions_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);
    uint32_t ifindex = 0;
    const char* file_name =
        (execution_type == EBPF_EXECUTION_NATIVE ? "test_utility_helpers_um.dll" : "test_utility_helpers.o");
    program_load_attach_helper_t program_helper(
        file_name, BPF_PROG_TYPE_XDP, "test_utility_helpers", execution_type, &ifindex, sizeof(ifindex), hook);
    bpf_object* object = program_helper.get_object();

    // Dummy context (not used by the eBPF program).
    xdp_md_t ctx{};

    uint32_t hook_result;
    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 0);

    verify_utility_helper_results(object, false);
}

void
map_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;

    int result;
    const char* error_message = nullptr;
    bpf_object_ptr unique_object;
    fd_t program_fd;
    bpf_link_ptr link;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_um.dll" : "map.o");

    result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_XDP, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size(), 0, TEST_IFINDEX};

    uint32_t hook_result;
    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    // Program should return 0 if all the map tests pass.
    REQUIRE(hook_result >= 0);

    hook.detach_and_close_link(&link);

    bpf_object__close(unique_object.release());
}

DECLARE_ALL_TEST_CASES("droppacket", "[end_to_end]", droppacket_test);
DECLARE_ALL_TEST_CASES("divide_by_zero", "[end_to_end]", divide_by_zero_test_um);
DECLARE_ALL_TEST_CASES("bindmonitor", "[end_to_end]", bindmonitor_test);
DECLARE_ALL_TEST_CASES("bindmonitor-tailcall", "[end_to_end]", bindmonitor_tailcall_test);
DECLARE_ALL_TEST_CASES("bindmonitor-ringbuf", "[end_to_end]", bindmonitor_ring_buffer_test);
DECLARE_ALL_TEST_CASES("utility-helpers", "[end_to_end]", _utility_helper_functions_test);
DECLARE_ALL_TEST_CASES("map", "[end_to_end]", map_test);
DECLARE_ALL_TEST_CASES("bad_map_name", "[end_to_end]", bad_map_name_um);

TEST_CASE("enum section", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    ebpf_section_info_t* section_data = nullptr;
    uint32_t result;

    REQUIRE(
        (result = ebpf_enumerate_sections(SAMPLE_PATH "droppacket.o", true, &section_data, &error_message),
         ebpf_free_string(error_message),
         error_message = nullptr,
         result == 0));
    for (auto current_section = section_data; current_section != nullptr; current_section = current_section->next) {
        ebpf_stat_t* stat = current_section->stats;
        REQUIRE(strcmp(stat->key, "Instructions") == 0);
        REQUIRE(stat->value == 47);
    }
    ebpf_free_sections(section_data);
    ebpf_free_string(error_message);
}

TEST_CASE("verify section", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    const char* report = nullptr;
    uint32_t result;
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    ebpf_api_verifier_stats_t stats;
    REQUIRE(
        (result = ebpf_api_elf_verify_section_from_file(
             SAMPLE_PATH "droppacket.o", "xdp", nullptr, false, &report, &error_message, &stats),
         ebpf_free_string(error_message),
         error_message = nullptr,
         result == 0));
    REQUIRE(report != nullptr);
    ebpf_free_string(report);
}

TEST_CASE("verify section with invalid program type", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    const char* report = nullptr;
    uint32_t result;
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_BIND);

    ebpf_api_verifier_stats_t stats;
    result = ebpf_api_elf_verify_section_from_file(
        SAMPLE_PATH "droppacket.o", "xdp", &EBPF_PROGRAM_TYPE_UNSPECIFIED, false, &report, &error_message, &stats);

    REQUIRE(result == 1);
    REQUIRE(error_message != nullptr);
    ebpf_free_string(error_message);
}

void
verify_bad_section(const char* path, const std::string& expected_error_message)
{
    _test_helper_end_to_end test_helper;
    const char* error_message = nullptr;
    const char* report = nullptr;
    uint32_t result;
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);
    ebpf_api_verifier_stats_t stats;
    result = ebpf_api_elf_verify_section_from_file(path, "xdp", nullptr, false, &report, &error_message, &stats);
    REQUIRE(result != 0);
    REQUIRE(report == nullptr);
    REQUIRE((error_message != nullptr && std::string(error_message) == expected_error_message));
    ebpf_free_string(report);
    ebpf_free_string(error_message);
}
TEST_CASE("verify bad1.o", "[end_to_end][fuzzed]")
{
    verify_bad_section(
        SAMPLE_PATH "bad\\bad1.o",
        "error: ELF file bad\\bad1.o is malformed: Failed parsing in struct _SECTION_HEADER_TABLE_ENTRY field none "
        "reason constraint failed");
}
TEST_CASE("verify bad2.o", "[end_to_end][fuzzed]")
{
    verify_bad_section(
        SAMPLE_PATH "bad\\bad2.o",
        "error: ELF file bad\\bad2.o is malformed: Failed parsing in struct _E_IDENT field SEVEN.refinement reason "
        "constraint failed");
}

static void
_cgroup_load_test(
    _In_z_ const char* file,
    _In_z_ const char* name,
    ebpf_program_type_t& program_type,
    ebpf_attach_type_t& attach_type,
    ebpf_execution_type_t execution_type)
{
    int result;
    const char* error_message = nullptr;
    fd_t program_fd;

    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(program_type, attach_type);
    program_info_provider_t program_info(program_type);
    bpf_object_ptr unique_object;

    result = ebpf_program_load(file, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }

    REQUIRE(result == 0);

    bpf_program* program = bpf_object__find_program_by_name(unique_object.get(), name);
    REQUIRE(program != nullptr);

    uint32_t compartment_id = 0;
    REQUIRE(hook.attach(program, &compartment_id, sizeof(compartment_id)) == EBPF_SUCCESS);
    REQUIRE(hook.detach(ebpf_fd_invalid, &compartment_id, sizeof(compartment_id)) == EBPF_SUCCESS);

    compartment_id = 1;
    REQUIRE(hook.attach(program, &compartment_id, sizeof(compartment_id)) == EBPF_SUCCESS);
    REQUIRE(hook.detach(program_fd, &compartment_id, sizeof(compartment_id)) == EBPF_SUCCESS);

    bpf_object__close(unique_object.release());
}
static void
_cgroup_sock_addr_load_test(
    _In_z_ const char* file,
    _In_z_ const char* name,
    ebpf_attach_type_t& attach_type,
    ebpf_execution_type_t execution_type)
{
    _cgroup_load_test(file, name, EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR, attach_type, execution_type);
}

#define DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST2(file, name, attach_type, name_suffix, file_suffix, execution_type) \
    TEST_CASE("cgroup_sockaddr_load_test_" name "_" #attach_type "_" name_suffix, "[cgroup_sock_addr]")        \
    {                                                                                                          \
        _cgroup_sock_addr_load_test(file file_suffix, name, attach_type, execution_type);                      \
    }

#if !defined(CONFIG_BPF_JIT_DISABLED)
#define DECLARE_CGROUP_SOCK_ADDR_LOAD_JIT_TEST(file, name, attach_type) \
    DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST2(file, name, attach_type, "jit", ".o", EBPF_EXECUTION_JIT)
#else
#define DECLARE_CGROUP_SOCK_ADDR_LOAD_JIT_TEST(file, name, attach_type)
#endif

#define DECLARE_CGROUP_SOCK_ADDR_LOAD_NATIVE_TEST(file, name, attach_type) \
    DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST2(file, name, attach_type, "native", "_um.dll", EBPF_EXECUTION_NATIVE)

#define DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST(file, name, attach_type) \
    DECLARE_CGROUP_SOCK_ADDR_LOAD_JIT_TEST(file, name, attach_type) \
    DECLARE_CGROUP_SOCK_ADDR_LOAD_NATIVE_TEST(file, name, attach_type)

DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST(
    SAMPLE_PATH "cgroup_sock_addr", "authorize_connect4", EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT);
DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST(
    SAMPLE_PATH "cgroup_sock_addr", "authorize_connect6", EBPF_ATTACH_TYPE_CGROUP_INET6_CONNECT);
DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST(
    SAMPLE_PATH "cgroup_sock_addr", "authorize_recv_accept4", EBPF_ATTACH_TYPE_CGROUP_INET4_RECV_ACCEPT);
DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST(
    SAMPLE_PATH "cgroup_sock_addr", "authorize_recv_accept6", EBPF_ATTACH_TYPE_CGROUP_INET6_RECV_ACCEPT);

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("cgroup_sockops_load_test", "[cgroup_sockops]")
{
    _cgroup_load_test(
        "sockops.o",
        "connection_monitor",
        EBPF_PROGRAM_TYPE_SOCK_OPS,
        EBPF_ATTACH_TYPE_CGROUP_SOCK_OPS,
        EBPF_EXECUTION_JIT);
}
#endif

TEST_CASE("verify_test0", "[sample_extension]")
{
    _test_helper_end_to_end test_helper;
    program_info_provider_t sample_extension_program_info(EBPF_PROGRAM_TYPE_SAMPLE);

    const char* error_message = nullptr;
    const char* report = nullptr;
    uint32_t result;

    ebpf_api_verifier_stats_t stats;
    REQUIRE(
        (result = ebpf_api_elf_verify_section_from_file(
             SAMPLE_PATH "test_sample_ebpf.o", "sample_ext", nullptr, false, &report, &error_message, &stats),
         ebpf_free_string(error_message),
         error_message = nullptr,
         result == 0));
    REQUIRE(report != nullptr);
    ebpf_free_string(report);
}

TEST_CASE("verify_test1", "[sample_extension]")
{
    _test_helper_end_to_end test_helper;
    program_info_provider_t sample_extension_program_info(EBPF_PROGRAM_TYPE_SAMPLE);

    const char* error_message = nullptr;
    const char* report = nullptr;
    uint32_t result;

    ebpf_api_verifier_stats_t stats;

    REQUIRE(
        (result = ebpf_api_elf_verify_section_from_file(
             SAMPLE_PATH "test_sample_ebpf.o", "sample_ext/utility", nullptr, false, &report, &error_message, &stats),
         ebpf_free_string(error_message),
         error_message = nullptr,
         result == 0));
    REQUIRE(report != nullptr);
    ebpf_free_string(report);

    REQUIRE(result == 0);
}

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("map_pinning_test", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    int result;
    bpf_object_ptr unique_object;
    fd_t program_fd;

    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);

    result = ebpf_program_load(
        SAMPLE_PATH "bindmonitor.o",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_INTERPRET,
        &unique_object,
        &program_fd,
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);

    std::string process_maps_name = "bindmonitor::process_map";
    std::string limit_maps_name = "bindmonitor::limits_map";

    REQUIRE(bpf_object__find_map_by_name(unique_object.get(), "process_map") != nullptr);
    REQUIRE(bpf_object__find_map_by_name(unique_object.get(), "limits_map") != nullptr);
    REQUIRE(
        bpf_map__pin(bpf_object__find_map_by_name(unique_object.get(), "process_map"), process_maps_name.c_str()) ==
        EBPF_SUCCESS);
    REQUIRE(
        bpf_map__pin(bpf_object__find_map_by_name(unique_object.get(), "limits_map"), limit_maps_name.c_str()) ==
        EBPF_SUCCESS);

    fd_t fd = bpf_obj_get(process_maps_name.c_str());
    REQUIRE(fd != ebpf_fd_invalid);
    Platform::_close(fd);

    fd = bpf_obj_get(limit_maps_name.c_str());
    REQUIRE(fd != ebpf_fd_invalid);
    Platform::_close(fd);

    REQUIRE(
        bpf_map__unpin(bpf_object__find_map_by_name(unique_object.get(), "process_map"), process_maps_name.c_str()) ==
        EBPF_SUCCESS);
    REQUIRE(
        bpf_map__unpin(bpf_object__find_map_by_name(unique_object.get(), "limits_map"), limit_maps_name.c_str()) ==
        EBPF_SUCCESS);

    REQUIRE(bpf_obj_get(limit_maps_name.c_str()) == ebpf_fd_invalid);

    REQUIRE(bpf_obj_get(process_maps_name.c_str()) == ebpf_fd_invalid);

    bpf_object__close(unique_object.release());
}
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("enumerate_and_query_programs", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    uint32_t program_id;
    uint32_t next_program_id;
    const char* error_message = nullptr;
    int result;
    const char* file_name = nullptr;
    const char* section_name = nullptr;
    bpf_object_ptr unique_object[2];
    fd_t program_fds[2] = {0};

    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_JIT,
        &unique_object[0],
        &program_fds[0],
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_INTERPRET,
        &unique_object[1],
        &program_fds[1],
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    ebpf_execution_type_t type;
    program_id = 0;
    REQUIRE(bpf_prog_get_next_id(program_id, &next_program_id) == 0);
    program_id = next_program_id;
    fd_t program_fd = bpf_prog_get_fd_by_id(program_id);
    REQUIRE(program_fd > 0);
    REQUIRE(ebpf_program_query_info(program_fd, &type, &file_name, &section_name) == EBPF_SUCCESS);
    Platform::_close(program_fd);
    REQUIRE(type == EBPF_EXECUTION_JIT);
    REQUIRE(strcmp(file_name, SAMPLE_PATH "droppacket.o") == 0);
    ebpf_free_string(file_name);
    file_name = nullptr;
    REQUIRE(strcmp(section_name, "xdp") == 0);
    ebpf_free_string(section_name);
    section_name = nullptr;

    REQUIRE(bpf_prog_get_next_id(program_id, &next_program_id) == 0);
    program_id = next_program_id;
    program_fd = bpf_prog_get_fd_by_id(program_id);
    REQUIRE(program_fd > 0);
    REQUIRE(ebpf_program_query_info(program_fd, &type, &file_name, &section_name) == EBPF_SUCCESS);
    Platform::_close(program_fd);
    REQUIRE(type == EBPF_EXECUTION_INTERPRET);
    REQUIRE(strcmp(file_name, SAMPLE_PATH "droppacket.o") == 0);
    REQUIRE(strcmp(section_name, "xdp") == 0);
    ebpf_free_string(file_name);
    ebpf_free_string(section_name);
    file_name = nullptr;
    section_name = nullptr;

    REQUIRE(bpf_prog_get_next_id(program_id, &next_program_id) == -ENOENT);

    for (int i = 0; i < _countof(unique_object); i++) {
        bpf_object__close(unique_object[i].release());
    }
}
#endif

TEST_CASE("pinned_map_enum", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    ebpf_test_pinned_map_enum();
}

#if !defined(CONFIG_BPF_JIT_DISABLED)
// This test uses ebpf_link_close() to test implicit detach.
TEST_CASE("implicit_detach", "[end_to_end]")
{
    // This test case does the following:
    // 1. Close program handle. An implicit detach should happen and program
    //    object should be deleted.
    // 2. Close link handle. The link object should be deleted.

    _test_helper_end_to_end test_helper;

    int result = 0;
    bpf_object_ptr unique_object;
    fd_t program_fd;
    const char* error_message = nullptr;
    bpf_link* link = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_JIT,
        &unique_object,
        &program_fd,
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // Call bpf_object__close() which will close the program fd. That should
    // detach the program from the hook and unload the program.
    bpf_object__close(unique_object.release());

    uint32_t program_id;
    REQUIRE(bpf_prog_get_next_id(0, &program_id) == -ENOENT);

    // Close link handle (without detaching). This should delete the link
    // object. ebpf_object_tracking_terminate() which is called when the test
    // exits checks if all the objects in EC have been deleted.
    hook.close_link(link);
}

// This test uses bpf_link__disconnect() and bpf_link__destroy() to test
// implicit detach.
TEST_CASE("implicit_detach_2", "[end_to_end]")
{
    // This test case does the following:
    // 1. Close program handle. An implicit detach should happen and the program
    //    object should be deleted.
    // 2. Close link handle. The link object should be deleted.

    _test_helper_end_to_end test_helper;

    int result = 0;
    bpf_object_ptr unique_object;
    fd_t program_fd;
    const char* error_message = nullptr;
    bpf_link* link = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_JIT,
        &unique_object,
        &program_fd,
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // Call bpf_object__close() which will close the program fd. That should
    // detach the program from the hook and unload the program.
    bpf_object__close(unique_object.release());

    uint32_t program_id;
    REQUIRE(bpf_prog_get_next_id(0, &program_id) == -ENOENT);

    // Close link handle (without detaching). This should delete the link
    // object. ebpf_object_tracking_terminate() which is called when the test
    // exits checks if all the objects in the execution context have been deleted.
    bpf_link__disconnect(link);
    REQUIRE(bpf_link__destroy(link) == 0);
}
#endif

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("explicit_detach", "[end_to_end]")
{
    // This test case does the following:
    // 1. Call detach API and then close the link handle. The link object
    //    should be deleted.
    // 2. Close program handle. The program object should be deleted.

    _test_helper_end_to_end test_helper;

    bpf_object_ptr unique_object;
    fd_t program_fd;
    bpf_link_ptr link;
    int result;
    const char* error_message = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_INTERPRET,
        &unique_object,
        &program_fd,
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // Detach and close link handle.
    // ebpf_object_tracking_terminate() which is called when the test
    // exits checks if all the objects in EC have been deleted.
    hook.detach_and_close_link(&link);

    // Close program handle.
    bpf_object__close(unique_object.release());
    uint32_t program_id;
    REQUIRE(bpf_prog_get_next_id(0, &program_id) == -ENOENT);
}

TEST_CASE("implicit_explicit_detach", "[end_to_end]")
{
    // This test case does the following:
    // 1. Close the program handle so that an implicit detach happens.
    // 2. Explicitly call detach and then close the link handle. Explicit
    //    detach in this step should be a no-op.

    _test_helper_end_to_end test_helper;

    bpf_object_ptr unique_object;
    fd_t program_fd;
    bpf_link_ptr link;
    int result;
    const char* error_message = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o",
        BPF_PROG_TYPE_UNSPEC,
        EBPF_EXECUTION_INTERPRET,
        &unique_object,
        &program_fd,
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(result == 0);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // Close program handle. That should detach the program from the hook
    // and unload the program.
    bpf_object__close(unique_object.release());
    uint32_t program_id;
    REQUIRE(bpf_prog_get_next_id(0, &program_id) == -ENOENT);

    // Detach and close link handle.
    // ebpf_object_tracking_terminate() which is called when the test
    // exits checks if all the objects in EC have been deleted.
    hook.detach_and_close_link(&link);
}
#endif

TEST_CASE("create_map", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    fd_t map_fd;
    uint32_t key = 0;
    uint64_t value = 10;
    int element_count = 2;

    map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(uint32_t), sizeof(uint64_t), 5, nullptr);
    REQUIRE(map_fd > 0);

    for (int i = 0; i < element_count; i++) {
        REQUIRE(bpf_map_update_elem(map_fd, &key, &value, EBPF_ANY) == EBPF_SUCCESS);
        key++;
        value++;
    }

    key = 0;
    value = 10;
    for (int i = 0; i < element_count; i++) {
        uint64_t read_value;
        REQUIRE(bpf_map_lookup_elem(map_fd, &key, &read_value) == EBPF_SUCCESS);
        REQUIRE(read_value == value);
        key++;
        value++;
    }

    Platform::_close(map_fd);
}

TEST_CASE("create_map_name", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    fd_t map_fd;
    uint32_t key = 0;
    uint64_t value = 10;
    int element_count = 2;
    const char* map_name = "array_map";

    map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, map_name, sizeof(uint32_t), sizeof(uint64_t), 5, nullptr);
    REQUIRE(map_fd > 0);

    for (int i = 0; i < element_count; i++) {
        REQUIRE(bpf_map_update_elem(map_fd, &key, &value, EBPF_ANY) == EBPF_SUCCESS);
        key++;
        value++;
    }

    key = 0;
    value = 10;
    for (int i = 0; i < element_count; i++) {
        uint64_t read_value;
        REQUIRE(bpf_map_lookup_elem(map_fd, &key, &read_value) == EBPF_SUCCESS);
        REQUIRE(read_value == value);
        key++;
        value++;
    }

    Platform::_close(map_fd);
}

static void
_xdp_reflect_packet_test(ebpf_execution_type_t execution_type, ADDRESS_FAMILY address_family)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);
    uint32_t ifindex = 0;
    program_load_attach_helper_t program_helper(
        SAMPLE_PATH "reflect_packet.o",
        BPF_PROG_TYPE_XDP,
        "reflect_packet",
        execution_type,
        &ifindex,
        sizeof(ifindex),
        hook);

    // Dummy UDP datagram with fake IP and MAC addresses.
    udp_packet_t packet(address_family);
    packet.set_destination_port(ntohs(REFLECTION_TEST_PORT));

    xdp_md_t ctx{packet.data(), packet.data() + packet.size(), 0, TEST_IFINDEX};

    uint32_t hook_result;
    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == XDP_TX);

    ebpf::ETHERNET_HEADER* ethernet_header = reinterpret_cast<ebpf::ETHERNET_HEADER*>(ctx.data);
    REQUIRE(memcmp(ethernet_header->Destination, _test_source_mac.data(), sizeof(ethernet_header->Destination)) == 0);
    REQUIRE(memcmp(ethernet_header->Source, _test_destination_mac.data(), sizeof(ethernet_header->Source)) == 0);

    if (address_family == AF_INET) {
        ebpf::IPV4_HEADER* ipv4_header = reinterpret_cast<ebpf::IPV4_HEADER*>(ethernet_header + 1);
        REQUIRE(ipv4_header->SourceAddress == _test_destination_ipv4.s_addr);
        REQUIRE(ipv4_header->DestinationAddress == _test_source_ipv4.s_addr);
    } else {
        ebpf::IPV6_HEADER* ipv6 = reinterpret_cast<ebpf::IPV6_HEADER*>(ethernet_header + 1);
        REQUIRE(memcmp(ipv6->SourceAddress, &_test_destination_ipv6, sizeof(ebpf::ipv6_address_t)) == 0);
        REQUIRE(memcmp(ipv6->DestinationAddress, &_test_source_ipv6, sizeof(ebpf::ipv6_address_t)) == 0);
    }
}

static void
_xdp_encap_reflect_packet_test(ebpf_execution_type_t execution_type, ADDRESS_FAMILY address_family)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);
    uint32_t ifindex = 0;
    program_load_attach_helper_t program_helper(
        SAMPLE_PATH "encap_reflect_packet.o",
        BPF_PROG_TYPE_XDP,
        "encap_reflect_packet",
        execution_type,
        &ifindex,
        sizeof(ifindex),
        hook);

    // Dummy UDP datagram with fake IP and MAC addresses.
    udp_packet_t packet(address_family);
    packet.set_destination_port(ntohs(REFLECTION_TEST_PORT));

    // Dummy context (not used by the eBPF program).
    xdp_md_helper_t ctx(packet.packet());

    uint32_t hook_result;
    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == XDP_TX);

    ebpf::ETHERNET_HEADER* ethernet_header = reinterpret_cast<ebpf::ETHERNET_HEADER*>(ctx.data);
    REQUIRE(memcmp(ethernet_header->Destination, _test_source_mac.data(), sizeof(ethernet_header->Destination)) == 0);
    REQUIRE(memcmp(ethernet_header->Source, _test_destination_mac.data(), sizeof(ethernet_header->Source)) == 0);

    if (address_family == AF_INET) {
        ebpf::IPV4_HEADER* ipv4_header = reinterpret_cast<ebpf::IPV4_HEADER*>(ethernet_header + 1);
        REQUIRE(ipv4_header->SourceAddress == _test_destination_ipv4.s_addr);
        REQUIRE(ipv4_header->DestinationAddress == _test_source_ipv4.s_addr);
        REQUIRE(ipv4_header->Protocol == IPPROTO_IPV4);
        ebpf::IPV4_HEADER* inner_ipv4_header = reinterpret_cast<ebpf::IPV4_HEADER*>(
            reinterpret_cast<uint8_t*>(ipv4_header) + (ipv4_header->HeaderLength * sizeof(uint32_t)));
        REQUIRE(inner_ipv4_header->SourceAddress == _test_destination_ipv4.s_addr);
        REQUIRE(inner_ipv4_header->DestinationAddress == _test_source_ipv4.s_addr);
    } else {
        ebpf::IPV6_HEADER* ipv6 = reinterpret_cast<ebpf::IPV6_HEADER*>(ethernet_header + 1);
        REQUIRE(memcmp(ipv6->SourceAddress, &_test_destination_ipv6, sizeof(ebpf::ipv6_address_t)) == 0);
        REQUIRE(memcmp(ipv6->DestinationAddress, &_test_source_ipv6, sizeof(ebpf::ipv6_address_t)) == 0);
        REQUIRE(ipv6->NextHeader == IPPROTO_IPV6);
        ebpf::IPV6_HEADER* inner_ipv6 = ipv6 + 1;
        REQUIRE(memcmp(inner_ipv6->SourceAddress, &_test_destination_ipv6, sizeof(ebpf::ipv6_address_t)) == 0);
        REQUIRE(memcmp(inner_ipv6->DestinationAddress, &_test_source_ipv6, sizeof(ebpf::ipv6_address_t)) == 0);
    }
}

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("printk", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);
    uint32_t ifindex = 0;
    program_load_attach_helper_t program_helper(
        SAMPLE_PATH "printk.o", BPF_PROG_TYPE_BIND, "func", EBPF_EXECUTION_INTERPRET, &ifindex, sizeof(ifindex), hook);

    // The current bind hook only works with IPv4, so compose a sample IPv4 context.
    SOCKADDR_IN addr = {AF_INET};
    addr.sin_port = htons(80);
    bind_md_t ctx = {0};
    ctx.process_id = GetCurrentProcessId();
    ctx.protocol = 2;
    ctx.socket_address_length = sizeof(addr);
    memcpy(&ctx.socket_address, &addr, ctx.socket_address_length);

    capture_helper_t capture;
    std::string output;
    uint32_t hook_result = 0;
    errno_t error = capture.begin_capture();
    if (error == NO_ERROR) {
        ebpf_result_t hook_fire_result = hook.fire(&ctx, &hook_result);
        output = capture.get_stdout_contents();
        REQUIRE(hook_fire_result == EBPF_SUCCESS);
    }
    std::string expected_output = "Hello, world\n"
                                  "Hello, world\n"
                                  "PID: " +
                                  std::to_string(ctx.process_id) +
                                  " using %u\n"
                                  "PID: " +
                                  std::to_string(ctx.process_id) +
                                  " using %lu\n"
                                  "PID: " +
                                  std::to_string(ctx.process_id) +
                                  " using %llu\n"
                                  "PID: " +
                                  std::to_string(ctx.process_id) +
                                  " PROTO: 2\n"
                                  "PID: " +
                                  std::to_string(ctx.process_id) +
                                  " PROTO: 2 ADDRLEN: 16\n"
                                  "100% done\n";
    REQUIRE(output == expected_output);

    // Six of the printf calls in the program should fail and return -1
    // so subtract 6 from the length to get the expected return value.
    REQUIRE(hook_result == output.length() - 6);
}
#endif

TEST_CASE("xdp-reflect-v4-jit", "[xdp_tests]") { _xdp_reflect_packet_test(EBPF_EXECUTION_JIT, AF_INET); }
TEST_CASE("xdp-reflect-v6-jit", "[xdp_tests]") { _xdp_reflect_packet_test(EBPF_EXECUTION_JIT, AF_INET6); }
TEST_CASE("xdp-reflect-v4-interpret", "[xdp_tests]") { _xdp_reflect_packet_test(EBPF_EXECUTION_INTERPRET, AF_INET); }
TEST_CASE("xdp-reflect-v6-interpret", "[xdp_tests]") { _xdp_reflect_packet_test(EBPF_EXECUTION_INTERPRET, AF_INET6); }
TEST_CASE("xdp-encap-reflect-v4-jit", "[xdp_tests]") { _xdp_encap_reflect_packet_test(EBPF_EXECUTION_JIT, AF_INET); }
TEST_CASE("xdp-encap-reflect-v6-jit", "[xdp_tests]") { _xdp_encap_reflect_packet_test(EBPF_EXECUTION_JIT, AF_INET6); }
TEST_CASE("xdp-encap-reflect-v4-interpret", "[xdp_tests]")
{
    _xdp_encap_reflect_packet_test(EBPF_EXECUTION_INTERPRET, AF_INET);
}
TEST_CASE("xdp-encap-reflect-v6-interpret", "[xdp_tests]")
{
    _xdp_encap_reflect_packet_test(EBPF_EXECUTION_INTERPRET, AF_INET6);
}

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED) || !defined(CONFIG_BPF_JIT_DISABLED)
static void
_xdp_decapsulate_permit_packet_test(ebpf_execution_type_t execution_type, ADDRESS_FAMILY address_family)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);
    uint32_t ifindex = 0;
    program_load_attach_helper_t program_helper(
        SAMPLE_PATH "decap_permit_packet.o",
        BPF_PROG_TYPE_XDP,
        "decapsulate_permit_packet",
        execution_type,
        &ifindex,
        sizeof(ifindex),
        hook);

    // Dummy IP in IP packet with fake IP and MAC addresses.
    ip_in_ip_packet_t packet(address_family);

    size_t offset = sizeof(ebpf::ETHERNET_HEADER);
    offset += (address_family == AF_INET) ? sizeof(ebpf::IPV4_HEADER) : sizeof(ebpf::IPV6_HEADER);
    uint8_t* inner_ip_header = packet.packet().data() + offset;
    std::vector<uint8_t> inner_ip_datagram(inner_ip_header, packet.packet().data() + packet.packet().size());

    uint32_t hook_result;
    xdp_md_helper_t ctx(packet.packet());
    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == XDP_PASS);

    ebpf::ETHERNET_HEADER* ethernet_header = reinterpret_cast<ebpf::ETHERNET_HEADER*>(ctx.data);

    if (address_family == AF_INET) {
        ebpf::IPV4_HEADER* ipv4_header = reinterpret_cast<ebpf::IPV4_HEADER*>(ethernet_header + 1);
        REQUIRE(memcmp(ipv4_header, inner_ip_datagram.data(), inner_ip_datagram.size()) == 0);
    } else {
        ebpf::IPV6_HEADER* ipv6 = reinterpret_cast<ebpf::IPV6_HEADER*>(ethernet_header + 1);
        REQUIRE(memcmp(ipv6, inner_ip_datagram.data(), inner_ip_datagram.size()) == 0);
    }
}
#endif

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("xdp-decapsulate-permit-v4-jit", "[xdp_tests]")
{
    _xdp_decapsulate_permit_packet_test(EBPF_EXECUTION_JIT, AF_INET);
}
TEST_CASE("xdp-decapsulate-permit-v6-jit", "[xdp_tests]")
{
    _xdp_decapsulate_permit_packet_test(EBPF_EXECUTION_JIT, AF_INET6);
}
#endif
#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
TEST_CASE("xdp-decapsulate-permit-v4-interpret", "[xdp_tests]")
{
    _xdp_decapsulate_permit_packet_test(EBPF_EXECUTION_INTERPRET, AF_INET);
}
TEST_CASE("xdp-decapsulate-permit-v6-interpret", "[xdp_tests]")
{
    _xdp_decapsulate_permit_packet_test(EBPF_EXECUTION_INTERPRET, AF_INET6);
}

TEST_CASE("link_tests", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);
    uint32_t ifindex = 0;
    program_load_attach_helper_t program_helper(
        SAMPLE_PATH "bpf.o", BPF_PROG_TYPE_XDP, "func", EBPF_EXECUTION_INTERPRET, &ifindex, sizeof(ifindex), hook);

    // Dummy UDP datagram with fake IP and MAC addresses.
    udp_packet_t packet(AF_INET);
    packet.set_destination_port(ntohs(REFLECTION_TEST_PORT));

    // Dummy context (not used by the eBPF program).
    xdp_md_helper_t ctx(packet.packet());
    uint32_t result;

    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);
    bpf_program* program = bpf_object__find_program_by_name(program_helper.get_object(), "func");
    REQUIRE(program != nullptr);

    // Test the case where the provider only permits a single program to be attached.
    REQUIRE(hook.attach(program) == EBPF_EXTENSION_FAILED_TO_LOAD);

    hook.detach();
}
#endif

static void
_map_reuse_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_reuse_um.dll" : "map_reuse.o");

    // First create and pin the maps manually.
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)inner_map_fd};
    int outer_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, nullptr, sizeof(__u32), sizeof(fd_t), 1, &opts);
    REQUIRE(outer_map_fd > 0);

    // Verify we can insert the inner map into the outer map.
    __u32 outer_key = 0;
    int error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    // Pin the outer map.
    error = bpf_obj_pin(outer_map_fd, "/ebpf/global/outer_map");
    REQUIRE(error == 0);

    // The outer map name created above should not have a name.
    bpf_map_info info;
    uint32_t info_size = sizeof(info);
    REQUIRE(bpf_obj_get_info_by_fd(outer_map_fd, &info, &info_size) == 0);
    REQUIRE(info.name[0] == 0);

    int port_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(port_map_fd > 0);

    // Pin port map.
    error = bpf_obj_pin(port_map_fd, "/ebpf/global/port_map");
    REQUIRE(error == 0);

    // Add an entry in the inner map.
    __u32 key = 0;
    __u32 value = 200;
    error = bpf_map_update_elem(inner_map_fd, &key, &value, BPF_ANY);
    REQUIRE(error == 0);

    uint32_t ifindex = 0;
    program_load_attach_helper_t program_helper(
        file_name, BPF_PROG_TYPE_XDP, "lookup_update", EBPF_EXECUTION_ANY, &ifindex, sizeof(ifindex), hook);

    // The outer map we created earlier should still not have a name even though there is a name in the file,
    // since the unnamed map was reused.
    REQUIRE(bpf_obj_get_info_by_fd(outer_map_fd, &info, &info_size) == 0);
    REQUIRE(info.name[0] == 0);

    auto packet = prepare_udp_packet(10, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size(), 0, TEST_IFINDEX};
    uint32_t hook_result;

    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 200);

    key = 0;
    __u32 port_map_value;
    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &port_map_value) == EBPF_SUCCESS);
    REQUIRE(port_map_value == 200);

    REQUIRE(_get_total_map_count() == 4);

    Platform::_close(outer_map_fd);
    Platform::_close(inner_map_fd);
    Platform::_close(port_map_fd);

    REQUIRE(ebpf_object_unpin("/ebpf/global/outer_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/port_map") == EBPF_SUCCESS);
}

DECLARE_JIT_TEST_CASES("map_reuse", "[end_to_end]", _map_reuse_test);

// Try to reuse a map of the wrong type.
static void
_wrong_map_reuse_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_reuse_um.dll" : "map_reuse.o");

    // First create and pin the maps manually.
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)inner_map_fd};
    int outer_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, nullptr, sizeof(__u32), sizeof(fd_t), 1, &opts);
    REQUIRE(outer_map_fd > 0);

    // Pin the outer map and port map to the wrong paths so they won't match what is in the ebpf program.
    REQUIRE(bpf_obj_pin(outer_map_fd, "/ebpf/global/port_map") == 0);

    int port_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(port_map_fd > 0);

    // Pin port map.
    REQUIRE(bpf_obj_pin(port_map_fd, "/ebpf/global/outer_map") == 0);

    // Open eBPF program file.
    bpf_object_ptr object;
    {
        bpf_object* local_object = bpf_object__open(file_name);
        REQUIRE(local_object != nullptr);
        object.reset(local_object);
    }
    bpf_program* program = bpf_object__next_program(object.get(), nullptr);
    REQUIRE(program != nullptr);

    // Try to load the program.  This should fail because the maps can't be reused.
    REQUIRE(bpf_object__load(object.get()) == -EINVAL);

    Platform::_close(outer_map_fd);
    Platform::_close(inner_map_fd);
    Platform::_close(port_map_fd);

    REQUIRE(ebpf_object_unpin("/ebpf/global/outer_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/port_map") == EBPF_SUCCESS);
}

DECLARE_JIT_TEST_CASES("wrong_map_reuse", "[end_to_end]", _wrong_map_reuse_test);

static void
_auto_pinned_maps_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_reuse_um.dll" : "map_reuse.o");

    uint32_t ifindex = 0;
    program_load_attach_helper_t program_helper(
        file_name, BPF_PROG_TYPE_XDP, "lookup_update", EBPF_EXECUTION_ANY, &ifindex, sizeof(ifindex), hook);

    fd_t outer_map_fd = bpf_obj_get("/ebpf/global/outer_map");
    REQUIRE(outer_map_fd > 0);

    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    __u32 outer_key = 0;
    int error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    // Add an entry in the inner map.
    __u32 key = 0;
    __u32 value = 200;
    error = bpf_map_update_elem(inner_map_fd, &key, &value, BPF_ANY);
    REQUIRE(error == 0);

    fd_t port_map_fd = bpf_obj_get("/ebpf/global/port_map");
    REQUIRE(port_map_fd > 0);

    auto packet = prepare_udp_packet(10, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size(), 0, TEST_IFINDEX};
    uint32_t hook_result;

    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 200);

    key = 0;
    __u32 port_map_value;
    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &port_map_value) == EBPF_SUCCESS);
    REQUIRE(port_map_value == 200);

    Platform::_close(outer_map_fd);
    Platform::_close(inner_map_fd);
    Platform::_close(port_map_fd);

    REQUIRE(ebpf_object_unpin("/ebpf/global/outer_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/port_map") == EBPF_SUCCESS);
}

DECLARE_JIT_TEST_CASES("auto_pinned_maps", "[end_to_end]", _auto_pinned_maps_test);

#if !defined(CONFIG_BPF_JIT_DISABLED)
TEST_CASE("auto_pinned_maps_custom_path", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    struct bpf_object_open_opts opts = {0};
    opts.pin_root_path = "/custompath/global";
    bpf_object_ptr object;
    {
        struct bpf_object* local_object = bpf_object__open_file("map_reuse.o", &opts);
        REQUIRE(local_object != nullptr);
        object.reset(local_object);
    }

    // Load the program.
    REQUIRE(bpf_object__load(object.get()) == 0);

    struct bpf_program* program = bpf_object__find_program_by_name(object.get(), "lookup_update");
    REQUIRE(program != nullptr);

    // Attach should now succeed.
    bpf_link_ptr link;
    {
        struct bpf_link* local_link = bpf_program__attach(program);
        REQUIRE(local_link != nullptr);
        link.reset(local_link);
    }

    fd_t outer_map_fd = bpf_obj_get("/custompath/global/outer_map");
    REQUIRE(outer_map_fd > 0);

    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    __u32 outer_key = 0;
    int error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    // Add an entry in the inner map.
    __u32 key = 0;
    __u32 value = 200;
    error = bpf_map_update_elem(inner_map_fd, &key, &value, BPF_ANY);
    REQUIRE(error == 0);

    fd_t port_map_fd = bpf_obj_get("/custompath/global/port_map");
    REQUIRE(port_map_fd > 0);

    auto packet = prepare_udp_packet(10, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size(), 0, TEST_IFINDEX};
    uint32_t hook_result;

    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 200);

    key = 0;
    __u32 port_map_value;
    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &port_map_value) == EBPF_SUCCESS);
    REQUIRE(port_map_value == 200);

    REQUIRE(_get_total_map_count() == 4);

    Platform::_close(outer_map_fd);
    Platform::_close(inner_map_fd);
    Platform::_close(port_map_fd);

    REQUIRE(ebpf_object_unpin("/custompath/global/outer_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/custompath/global/port_map") == EBPF_SUCCESS);
}
#endif

static void
_map_reuse_invalid_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    // Create and pin a map with a different map type than in ELF file.
    int map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(map_fd > 0);

    // Pin the map.
    int error = bpf_obj_pin(map_fd, "/ebpf/global/outer_map");
    REQUIRE(error == 0);

    int port_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(port_map_fd > 0);

    // Pin port map.
    error = bpf_obj_pin(port_map_fd, "/ebpf/global/port_map");
    REQUIRE(error == 0);

    // Load BPF object from ELF file. Loading the program should fail as the
    // map type for map pinned at "/ebpf/global/outer_map" does not match.
    bpf_object_ptr unique_object;
    fd_t program_fd;
    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_reuse_um.dll" : "map_reuse.o");
    int result =
        ebpf_program_load(file_name, BPF_PROG_TYPE_XDP, EBPF_EXECUTION_ANY, &unique_object, &program_fd, nullptr);

    REQUIRE(result == -EINVAL);

    Platform::_close(map_fd);
    Platform::_close(port_map_fd);

    REQUIRE(ebpf_object_unpin("/ebpf/global/outer_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/port_map") == EBPF_SUCCESS);
}

DECLARE_JIT_TEST_CASES("map_reuse_invalid", "[end_to_end]", _map_reuse_invalid_test);

static void
_map_reuse_2_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_reuse_2_um.dll" : "map_reuse_2.o");

    // First create and pin the maps manually.
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)inner_map_fd};
    int outer_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, nullptr, sizeof(__u32), sizeof(fd_t), 1, &opts);
    REQUIRE(outer_map_fd > 0);

    // Verify we can insert the inner map into the outer map.
    __u32 outer_key = 0;
    int error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    // Pin the outer map.
    error = bpf_obj_pin(outer_map_fd, "/ebpf/global/outer_map");
    REQUIRE(error == 0);

    int port_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(outer_map_fd > 0);

    // Pin port map.
    error = bpf_obj_pin(port_map_fd, "/ebpf/global/port_map");
    REQUIRE(error == 0);

    // Add an entry in the inner map.
    __u32 key = 0;
    __u32 value = 200;
    error = bpf_map_update_elem(inner_map_fd, &key, &value, BPF_ANY);
    REQUIRE(error == 0);

    uint32_t ifindex = 0;
    program_load_attach_helper_t program_helper(
        file_name, BPF_PROG_TYPE_XDP, "lookup_update", EBPF_EXECUTION_ANY, &ifindex, sizeof(ifindex), hook);

    auto packet = prepare_udp_packet(10, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size(), 0, TEST_IFINDEX};
    uint32_t hook_result;

    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 200);

    key = 0;
    __u32 port_map_value;
    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &port_map_value) == EBPF_SUCCESS);
    REQUIRE(port_map_value == 200);

    REQUIRE(_get_total_map_count() == 4);

    Platform::_close(outer_map_fd);
    Platform::_close(inner_map_fd);
    Platform::_close(port_map_fd);

    // The below two objects were pinned by this UM test.
    REQUIRE(ebpf_object_unpin("/ebpf/global/outer_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/port_map") == EBPF_SUCCESS);

    // This object was auto-pinned while loading the program.
    REQUIRE(ebpf_object_unpin("/ebpf/global/inner_map") == EBPF_SUCCESS);
}

DECLARE_JIT_TEST_CASES("map_reuse_2", "[end_to_end]", _map_reuse_2_test);

static void
_map_reuse_3_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    // First create and pin the maps manually.
    int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(inner_map_fd > 0);

    bpf_map_create_opts opts = {.inner_map_fd = (uint32_t)inner_map_fd};
    int outer_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH_OF_MAPS, nullptr, sizeof(__u32), sizeof(fd_t), 1, &opts);
    REQUIRE(outer_map_fd > 0);

    // Verify we can insert the inner map into the outer map.
    __u32 outer_key = 0;
    int error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    // Pin the outer map.
    error = bpf_obj_pin(outer_map_fd, "/ebpf/global/outer_map");
    REQUIRE(error == 0);

    // Pin the inner map.
    error = bpf_obj_pin(inner_map_fd, "/ebpf/global/inner_map");
    REQUIRE(error == 0);

    int port_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(__u32), sizeof(__u32), 1, nullptr);
    REQUIRE(outer_map_fd > 0);

    // Pin port map.
    error = bpf_obj_pin(port_map_fd, "/ebpf/global/port_map");
    REQUIRE(error == 0);

    // Add an entry in the inner map.
    __u32 key = 0;
    __u32 value = 200;
    error = bpf_map_update_elem(inner_map_fd, &key, &value, BPF_ANY);
    REQUIRE(error == 0);

    const char* file_name = (execution_type == EBPF_EXECUTION_NATIVE ? "map_reuse_2_um.dll" : "map_reuse_2.o");

    uint32_t ifindex = 0;
    program_load_attach_helper_t program_helper(
        file_name, BPF_PROG_TYPE_XDP, "lookup_update", EBPF_EXECUTION_ANY, &ifindex, sizeof(ifindex), hook);

    auto packet = prepare_udp_packet(10, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size(), 0, TEST_IFINDEX};
    uint32_t hook_result;

    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 200);

    key = 0;
    __u32 port_map_value;
    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &port_map_value) == EBPF_SUCCESS);
    REQUIRE(port_map_value == 200);

    REQUIRE(_get_total_map_count() == 3);

    Platform::_close(outer_map_fd);
    Platform::_close(inner_map_fd);
    Platform::_close(port_map_fd);

    REQUIRE(ebpf_object_unpin("/ebpf/global/outer_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/inner_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/port_map") == EBPF_SUCCESS);
}

DECLARE_JIT_TEST_CASES("map_reuse_3", "[end_to_end]", _map_reuse_3_test);

static void
_create_service_helper(
    _In_z_ const wchar_t* file_name,
    _In_z_ const wchar_t* service_name,
    _In_ const GUID* provider_module_id,
    _Out_ SC_HANDLE* service_handle)
{
    std::wstring parameters_path(PARAMETERS_PATH_PREFIX);

    REQUIRE(Platform::_create_service(service_name, file_name, service_handle) == ERROR_SUCCESS);

    parameters_path = parameters_path + service_name + L"\\" + SERVICE_PARAMETERS;
    REQUIRE(Platform::_create_registry_key(HKEY_LOCAL_MACHINE, parameters_path.c_str()) == ERROR_SUCCESS);

    REQUIRE(
        Platform::_update_registry_value(
            HKEY_LOCAL_MACHINE, parameters_path.c_str(), REG_BINARY, NPI_MODULE_ID, provider_module_id, sizeof(GUID)) ==
        ERROR_SUCCESS);
}

// Load a native module with non-existing driver.
TEST_CASE("load_native_program_negative", "[end-to-end]")
{
    _test_helper_end_to_end test_helper;

    GUID provider_module_id;
    SC_HANDLE service_handle = nullptr;
    std::wstring service_path(SERVICE_PATH_PREFIX);
    ebpf_handle_t module_handle = ebpf_handle_invalid;
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;
    set_native_module_failures(true);

    REQUIRE(UuidCreate(&provider_module_id) == RPC_S_OK);

    // Creating valid service with non-existing driver.
    _create_service_helper(L"fake_program.dll", NATIVE_DRIVER_SERVICE_NAME, &provider_module_id, &service_handle);

    // Load native module. It should fail.
    service_path = service_path + NATIVE_DRIVER_SERVICE_NAME;
    REQUIRE(
        test_ioctl_load_native_module(
            service_path, &provider_module_id, &module_handle, &count_of_maps, &count_of_programs) ==
        ERROR_PATH_NOT_FOUND);
}

// Load native module by passing invalid service name to EC.
TEST_CASE("load_native_program_negative2", "[end-to-end]")
{
    _test_helper_end_to_end test_helper;

    GUID provider_module_id;
    SC_HANDLE service_handle = nullptr;
    std::wstring service_path(L"");
    ebpf_handle_t module_handle = ebpf_handle_invalid;
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;
    set_native_module_failures(true);

    REQUIRE(UuidCreate(&provider_module_id) == RPC_S_OK);

    _create_service_helper(L"droppacket_um.dll", NATIVE_DRIVER_SERVICE_NAME, &provider_module_id, &service_handle);

    // Create invalid service path and pass to EC.
    service_path += NATIVE_DRIVER_SERVICE_NAME_2;

    // Load native module. It should fail.
    REQUIRE(
        test_ioctl_load_native_module(
            service_path, &provider_module_id, &module_handle, &count_of_maps, &count_of_programs) ==
        ERROR_PATH_NOT_FOUND);
}

// Load native module and then try to reload the same module.
TEST_CASE("load_native_program_negative3", "[end-to-end]")
{
#define MAP_COUNT 2
#define PROGRAM_COUNT 1
    _test_helper_end_to_end test_helper;

    GUID provider_module_id = GUID_NULL;
    std::wstring service_path(SERVICE_PATH_PREFIX);
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;
    int error;
    const char* error_message = nullptr;
    bpf_object_ptr unique_object;
    fd_t program_fd;
    std::wstring file_path(L"droppacket_um.dll");
    const wchar_t* service_name = nullptr;
    ebpf_handle_t module_handle = ebpf_handle_invalid;
    ebpf_handle_t map_handles[MAP_COUNT];
    ebpf_handle_t program_handles[PROGRAM_COUNT];

    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    // Load a valid native module.
    error = ebpf_program_load(
        "droppacket_um.dll", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_NATIVE, &unique_object, &program_fd, &error_message);
    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free((void*)error_message);
    }
    REQUIRE(error == 0);

    // Get the service name that was created.
    REQUIRE(get_service_details_for_file(file_path, &service_name, &provider_module_id) == EBPF_SUCCESS);

    set_native_module_failures(true);

    // Try to reload the same native module. It should fail.
    service_path = service_path + service_name;
    REQUIRE(
        test_ioctl_load_native_module(
            service_path, &provider_module_id, &module_handle, &count_of_maps, &count_of_programs) ==
        ERROR_OBJECT_ALREADY_EXISTS);

    // Try to load the programs from the same module again. It should fail.
    REQUIRE(
        test_ioctl_load_native_programs(
            &provider_module_id, nullptr, MAP_COUNT, map_handles, PROGRAM_COUNT, program_handles) ==
        ERROR_OBJECT_ALREADY_EXISTS);

    bpf_object__close(unique_object.release());

    // Now that we have closed the object, try to load programs from the same module again. This should
    // fail as the module should now be marked as "unloading".
    REQUIRE(
        test_ioctl_load_native_programs(
            &provider_module_id, nullptr, MAP_COUNT, map_handles, PROGRAM_COUNT, program_handles) != ERROR_SUCCESS);
}

// Load native module and then try to load programs with incorrect params.
TEST_CASE("load_native_program_negative4", "[end-to-end]")
{
#define INCORRECT_MAP_COUNT 1
#define PROGRAM_COUNT 1
    _test_helper_end_to_end test_helper;

    GUID provider_module_id = GUID_NULL;
    SC_HANDLE service_handle = nullptr;
    std::wstring service_path(SERVICE_PATH_PREFIX);
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;
    std::wstring file_path(L"droppacket_um.dll");
    _test_handle_helper module_handle;
    ebpf_handle_t map_handles[INCORRECT_MAP_COUNT];
    ebpf_handle_t program_handles[PROGRAM_COUNT];

    REQUIRE(UuidCreate(&provider_module_id) == RPC_S_OK);

    // First try to load native program without loading the native module.
    REQUIRE(
        test_ioctl_load_native_programs(
            &provider_module_id, nullptr, INCORRECT_MAP_COUNT, map_handles, PROGRAM_COUNT, program_handles) ==
        ERROR_PATH_NOT_FOUND);

    // Creating valid service with valid driver.
    _create_service_helper(L"droppacket_um.dll", NATIVE_DRIVER_SERVICE_NAME, &provider_module_id, &service_handle);

    // Load native module. It should succeed.
    service_path = service_path + NATIVE_DRIVER_SERVICE_NAME;
    REQUIRE(
        test_ioctl_load_native_module(
            service_path,
            &provider_module_id,
            module_handle.get_handle_pointer(),
            &count_of_maps,
            &count_of_programs) == ERROR_SUCCESS);

    // Try to load the programs by passing wrong map and program handles size. This should fail.
    REQUIRE(
        test_ioctl_load_native_programs(
            &provider_module_id, nullptr, INCORRECT_MAP_COUNT, map_handles, PROGRAM_COUNT, program_handles) ==
        ERROR_INVALID_PARAMETER);

    // Delete the created service.
    Platform::_delete_service(service_handle);
}

// Try to load a .sys in user mode.
TEST_CASE("load_native_program_negative5", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    int result;
    const char* error_message = nullptr;
    bpf_object_ptr unique_object;
    fd_t program_fd;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    set_native_module_failures(true);
    result = ebpf_program_load(
        "map.sys", BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_ANY, &unique_object, &program_fd, &error_message);
    REQUIRE(result == -ENOENT);
}

// Load native module twice.
TEST_CASE("load_native_program_negative6", "[end-to-end]")
{
    _test_helper_end_to_end test_helper;

    GUID provider_module_id;
    SC_HANDLE service_handle = nullptr;
    SC_HANDLE service_handle2 = nullptr;
    std::wstring service_path(SERVICE_PATH_PREFIX);
    std::wstring service_path2(SERVICE_PATH_PREFIX);
    _test_handle_helper module_handle;
    _test_handle_helper module_handle2;
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;
    set_native_module_failures(true);

    REQUIRE(UuidCreate(&provider_module_id) == RPC_S_OK);

    // Create a valid service with valid driver.
    _create_service_helper(L"droppacket_um.dll", NATIVE_DRIVER_SERVICE_NAME, &provider_module_id, &service_handle);

    // Load native module. It should succeed.
    service_path = service_path + NATIVE_DRIVER_SERVICE_NAME;
    REQUIRE(
        test_ioctl_load_native_module(
            service_path,
            &provider_module_id,
            module_handle.get_handle_pointer(),
            &count_of_maps,
            &count_of_programs) == ERROR_SUCCESS);

    // Create a new service with same driver and same module id.
    _create_service_helper(L"droppacket_um.dll", NATIVE_DRIVER_SERVICE_NAME_2, &provider_module_id, &service_handle2);

    set_native_module_failures(true);

    // Load native module. It should fail.
    service_path2 = service_path2 + NATIVE_DRIVER_SERVICE_NAME_2;
    REQUIRE(
        test_ioctl_load_native_module(
            service_path2,
            &provider_module_id,
            module_handle2.get_handle_pointer(),
            &count_of_maps,
            &count_of_programs) == ERROR_OBJECT_ALREADY_EXISTS);
}

// The below tests try to load native drivers for invalid programs (that will fail verification).
// Since verification can be skipped in bpf2c for only Debug builds, these tests are applicable
// only for Debug build.
#ifdef _DEBUG

// Load programs from a native module which has 0 programs.
TEST_CASE("load_native_program_negative8", "[end-to-end]")
{
    _test_helper_end_to_end test_helper;

    GUID provider_module_id = GUID_NULL;
    SC_HANDLE service_handle = nullptr;
    std::wstring service_path(SERVICE_PATH_PREFIX);
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;
    std::wstring file_path(L"droppacket_um.dll");
    ebpf_handle_t map_handles;
    ebpf_handle_t program_handles;
    _test_handle_helper module_handle;

    REQUIRE(UuidCreate(&provider_module_id) == RPC_S_OK);

    // Creating valid service with valid driver.
    _create_service_helper(L"empty_um.dll", NATIVE_DRIVER_SERVICE_NAME, &provider_module_id, &service_handle);

    // Load native module. It should succeed.
    service_path = service_path + NATIVE_DRIVER_SERVICE_NAME;
    REQUIRE(
        test_ioctl_load_native_module(
            service_path,
            &provider_module_id,
            module_handle.get_handle_pointer(),
            &count_of_maps,
            &count_of_programs) == ERROR_SUCCESS);

    // Try to load the programs from the module with 0 programs.
    REQUIRE(
        test_ioctl_load_native_programs(&provider_module_id, nullptr, 1, &map_handles, 1, &program_handles) ==
        ERROR_INVALID_PARAMETER);

    // Delete the created service.
    Platform::_delete_service(service_handle);
}

static void
_load_invalid_program(_In_z_ const char* file_name, ebpf_execution_type_t execution_type, int expected_result)
{
    _test_helper_end_to_end test_helper;

    int result;
    bpf_object_ptr unique_object;
    fd_t program_fd;

    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);

    result = ebpf_program_load(file_name, BPF_PROG_TYPE_UNSPEC, execution_type, &unique_object, &program_fd, nullptr);
    REQUIRE(result == expected_result);
}

TEST_CASE("load_native_program_invalid1", "[end-to-end]")
{
    _load_invalid_program("invalid_maps1_um.dll", EBPF_EXECUTION_NATIVE, -EINVAL);
}
TEST_CASE("load_native_program_invalid2", "[end-to-end]")
{
    _load_invalid_program("invalid_maps2_um.dll", EBPF_EXECUTION_NATIVE, -EINVAL);
}
TEST_CASE("load_native_program_invalid3", "[end-to-end]")
{
    _load_invalid_program("invalid_helpers_um.dll", EBPF_EXECUTION_NATIVE, -EINVAL);
}
TEST_CASE("load_native_program_invalid4", "[end-to-end]")
{
    _load_invalid_program("empty_um.dll", EBPF_EXECUTION_NATIVE, -EINVAL);
}
TEST_CASE("load_native_program_invalid5", "[end-to-end]")
{
    _load_invalid_program("invalid_maps3_um.dll", EBPF_EXECUTION_NATIVE, -EINVAL);
}

typedef struct _ebpf_scoped_non_preemptible
{
    _ebpf_scoped_non_preemptible()
    {
        ebpf_assert_success(
            ebpf_set_current_thread_affinity((uintptr_t)1 << ebpf_get_current_cpu(), &old_thread_affinity));
        KeRaiseIrql(DISPATCH_LEVEL, &old_irql);
    }
    ~_ebpf_scoped_non_preemptible()
    {
        KeLowerIrql(old_irql);
        ebpf_restore_current_thread_affinity(old_thread_affinity);
    }
    uintptr_t old_thread_affinity = 0;
    KIRQL old_irql = PASSIVE_LEVEL;
} ebpf_scoped_non_preemptible_t;

TEST_CASE("load_native_program_invalid5-non-preemptible", "[end-to-end]")
{
    // Raising virtual IRQL to dispatch will ensure ebpf_native_load queues
    // a workitem and that code path is executed.
    ebpf_scoped_non_preemptible_t non_preemptible;
    _load_invalid_program("invalid_maps3_um.dll", EBPF_EXECUTION_NATIVE, -EINVAL);
}
#endif

// Load native module and then use module handle for a different purpose.
TEST_CASE("native_module_handle_test_negative", "[end-to-end]")
{
    _test_helper_end_to_end test_helper;

    GUID provider_module_id;
    SC_HANDLE service_handle = nullptr;
    std::wstring service_path(SERVICE_PATH_PREFIX);
    ebpf_handle_t module_handle = ebpf_handle_invalid;
    size_t count_of_maps = 0;
    size_t count_of_programs = 0;
    set_native_module_failures(true);

    REQUIRE(UuidCreate(&provider_module_id) == RPC_S_OK);

    // Create a valid service with valid driver.
    _create_service_helper(L"droppacket_um.dll", NATIVE_DRIVER_SERVICE_NAME, &provider_module_id, &service_handle);

    // Load native module. It should succeed.
    service_path = service_path + NATIVE_DRIVER_SERVICE_NAME;
    REQUIRE(
        test_ioctl_load_native_module(
            service_path, &provider_module_id, &module_handle, &count_of_maps, &count_of_programs) == ERROR_SUCCESS);

    // Create an fd for the module handle.
    fd_t module_fd = Platform::_open_osfhandle(module_handle, 0);
    REQUIRE(module_fd != ebpf_fd_invalid);

    // Try to use the native module fd as a program or map fd.
    bpf_prog_info program_info = {};
    uint32_t program_info_size = sizeof(program_info);
    REQUIRE(bpf_obj_get_info_by_fd(module_fd, &program_info, &program_info_size) == -EINVAL);

    Platform::_close(module_fd);
}

TEST_CASE("ebpf_get_program_type_by_name invalid name", "[end-to-end]")
{
    _test_helper_end_to_end test_helper;
    ebpf_program_type_t program_type;
    ebpf_attach_type_t attach_type;

    REQUIRE(ebpf_get_program_type_by_name("invalid_name", &program_type, &attach_type) == EBPF_KEY_NOT_FOUND);

    // Now set verification in progress and try again.
    set_verification_in_progress(true);
    REQUIRE(ebpf_get_program_type_by_name("invalid_name", &program_type, &attach_type) == EBPF_KEY_NOT_FOUND);
}

TEST_CASE("ebpf_get_program_type_name invalid types", "[end-to-end]")
{
    _test_helper_end_to_end test_helper;
    ebpf_program_type_t program_type = EBPF_PROGRAM_TYPE_UNSPECIFIED;

    // First try with EBPF_PROGRAM_TYPE_UNSPECIFIED.
    const char* name1 = ebpf_get_program_type_name(&program_type);
    REQUIRE(name1 == nullptr);

    // Try with a random program type GUID.
    REQUIRE(UuidCreate(&program_type) == RPC_S_OK);
    const char* name2 = ebpf_get_program_type_name(&program_type);
    REQUIRE(name2 == nullptr);
}

TEST_CASE("get_ebpf_attach_type", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    // First test a valid input.
    const ebpf_attach_type_t* attach_type = get_ebpf_attach_type(BPF_ATTACH_TYPE_BIND);
    REQUIRE(attach_type != nullptr);

    REQUIRE(IsEqualGUID(*attach_type, EBPF_ATTACH_TYPE_BIND) != 0);

    // Try with BPF_ATTACH_TYPE_UNSPEC.
    REQUIRE(get_ebpf_attach_type(BPF_ATTACH_TYPE_UNSPEC) == nullptr);

    // Try with invalid bpf attach type.
    REQUIRE(get_ebpf_attach_type((bpf_attach_type_t)BPF_ATTACH_TYPE_INVALID) == nullptr);
}

TEST_CASE("get_bpf_program_type", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    // First test a valid input.
    REQUIRE(get_bpf_program_type(&EBPF_PROGRAM_TYPE_SAMPLE) == BPF_PROG_TYPE_SAMPLE);

    // Try with EBPF_PROGRAM_TYPE_UNSPECIFIED.
    REQUIRE(get_bpf_program_type(&EBPF_PROGRAM_TYPE_UNSPECIFIED) == BPF_PROG_TYPE_UNSPEC);

    // Try with invalid program type.
    GUID invalid_program_type;
    REQUIRE(UuidCreate(&invalid_program_type) == RPC_S_OK);
    REQUIRE(get_bpf_program_type(&invalid_program_type) == BPF_PROG_TYPE_UNSPEC);
}

TEST_CASE("ebpf_get_ebpf_program_type", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    // Try with BPF_PROG_TYPE_UNSPEC.
    const ebpf_program_type_t* program_type = ebpf_get_ebpf_program_type(BPF_PROG_TYPE_UNSPEC);
    REQUIRE(program_type != nullptr);
    REQUIRE(IsEqualGUID(EBPF_PROGRAM_TYPE_UNSPECIFIED, *program_type) != 0);

    // Try a valid bpf prog type.
    program_type = ebpf_get_ebpf_program_type(BPF_PROG_TYPE_XDP);
    REQUIRE(program_type != nullptr);
    REQUIRE(IsEqualGUID(EBPF_PROGRAM_TYPE_XDP, *program_type) != 0);

    // Try an invalid bpf prog type.
    program_type = ebpf_get_ebpf_program_type((bpf_prog_type_t)BPF_PROG_TYPE_INVALID);
    REQUIRE(program_type == nullptr);
}

TEST_CASE("get_bpf_attach_type", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    // Try with EBPF_ATTACH_TYPE_XDP.
    REQUIRE(get_bpf_attach_type(&EBPF_ATTACH_TYPE_XDP) == BPF_XDP);

    // Try with EBPF_ATTACH_TYPE_UNSPECIFIED.
    REQUIRE(get_bpf_attach_type(&EBPF_ATTACH_TYPE_UNSPECIFIED) == BPF_ATTACH_TYPE_UNSPEC);

    // Try with invalid attach type.
    GUID invalid_attach_type;
    REQUIRE(UuidCreate(&invalid_attach_type) == RPC_S_OK);
    REQUIRE(get_bpf_attach_type(&invalid_attach_type) == BPF_ATTACH_TYPE_UNSPEC);
}

TEST_CASE("test_ebpf_object_set_execution_type", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    // First open a .dll file
    bpf_object* native_object = bpf_object__open("droppacket_um.dll");
    REQUIRE(native_object != nullptr);

    // Try to set incorrect execution type.
    REQUIRE(ebpf_object_set_execution_type(native_object, EBPF_EXECUTION_JIT) == EBPF_INVALID_ARGUMENT);
    REQUIRE(ebpf_object_set_execution_type(native_object, EBPF_EXECUTION_INTERPRET) == EBPF_INVALID_ARGUMENT);

    // The following should succeed.
    REQUIRE(ebpf_object_set_execution_type(native_object, EBPF_EXECUTION_ANY) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_get_execution_type(native_object) == EBPF_EXECUTION_NATIVE);
    REQUIRE(ebpf_object_set_execution_type(native_object, EBPF_EXECUTION_NATIVE) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_get_execution_type(native_object) == EBPF_EXECUTION_NATIVE);

    bpf_object__close(native_object);

    // Open a .o file
    bpf_object* jit_object = bpf_object__open("droppacket.o");
    REQUIRE(jit_object != nullptr);

    // Try to set incorrect execution type.
    REQUIRE(ebpf_object_set_execution_type(jit_object, EBPF_EXECUTION_NATIVE) == EBPF_INVALID_ARGUMENT);

    // The following should succeed.
    REQUIRE(ebpf_object_set_execution_type(jit_object, EBPF_EXECUTION_ANY) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_get_execution_type(jit_object) == EBPF_EXECUTION_JIT);
    REQUIRE(ebpf_object_set_execution_type(jit_object, EBPF_EXECUTION_JIT) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_get_execution_type(jit_object) == EBPF_EXECUTION_JIT);
    REQUIRE(ebpf_object_set_execution_type(jit_object, EBPF_EXECUTION_INTERPRET) == EBPF_SUCCESS);
    REQUIRE(ebpf_object_get_execution_type(jit_object) == EBPF_EXECUTION_INTERPRET);

    bpf_object__close(jit_object);
}

static void
extension_reload_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    // Create a 0-byte UDP packet.
    auto packet0 = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);

    // Test that we drop the packet and increment the map.
    xdp_md_t ctx0{packet0.data(), packet0.data() + packet0.size(), 0, TEST_IFINDEX};

    // Try loading without the extension loaded.
    bpf_object_ptr unique_droppacket_object;
    int program_fd = -1;
    const char* error_message = nullptr;

    // Should fail.
    REQUIRE(
        ebpf_program_load(
            execution_type == EBPF_EXECUTION_NATIVE ? "droppacket_um.dll" : "droppacket.o",
            BPF_PROG_TYPE_UNSPEC,
            execution_type,
            &unique_droppacket_object,
            &program_fd,
            &error_message) != 0);

    ebpf_free((void*)error_message);

    // Load the program with the extension loaded.
    {
        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
        program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

        REQUIRE(
            ebpf_program_load(
                execution_type == EBPF_EXECUTION_NATIVE ? "droppacket_um.dll" : "droppacket.o",
                BPF_PROG_TYPE_UNSPEC,
                execution_type,
                &unique_droppacket_object,
                &program_fd,
                &error_message) == 0);

        uint32_t if_index = TEST_IFINDEX;
        bpf_link* link = nullptr;
        // Attach only to the single interface being tested.
        REQUIRE(hook.attach_link(program_fd, &if_index, sizeof(if_index), &link) == EBPF_SUCCESS);
        bpf_link__disconnect(link);
        bpf_link__destroy(link);

        // Program should run.
        uint32_t hook_result = MAXUINT32;
        REQUIRE(hook.fire(&ctx0, &hook_result) == EBPF_SUCCESS);
        REQUIRE(hook_result == XDP_PASS);

        // Unload the extension (xdp_program_info and hook will be destroyed).
    }

    // Reload the extension provider with unchanged data.
    {
        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
        program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

        // Program should re-attach to the hook.

        // Program should run.
        uint32_t hook_result = MAXUINT32;
        REQUIRE(hook.fire(&ctx0, &hook_result) == EBPF_SUCCESS);
        REQUIRE(hook_result == XDP_PASS);
    }

    // Reload the extension provider with missing helper function.
    {
        ebpf_helper_function_addresses_t changed_helper_function_address_table =
            _test_ebpf_xdp_helper_function_address_table;
        ebpf_program_data_t changed_program_data = _ebpf_xdp_program_data;
        changed_program_data.program_type_specific_helper_function_addresses = &changed_helper_function_address_table;
        changed_helper_function_address_table.helper_function_count = 0;

        ebpf_extension_data_t changed_provider_data = {
            TEST_NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(changed_program_data), &changed_program_data};

        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
        program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP, &changed_provider_data);

        // Program should re-attach to the hook.

        // Program should not run.
        uint32_t hook_result = MAXUINT32;
        REQUIRE(hook.fire(&ctx0, &hook_result) != EBPF_SUCCESS);
        REQUIRE(hook_result != XDP_PASS);
    }

    // Reload the extension provider with changed helper function data.
    {
        ebpf_program_info_t changed_program_info = _ebpf_xdp_program_info;
        ebpf_helper_function_prototype_t helper_function_prototypes[] = {
            _xdp_ebpf_extension_helper_function_prototype[0]};
        helper_function_prototypes[0].return_type = EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL;
        changed_program_info.program_type_specific_helper_prototype = helper_function_prototypes;
        ebpf_program_data_t changed_program_data = _ebpf_xdp_program_data;
        changed_program_data.program_info = &changed_program_info;

        ebpf_extension_data_t changed_provider_data = {
            TEST_NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(changed_program_data), &changed_program_data};

        single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
        program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP, &changed_provider_data);

        // Program should re-attach to the hook.

        // Program should not run.
        uint32_t hook_result = MAXUINT32;
        REQUIRE(hook.fire(&ctx0, &hook_result) != EBPF_SUCCESS);
        REQUIRE(hook_result != XDP_PASS);
    }
}

DECLARE_ALL_TEST_CASES("extension_reload_test", "[end_to_end]", extension_reload_test);

// This test tests resource reclamation and clean-up after a premature/abnormal user mode application exit.
TEST_CASE("close_unload_test", "[close_cleanup]")
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    int result;
    bpf_object_ptr unique_object;
    bpf_link_ptr link;
    fd_t program_fd;

    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);

    const char* file_name = "bindmonitor_tailcall_um.dll";
    result = ebpf_program_load(
        file_name, BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_NATIVE, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        free((void*)error_message);
    }
    REQUIRE(result == 0);

    // Set up tail calls.
    struct bpf_program* callee0 = bpf_object__find_program_by_name(unique_object.get(), "BindMonitor_Callee0");
    REQUIRE(callee0 != nullptr);
    fd_t callee0_fd = bpf_program__fd(callee0);
    REQUIRE(callee0_fd > 0);

    struct bpf_program* callee1 = bpf_object__find_program_by_name(unique_object.get(), "BindMonitor_Callee1");
    REQUIRE(callee1 != nullptr);
    fd_t callee1_fd = bpf_program__fd(callee1);
    REQUIRE(callee1_fd > 0);

    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "prog_array_map");
    REQUIRE(prog_map_fd > 0);

    uint32_t index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee0_fd, 0) == 0);
    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // These are needed to prevent the memory leak detector from flagging a memory leak.
    hook.detach_and_close_link(&link);

    // The block of commented code after this comment is for documentation purposes only.
    //
    // A well-behaved user mode application _should_ call these calls to correctly free the allocated objects. In case
    // of careless applications that do not do so (or even well behaved applications, when they crash or terminate for
    // some reason before getting to this point), the 'premature application close' event handling _should_ take care
    // of reclaiming and free'ing such objects.
    //
    // In a user-mode unit test case such as this one, the 'premature application close' event is simulated/handled in
    // the context of the bpf_object__close() api, so a call to that api is mandatory for such tests.  All unit tests
    // belonging to the '[close_cleanup]' unit-test class will show this behavior.
    //
    // For an identical test meant for execution on the native (kernel mode ebpf-for-windows driver), this event will
    // be handled by the kernel mode driver on test application termination.  Such a test application _should_ _not_
    // call bpf_object__close() api either.
    //

    /*
       --- DO NOT REMOVE OR UN-COMMENT ---
    //
    // index = 0;
    // REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    //
    // index = 1;
    // REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    */

    bpf_object__close(unique_object.release());
}

// This test tests the case where a program is inserted multiple times with different keys into the same map.
TEST_CASE("multiple_map_insert", "[close_cleanup]")
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    int result;
    bpf_object_ptr unique_object;
    bpf_link_ptr link;
    fd_t program_fd;

    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);

    const char* file_name = "bindmonitor_tailcall_um.dll";
    result = ebpf_program_load(
        file_name, BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_NATIVE, &unique_object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        free((void*)error_message);
    }
    REQUIRE(result == 0);

    // Set up tail calls.
    struct bpf_program* callee0 = bpf_object__find_program_by_name(unique_object.get(), "BindMonitor_Callee0");
    REQUIRE(callee0 != nullptr);
    fd_t callee0_fd = bpf_program__fd(callee0);
    REQUIRE(callee0_fd > 0);

    struct bpf_program* callee1 = bpf_object__find_program_by_name(unique_object.get(), "BindMonitor_Callee1");
    REQUIRE(callee1 != nullptr);
    fd_t callee1_fd = bpf_program__fd(callee1);
    REQUIRE(callee1_fd > 0);

    fd_t prog_map_fd = bpf_object__find_map_fd_by_name(unique_object.get(), "prog_array_map");
    REQUIRE(prog_map_fd > 0);

    uint32_t index = 0;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee0_fd, 0) == 0);

    index = 1;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    // Insert the same program for multiple keys in the same map.
    index = 2;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    index = 4;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    index = 7;
    REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &callee1_fd, 0) == 0);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);
    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // These are needed to prevent the memory leak detector from flagging a memory leak.
    hook.detach_and_close_link(&link);

    /*
       --- DO NOT REMOVE OR UN-COMMENT ---
    // Please refer to the detailed comment in the 'close_unload_test' test for explanation.
    //
    // index = 0;
    // REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    //
    // index = 1;
    // REQUIRE(bpf_map_update_elem(prog_map_fd, &index, &ebpf_fd_invalid, 0) == 0);
    */

    bpf_object__close(unique_object.release());
}
