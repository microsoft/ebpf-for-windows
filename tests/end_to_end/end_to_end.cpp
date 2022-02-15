// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <array>
#include <chrono>
#include <mutex>
#include <thread>
#include <WinSock2.h>
#include <in6addr.h> // Must come after Winsock2.h

#include "bpf2c.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "dll_metadata_table.h"
#include "ebpf_bind_program_data.h"
#include "ebpf_core.h"
#include "ebpf_xdp_program_data.h"
#include "helpers.h"
#include "mock.h"
#include "platform.h"
#include "program_helper.h"
#include "sample_test_common.h"
#include "test_helper.hpp"
#include "tlv.h"
#include "xdp_tests_common.h"

namespace ebpf {
#pragma warning(push)
#pragma warning(disable : 4201) // nonstandard extension used : nameless struct/union
#include "../sample/ebpf.h"
#pragma warning(pop)
}; // namespace ebpf

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
        if (_address_family == AF_INET)
            (ip_addresses == nullptr) ? set_ipv4_addresses(&_test_ipv4_addrs.source, &_test_ipv4_addrs.destination)
                                      : set_ipv4_addresses(
                                            &(reinterpret_cast<const _ipv4_address_pair*>(ip_addresses))->source,
                                            &(reinterpret_cast<const _ipv4_address_pair*>(ip_addresses))->destination);
        else
            (ip_addresses == nullptr) ? set_ipv6_addresses(&_test_ipv6_addrs.source, &_test_ipv6_addrs.destination)
                                      : set_ipv6_addresses(
                                            &(reinterpret_cast<const _ipv6_address_pair*>(ip_addresses))->source,
                                            &(reinterpret_cast<const _ipv6_address_pair*>(ip_addresses))->destination);
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

void
droppacket_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;

    ebpf_result_t result;
    const char* error_message = nullptr;
    bpf_object* object = nullptr;
    fd_t program_fd;
    bpf_link* link;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o", nullptr, nullptr, execution_type, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);
    fd_t dropped_packet_map_fd = bpf_object__find_map_fd_by_name(object, "dropped_packet_map");

    // Tell the program which interface to filter on.
    fd_t interface_index_map_fd = bpf_object__find_map_fd_by_name(object, "interface_index_map");
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

    int hook_result;
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
    hook.detach_link(link);
    if_index = 0;
    REQUIRE(hook.attach_link(program_fd, &if_index, sizeof(if_index), &link) == EBPF_SUCCESS);

    // Fire a 0-length UDP packet on the interface index in the map, which should be dropped.
    REQUIRE(hook.fire(&ctx0, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == XDP_DROP);
    REQUIRE(bpf_map_lookup_elem(dropped_packet_map_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value == 1);

    // Fire a 0-length packet on any interface that is not in the map, which should be allowed.
    xdp_md_t ctx4{packet0.data(), packet0.data() + packet0.size(), 0, if_index + 1};
    REQUIRE(hook.fire(&ctx4, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == XDP_PASS);
    REQUIRE(bpf_map_lookup_elem(dropped_packet_map_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value == 1);

    hook.detach_link(link);
    hook.close_link(link);

    bpf_object__close(object);
}

void
divide_by_zero_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;

    ebpf_result_t result;
    const char* error_message = nullptr;
    bpf_object* object = nullptr;
    fd_t program_fd;
    bpf_link* link;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "divide_by_zero.o", nullptr, nullptr, execution_type, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);

    // Test that we drop the packet and increment the map
    xdp_md_t ctx{packet.data(), packet.data() + packet.size(), 0, TEST_IFINDEX};

    int hook_result;
    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    // uBPF returns -1 when the program hits a divide by zero error.
    REQUIRE(hook_result == -1);

    hook.detach_link(link);
    hook.close_link(link);

    bpf_object__close(object);
}

typedef struct _process_entry
{
    uint32_t count;
    uint8_t name[64];
} process_entry_t;

uint32_t
get_bind_count_for_pid(fd_t map_fd, uint64_t pid)
{
    process_entry_t entry{};
    bpf_map_lookup_elem(map_fd, &pid, &entry);

    return entry.count;
}

bind_action_t
emulate_bind(std::function<ebpf_result_t(void*, int*)>& invoke, uint64_t pid, const char* appid)
{
    int result;
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
emulate_unbind(std::function<ebpf_result_t(void*, int*)>& invoke, uint64_t pid, const char* appid)
{
    int result;
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

void
bindmonitor_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    uint64_t fake_pid = 12345;
    ebpf_result_t result;
    bpf_object* object = nullptr;
    bpf_link* link = nullptr;
    fd_t program_fd;

    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);

    result = ebpf_program_load(
        SAMPLE_PATH "bindmonitor.o", nullptr, nullptr, execution_type, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);
    fd_t limit_map_fd = bpf_object__find_map_fd_by_name(object, "limits_map");
    REQUIRE(limit_map_fd > 0);
    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");
    REQUIRE(process_map_fd > 0);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // Apply policy of maximum 2 binds per process
    set_bind_limit(limit_map_fd, 2);

    std::function<ebpf_result_t(void*, int*)> invoke = [&hook](void* context, int* result) -> ebpf_result_t {
        return hook.fire(context, result);
    };
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

    hook.detach_link(link);
    hook.close_link(link);

    bpf_object__close(object);
}

void
bindmonitor_ring_buffer_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    ebpf_result_t result;
    bpf_object* object = nullptr;
    bpf_link* link = nullptr;
    fd_t program_fd;

    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);

    // Load and attach a bind eBPF program that uses a ring buffer map to notify about bind operations.
    result = ebpf_program_load(
        SAMPLE_PATH "bindmonitor_ringbuf.o", nullptr, nullptr, execution_type, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    fd_t process_map_fd = bpf_object__find_map_fd_by_name(object, "process_map");
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
    std::function<ebpf_result_t(void*, int*)> invoke = [&hook](void* context, int* result) -> ebpf_result_t {
        return hook.fire(context, result);
    };

    ring_buffer_api_test_helper(process_map_fd, fake_app_ids, [&](int i) {
        // Emulate bind operation.
        std::vector<char> fake_app_id = fake_app_ids[i];
        fake_app_id.push_back('\0');
        REQUIRE(emulate_bind(invoke, fake_pid + i, fake_app_id.data()) == BIND_PERMIT);
    });

    hook.detach_link(link);
    hook.close_link(link);

    bpf_object__close(object);
}

static void
_utility_helper_functions_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);
    uint32_t ifindex = 0;
    program_load_attach_helper_t program_helper(
        SAMPLE_PATH "test_utility_helpers.o",
        EBPF_PROGRAM_TYPE_XDP,
        "test_utility_helpers",
        execution_type,
        &ifindex,
        sizeof(ifindex),
        hook);
    bpf_object* object = program_helper.get_object();

    // Dummy context (not used by the eBPF program).
    xdp_md_t ctx{};

    int hook_result;
    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 0);

    verify_utility_helper_results(object);
}

TEST_CASE("droppacket-jit", "[end_to_end]") { droppacket_test(EBPF_EXECUTION_JIT); }
TEST_CASE("divide_by_zero_jit", "[end_to_end]") { divide_by_zero_test(EBPF_EXECUTION_JIT); }
TEST_CASE("bindmonitor-jit", "[end_to_end]") { bindmonitor_test(EBPF_EXECUTION_JIT); }
TEST_CASE("bindmonitor-ringbuf-jit", "[end_to_end]") { bindmonitor_ring_buffer_test(EBPF_EXECUTION_JIT); }
TEST_CASE("droppacket-interpret", "[end_to_end]") { droppacket_test(EBPF_EXECUTION_INTERPRET); }
TEST_CASE("divide_by_zero_interpret", "[end_to_end]") { divide_by_zero_test(EBPF_EXECUTION_INTERPRET); }
TEST_CASE("bindmonitor-interpret", "[end_to_end]") { bindmonitor_test(EBPF_EXECUTION_INTERPRET); }
TEST_CASE("bindmonitor-ringbuf-interpret", "[end_to_end]") { bindmonitor_ring_buffer_test(EBPF_EXECUTION_INTERPRET); }
TEST_CASE("utility-helpers-jit", "[end_to_end]") { _utility_helper_functions_test(EBPF_EXECUTION_JIT); }
TEST_CASE("utility-helpers-interpret", "[end_to_end]") { _utility_helper_functions_test(EBPF_EXECUTION_INTERPRET); }

TEST_CASE("enum section", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    const tlv_type_length_value_t* section_data = nullptr;
    uint32_t result;

    REQUIRE(
        (result =
             ebpf_api_elf_enumerate_sections(SAMPLE_PATH "droppacket.o", nullptr, true, &section_data, &error_message),
         ebpf_free_string(error_message),
         error_message = nullptr,
         result == 0));
    for (auto current_section = tlv_child(section_data); current_section != tlv_next(section_data);
         current_section = tlv_next(current_section)) {
        auto section_name = tlv_child(current_section);
        auto type = tlv_next(section_name);
        auto map_count = tlv_next(type);
        auto program_bytes = tlv_next(map_count);
        auto stats_secton = tlv_next(program_bytes);

        REQUIRE(static_cast<tlv_type_t>(section_name->type) == tlv_type_t::STRING);
        REQUIRE(static_cast<tlv_type_t>(type->type) == tlv_type_t::STRING);
        REQUIRE(static_cast<tlv_type_t>(map_count->type) == tlv_type_t::UINT);
        REQUIRE(static_cast<tlv_type_t>(program_bytes->type) == tlv_type_t::BLOB);
        REQUIRE(static_cast<tlv_type_t>(stats_secton->type) == tlv_type_t::SEQUENCE);

        for (auto current_stat = tlv_child(stats_secton); current_stat != tlv_next(stats_secton);
             current_stat = tlv_next(current_stat)) {
            auto name = tlv_child(current_stat);
            auto value = tlv_next(name);
            REQUIRE(static_cast<tlv_type_t>(name->type) == tlv_type_t::STRING);
            REQUIRE(static_cast<tlv_type_t>(value->type) == tlv_type_t::UINT);
        }
    }
}

TEST_CASE("verify section", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    const char* report = nullptr;
    uint32_t result;
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    ebpf_api_verifier_stats_t stats;
    REQUIRE((
        result = ebpf_api_elf_verify_section(SAMPLE_PATH "droppacket.o", "xdp", false, &report, &error_message, &stats),
        ebpf_free_string(error_message),
        error_message = nullptr,
        result == 0));
    REQUIRE(report != nullptr);
    ebpf_free_string(report);
}

TEST_CASE("verify_test0", "[sample_extension]")
{
    _test_helper_end_to_end test_helper;
    program_info_provider_t sample_extension_program_info(EBPF_PROGRAM_TYPE_SAMPLE);

    const char* error_message = nullptr;
    const char* report = nullptr;
    uint32_t result;

    ebpf_api_verifier_stats_t stats;
    REQUIRE(
        (result = ebpf_api_elf_verify_section(
             SAMPLE_PATH "test_sample_ebpf.o", "sample_ext", false, &report, &error_message, &stats),
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
        (result = ebpf_api_elf_verify_section(
             SAMPLE_PATH "test_sample_ebpf.o", "sample_ext/utility", false, &report, &error_message, &stats),
         ebpf_free_string(error_message),
         error_message = nullptr,
         result == 0));
    REQUIRE(report != nullptr);
    ebpf_free_string(report);

    REQUIRE(result == 0);
}

TEST_CASE("map_pinning_test", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    ebpf_result_t result;
    bpf_object* object = nullptr;
    fd_t program_fd;

    program_info_provider_t bind_program_info(EBPF_PROGRAM_TYPE_BIND);

    result = ebpf_program_load(
        SAMPLE_PATH "bindmonitor.o", nullptr, nullptr, EBPF_EXECUTION_INTERPRET, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);

    std::string process_maps_name = "bindmonitor::process_map";
    std::string limit_maps_name = "bindmonitor::limits_map";

    REQUIRE(bpf_object__find_map_by_name(object, "process_map") != nullptr);
    REQUIRE(bpf_object__find_map_by_name(object, "limits_map") != nullptr);
    REQUIRE(
        bpf_map__pin(bpf_object__find_map_by_name(object, "process_map"), process_maps_name.c_str()) == EBPF_SUCCESS);
    REQUIRE(bpf_map__pin(bpf_object__find_map_by_name(object, "limits_map"), limit_maps_name.c_str()) == EBPF_SUCCESS);

    fd_t fd = bpf_obj_get(process_maps_name.c_str());
    REQUIRE(fd != ebpf_fd_invalid);
    Platform::_close(fd);

    fd = bpf_obj_get(limit_maps_name.c_str());
    REQUIRE(fd != ebpf_fd_invalid);
    Platform::_close(fd);

    REQUIRE(
        bpf_map__unpin(bpf_object__find_map_by_name(object, "process_map"), process_maps_name.c_str()) == EBPF_SUCCESS);
    REQUIRE(
        bpf_map__unpin(bpf_object__find_map_by_name(object, "limits_map"), limit_maps_name.c_str()) == EBPF_SUCCESS);

    REQUIRE(bpf_obj_get(limit_maps_name.c_str()) == ebpf_fd_invalid);

    REQUIRE(bpf_obj_get(process_maps_name.c_str()) == ebpf_fd_invalid);

    bpf_object__close(object);
}

TEST_CASE("enumerate_and_query_programs", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    fd_t program_fd;
    fd_t next_program_fd;
    const char* error_message = nullptr;
    ebpf_result_t result;
    const char* file_name = nullptr;
    const char* section_name = nullptr;
    bpf_object* object[2] = {0};
    fd_t program_fds[2] = {0};

    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o", nullptr, nullptr, EBPF_EXECUTION_JIT, &object[0], &program_fds[0], &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o",
        nullptr,
        nullptr,
        EBPF_EXECUTION_INTERPRET,
        &object[1],
        &program_fds[1],
        &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    ebpf_execution_type_t type;
    program_fd = ebpf_fd_invalid;
    REQUIRE(ebpf_get_next_program(program_fd, &next_program_fd) == EBPF_SUCCESS);
    REQUIRE(next_program_fd != ebpf_fd_invalid);
    program_fd = next_program_fd;
    REQUIRE(ebpf_program_query_info(program_fd, &type, &file_name, &section_name) == EBPF_SUCCESS);
    REQUIRE(type == EBPF_EXECUTION_JIT);
    REQUIRE(strcmp(file_name, SAMPLE_PATH "droppacket.o") == 0);
    ebpf_free_string(file_name);
    file_name = nullptr;
    REQUIRE(strcmp(section_name, "xdp") == 0);
    ebpf_free_string(section_name);
    section_name = nullptr;

    REQUIRE(ebpf_get_next_program(program_fd, &next_program_fd) == EBPF_SUCCESS);
    REQUIRE(next_program_fd != ebpf_fd_invalid);
    Platform::_close(program_fd);
    program_fd = next_program_fd;
    REQUIRE(ebpf_program_query_info(program_fd, &type, &file_name, &section_name) == EBPF_SUCCESS);
    REQUIRE(type == EBPF_EXECUTION_INTERPRET);
    REQUIRE(strcmp(file_name, SAMPLE_PATH "droppacket.o") == 0);
    REQUIRE(strcmp(section_name, "xdp") == 0);
    ebpf_free_string(file_name);
    ebpf_free_string(section_name);
    file_name = nullptr;
    section_name = nullptr;

    REQUIRE(ebpf_get_next_program(program_fd, &next_program_fd) == EBPF_SUCCESS);
    REQUIRE(next_program_fd == ebpf_fd_invalid);
    Platform::_close(program_fd);

    for (int i = 0; i < _countof(object); i++) {
        bpf_object__close(object[i]);
    }
}

TEST_CASE("pinned_map_enum", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    ebpf_test_pinned_map_enum();
}

// This test uses ebpf_link_close() to test implicit detach.
TEST_CASE("implicit_detach", "[end_to_end]")
{
    // This test case does the following:
    // 1. Close program handle. An implicit detach should happen and program
    //    object should be deleted.
    // 2. Close link handle. The link object should be deleted.

    _test_helper_end_to_end test_helper;

    uint32_t result = 0;
    bpf_object* object = nullptr;
    fd_t program_fd;
    const char* error_message = nullptr;
    bpf_link* link = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o", nullptr, nullptr, EBPF_EXECUTION_JIT, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // Call bpf_object__close() which will close the program fd. That should
    // detach the program from the hook and unload the program.
    bpf_object__close(object);

    program_fd = ebpf_fd_invalid;
    REQUIRE(ebpf_get_next_program(program_fd, &program_fd) == EBPF_SUCCESS);
    REQUIRE(program_fd == ebpf_fd_invalid);

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

    uint32_t result = 0;
    bpf_object* object = nullptr;
    fd_t program_fd;
    const char* error_message = nullptr;
    bpf_link* link = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o", nullptr, nullptr, EBPF_EXECUTION_JIT, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // Call bpf_object__close() which will close the program fd. That should
    // detach the program from the hook and unload the program.
    bpf_object__close(object);

    program_fd = ebpf_fd_invalid;
    REQUIRE(ebpf_get_next_program(program_fd, &program_fd) == EBPF_SUCCESS);
    REQUIRE(program_fd == ebpf_fd_invalid);

    // Close link handle (without detaching). This should delete the link
    // object. ebpf_object_tracking_terminate() which is called when the test
    // exits checks if all the objects in the execution context have been deleted.
    bpf_link__disconnect(link);
    REQUIRE(bpf_link__destroy(link) == 0);
}

TEST_CASE("explicit_detach", "[end_to_end]")
{
    // This test case does the following:
    // 1. Call detach API and then close the link handle. The link onject
    //    should be deleted.
    // 2. Close program handle. The program object should be deleted.

    _test_helper_end_to_end test_helper;

    bpf_object* object = nullptr;
    fd_t program_fd;
    bpf_link* link = nullptr;
    ebpf_result_t result;
    const char* error_message = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o", nullptr, nullptr, EBPF_EXECUTION_INTERPRET, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // Detach and close link handle.
    // ebpf_object_tracking_terminate() which is called when the test
    // exits checks if all the objects in EC have been deleted.
    hook.detach_link(link);
    hook.close_link(link);

    // Close program handle.
    bpf_object__close(object);
    program_fd = ebpf_fd_invalid;
    REQUIRE(ebpf_get_next_program(program_fd, &program_fd) == EBPF_SUCCESS);
    REQUIRE(program_fd == ebpf_fd_invalid);
}

TEST_CASE("implicit_explicit_detach", "[end_to_end]")
{
    // This test case does the following:
    // 1. Close the program handle so that an implicit detach happens.
    // 2. Explicitly call detach and then close the link handle. Explicit
    //    detach in this step should be a no-op.

    _test_helper_end_to_end test_helper;

    bpf_object* object = nullptr;
    fd_t program_fd;
    bpf_link* link = nullptr;
    ebpf_result_t result;
    const char* error_message = nullptr;

    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    result = ebpf_program_load(
        SAMPLE_PATH "droppacket.o", nullptr, nullptr, EBPF_EXECUTION_INTERPRET, &object, &program_fd, &error_message);

    if (error_message) {
        printf("ebpf_program_load failed with %s\n", error_message);
        ebpf_free_string(error_message);
        error_message = nullptr;
    }
    REQUIRE(result == EBPF_SUCCESS);

    uint32_t ifindex = 0;
    REQUIRE(hook.attach_link(program_fd, &ifindex, sizeof(ifindex), &link) == EBPF_SUCCESS);

    // Close program handle. That should detach the program from the hook
    // and unload the program.
    bpf_object__close(object);
    program_fd = ebpf_fd_invalid;
    REQUIRE(ebpf_get_next_program(program_fd, &program_fd) == EBPF_SUCCESS);
    REQUIRE(program_fd == ebpf_fd_invalid);

    // Detach and close link handle.
    // ebpf_object_tracking_terminate() which is called when the test
    // exits checks if all the objects in EC have been deleted.
    hook.detach_link(link);
    hook.close_link(link);
}

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
        EBPF_PROGRAM_TYPE_XDP,
        "reflect_packet",
        execution_type,
        &ifindex,
        sizeof(ifindex),
        hook);

    // Dummy UDP datagram with fake IP and MAC addresses.
    udp_packet_t packet(address_family);
    packet.set_destination_port(ntohs(REFLECTION_TEST_PORT));

    xdp_md_t ctx{packet.data(), packet.data() + packet.size(), 0, TEST_IFINDEX};

    int hook_result;
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
        EBPF_PROGRAM_TYPE_XDP,
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

    int hook_result;
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

static void
_xdp_decapsulate_permit_packet_test(ebpf_execution_type_t execution_type, ADDRESS_FAMILY address_family)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);
    uint32_t ifindex = 0;
    program_load_attach_helper_t program_helper(
        SAMPLE_PATH "decap_permit_packet.o",
        EBPF_PROGRAM_TYPE_XDP,
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

    int hook_result;
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

TEST_CASE("xdp-decapsulate-permit-v4-jit", "[xdp_tests]")
{
    _xdp_decapsulate_permit_packet_test(EBPF_EXECUTION_JIT, AF_INET);
}
TEST_CASE("xdp-decapsulate-permit-v6-jit", "[xdp_tests]")
{
    _xdp_decapsulate_permit_packet_test(EBPF_EXECUTION_JIT, AF_INET6);
}
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
        SAMPLE_PATH "bpf.o", EBPF_PROGRAM_TYPE_XDP, "func", EBPF_EXECUTION_INTERPRET, &ifindex, sizeof(ifindex), hook);

    // Dummy UDP datagram with fake IP and MAC addresses.
    udp_packet_t packet(AF_INET);
    packet.set_destination_port(ntohs(REFLECTION_TEST_PORT));

    // Dummy context (not used by the eBPF program).
    xdp_md_helper_t ctx(packet.packet());
    int result;

    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);
    bpf_program* program = bpf_object__find_program_by_name(program_helper.get_object(), "func");
    REQUIRE(program != nullptr);

    // Test the case where the provider only permits a single program to be attached.
    REQUIRE(hook.attach(program) == EBPF_EXTENSION_FAILED_TO_LOAD);

    hook.detach();
}

TEST_CASE("map_reuse", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    // First create and pin the maps manually.
    int inner_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u32), 1, 0);
    REQUIRE(inner_map_fd > 0);

    int outer_map_fd = bpf_create_map_in_map(BPF_MAP_TYPE_HASH_OF_MAPS, nullptr, sizeof(__u32), inner_map_fd, 1, 0);
    REQUIRE(outer_map_fd > 0);

    // Verify we can insert the inner map into the outer map.
    __u32 outer_key = 0;
    int error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    // Pin the outer map.
    error = bpf_obj_pin(outer_map_fd, "/ebpf/global/outer_map");
    REQUIRE(error == 0);

    int port_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u32), 1, 0);
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
        SAMPLE_PATH "map_reuse.o",
        EBPF_PROGRAM_TYPE_XDP,
        "lookup_update",
        EBPF_EXECUTION_ANY,
        &ifindex,
        sizeof(ifindex),
        hook);

    auto packet = prepare_udp_packet(10, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size(), 0, TEST_IFINDEX};
    int hook_result;

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

TEST_CASE("auto_pinned_maps", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    uint32_t ifindex = 0;
    program_load_attach_helper_t program_helper(
        SAMPLE_PATH "map_reuse.o",
        EBPF_PROGRAM_TYPE_XDP,
        "lookup_update",
        EBPF_EXECUTION_ANY,
        &ifindex,
        sizeof(ifindex),
        hook);

    fd_t outer_map_fd = bpf_obj_get("/ebpf/global/outer_map");
    REQUIRE(outer_map_fd > 0);

    int inner_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u32), 1, 0);
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
    int hook_result;

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

TEST_CASE("auto_pinned_maps_custom_path", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    struct bpf_object_open_opts opts = {0};
    opts.pin_root_path = "/custompath/global";
    struct bpf_object* object = bpf_object__open_file("map_reuse.o", &opts);
    REQUIRE(object != nullptr);

    // Load the program.
    REQUIRE(bpf_object__load(object) == 0);

    struct bpf_program* program = bpf_object__find_program_by_name(object, "lookup_update");
    REQUIRE(program != nullptr);

    // Attach should now succeed.
    struct bpf_link* link = bpf_program__attach(program);
    REQUIRE(link != nullptr);

    fd_t outer_map_fd = bpf_obj_get("/custompath/global/outer_map");
    REQUIRE(outer_map_fd > 0);

    int inner_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u32), 1, 0);
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
    int hook_result;

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

    REQUIRE(bpf_link__destroy(link) == 0);
    bpf_object__close(object);
}

TEST_CASE("map_reuse_invalid", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    // Create and pin a map with a different map type than in ELF file.
    int map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u32), 1, 0);
    REQUIRE(map_fd > 0);

    // Pin the map.
    int error = bpf_obj_pin(map_fd, "/ebpf/global/outer_map");
    REQUIRE(error == 0);

    int port_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u32), 1, 0);
    REQUIRE(port_map_fd > 0);

    // Pin port map.
    error = bpf_obj_pin(port_map_fd, "/ebpf/global/port_map");
    REQUIRE(error == 0);

    // Load BPF object from ELF file. Loading the program should fail as the
    // map type for map pinned at "/ebpf/global/outer_map" does not match.
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    const char* log_buffer = nullptr;
    ebpf_result_t result = ebpf_program_load(
        SAMPLE_PATH "map_reuse.o",
        &EBPF_PROGRAM_TYPE_XDP,
        nullptr,
        EBPF_EXECUTION_ANY,
        &object,
        &program_fd,
        &log_buffer);

    ebpf_free_string(log_buffer);
    REQUIRE(result == EBPF_INVALID_ARGUMENT);

    Platform::_close(map_fd);
    Platform::_close(port_map_fd);

    REQUIRE(ebpf_object_unpin("/ebpf/global/outer_map") == EBPF_SUCCESS);
    REQUIRE(ebpf_object_unpin("/ebpf/global/port_map") == EBPF_SUCCESS);
}

TEST_CASE("map_reuse_2", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    // First create and pin the maps manually.
    int inner_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u32), 1, 0);
    REQUIRE(inner_map_fd > 0);

    int outer_map_fd = bpf_create_map_in_map(BPF_MAP_TYPE_HASH_OF_MAPS, nullptr, sizeof(__u32), inner_map_fd, 1, 0);
    REQUIRE(outer_map_fd > 0);

    // Verify we can insert the inner map into the outer map.
    __u32 outer_key = 0;
    int error = bpf_map_update_elem(outer_map_fd, &outer_key, &inner_map_fd, 0);
    REQUIRE(error == 0);

    // Pin the outer map.
    error = bpf_obj_pin(outer_map_fd, "/ebpf/global/outer_map");
    REQUIRE(error == 0);

    int port_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u32), 1, 0);
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
        SAMPLE_PATH "map_reuse_2.o",
        EBPF_PROGRAM_TYPE_XDP,
        "lookup_update",
        EBPF_EXECUTION_ANY,
        &ifindex,
        sizeof(ifindex),
        hook);

    auto packet = prepare_udp_packet(10, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size(), 0, TEST_IFINDEX};
    int hook_result;

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

TEST_CASE("map_reuse_3", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);

    // First create and pin the maps manually.
    int inner_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u32), 1, 0);
    REQUIRE(inner_map_fd > 0);

    int outer_map_fd = bpf_create_map_in_map(BPF_MAP_TYPE_HASH_OF_MAPS, nullptr, sizeof(__u32), inner_map_fd, 1, 0);
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

    int port_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u32), 1, 0);
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
        SAMPLE_PATH "map_reuse_2.o",
        EBPF_PROGRAM_TYPE_XDP,
        "lookup_update",
        EBPF_EXECUTION_ANY,
        &ifindex,
        sizeof(ifindex),
        hook);

    auto packet = prepare_udp_packet(10, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx{packet.data(), packet.data() + packet.size(), 0, TEST_IFINDEX};
    int hook_result;

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

TEST_CASE("bpf2c_droppacket", "[bpf2c]")
{
    _test_helper_end_to_end test_helper;
    dll_metadata_table table("bpf2c_test_wrapper.dll", "droppacket");
    uint32_t key = 0;
    uint64_t value = 0;

    REQUIRE(bpf_map_lookup_elem(table.get_map("dropped_packet_map"), &key, &value) == 0);
    REQUIRE(value == 0);

    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);
    // Test that we drop the packet and increment the map
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};

    REQUIRE(table.invoke("xdp", &ctx) == XDP_DROP);
    REQUIRE(bpf_map_lookup_elem(table.get_map("dropped_packet_map"), &key, &value) == 0);
    REQUIRE(value == 1);

    packet = prepare_udp_packet(10, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx2{packet.data(), packet.data() + packet.size()};

    REQUIRE(table.invoke("xdp", &ctx2) == XDP_PASS);
    REQUIRE(bpf_map_lookup_elem(table.get_map("dropped_packet_map"), &key, &value) == 0);
    REQUIRE(value == 1);
}

TEST_CASE("bpf2c_divide_by_zero", "[bpf2c]")
{
    _test_helper_end_to_end test_helper;
    dll_metadata_table table("bpf2c_test_wrapper.dll", "divide_by_zero");

    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);
    // Test that we drop the packet and increment the map
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};

    // Verify the program doesn't crash
    REQUIRE(table.invoke("xdp", &ctx) == 0);
}

TEST_CASE("bpf2c_bindmonitor", "[bpf2c]")
{
    _test_helper_end_to_end test_helper;
    dll_metadata_table table("bpf2c_test_wrapper.dll", "bindmonitor");

    uint64_t fake_pid = 12345;

    fd_t limit_map_fd = table.get_map("limits_map");
    REQUIRE(limit_map_fd > 0);
    fd_t process_map_fd = table.get_map("process_map");
    REQUIRE(process_map_fd > 0);

    // Apply policy of maximum 2 binds per process
    set_bind_limit(limit_map_fd, 2);

    std::function<ebpf_result_t(void*, int*)> invoke = [&table](void* context, int* result) -> ebpf_result_t {
        *result = static_cast<int>(table.invoke("bind", context));
        return EBPF_SUCCESS;
    };
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
}