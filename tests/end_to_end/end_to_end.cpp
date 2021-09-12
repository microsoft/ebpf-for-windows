// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#define CATCH_CONFIG_MAIN

#include <array>
#include <chrono>
#include <mutex>
#include <thread>
#include <WinSock2.h>
#include <in6addr.h> // Must come after Winsock2.h

#include "bpf.h"
#include "catch_wrapper.hpp"
#include "common_tests.h"
#include "ebpf_bind_program_data.h"
#include "ebpf_core.h"
#include "ebpf_xdp_program_data.h"
#include "helpers.h"
#include "libbpf.h"
#include "mock.h"
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
prepare_udp_packet(uint16_t udp_length, uint16_t ethernet_type)
{
    std::vector<uint8_t> packet(
        sizeof(ebpf::ETHERNET_HEADER) + sizeof(ebpf::UDP_HEADER) +
        ((ethernet_type == ETHERNET_TYPE_IPV4) ? sizeof(ebpf::IPV4_HEADER) : sizeof(ebpf::IPV6_HEADER)));
    auto eth = reinterpret_cast<ebpf::ETHERNET_HEADER*>(packet.data());
    ebpf::UDP_HEADER* udp;
    if (ethernet_type == ETHERNET_TYPE_IPV4) {
        auto ipv4 = reinterpret_cast<ebpf::IPV4_HEADER*>(eth + 1);
        ipv4->HeaderLength = sizeof(ebpf::IPV4_HEADER) / sizeof(uint32_t);
        ipv4->Protocol = IPPROTO_UDP;
        udp = reinterpret_cast<ebpf::UDP_HEADER*>(ipv4 + 1);
    } else {
        auto ipv6 = reinterpret_cast<ebpf::IPV6_HEADER*>(eth + 1);
        ipv6->NextHeader = IPPROTO_UDP;
        udp = reinterpret_cast<ebpf::UDP_HEADER*>(ipv6 + 1);
    }
    eth->Type = ntohs(ethernet_type);
    udp->length = udp_length;

    return packet;
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

const in6_addr _test_source_ipv6 = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2e, 0xfe, 0x12, 0x34};
const in6_addr _test_destination_ipv6 = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2e, 0xfe, 0x56, 0x78};
const struct _ipv6_address_pair _test_ipv6_addrs = {_test_source_ipv6, _test_destination_ipv6};

typedef class _udp_packet
{
  public:
    _udp_packet(
        ADDRESS_FAMILY address_family,
        _In_ const std::array<uint8_t, 6>& source_mac = _test_source_mac,
        _In_ const std::array<uint8_t, 6>& destination_mac = _test_destination_mac,
        _In_opt_ const void* ip_addrs = nullptr,
        uint16_t datagram_length = 1024)
        : _address_family(address_family)
    {
        UNREFERENCED_PARAMETER(source_mac);
        UNREFERENCED_PARAMETER(destination_mac);
        _packet = prepare_udp_packet(
            sizeof(ebpf::UDP_HEADER) + datagram_length,
            (address_family == AF_INET) ? ETHERNET_TYPE_IPV4 : ETHERNET_TYPE_IPV6);
        set_mac_addresses(source_mac, destination_mac);
        if (_address_family == AF_INET)
            (ip_addrs == nullptr) ? set_ipv4_addresses(&_test_ipv4_addrs.source, &_test_ipv4_addrs.destination)
                                  : set_ipv4_addresses(
                                        &(reinterpret_cast<const _ipv4_address_pair*>(ip_addrs))->source,
                                        &(reinterpret_cast<const _ipv4_address_pair*>(ip_addrs))->destination);
        else
            (ip_addrs == nullptr) ? set_ipv6_addresses(&_test_ipv6_addrs.source, &_test_ipv6_addrs.destination)
                                  : set_ipv6_addresses(
                                        &(reinterpret_cast<const _ipv6_address_pair*>(ip_addrs))->source,
                                        &(reinterpret_cast<const _ipv6_address_pair*>(ip_addrs))->destination);
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

    static const ebpf::UDP_HEADER*
    _get_udp_header(_In_ const uint8_t* packet_buffer, ADDRESS_FAMILY address_family)
    {
        auto eth = reinterpret_cast<const ebpf::ETHERNET_HEADER*>(packet_buffer);
        const ebpf::UDP_HEADER* udp = nullptr;
        if (address_family == AF_INET) {
            auto ip = reinterpret_cast<const ebpf::IPV4_HEADER*>(eth + 1);
            udp = reinterpret_cast<const ebpf::UDP_HEADER*>(ip + 1);
        } else {
            REQUIRE(address_family == AF_INET6);
            auto ip = reinterpret_cast<const ebpf::IPV6_HEADER*>(eth + 1);
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

  private:
    void
    set_mac_addresses(_In_ const std::array<uint8_t, 6>& source_mac, _In_ const std::array<uint8_t, 6>& destination_mac)
    {
        auto eth = reinterpret_cast<ebpf::ETHERNET_HEADER*>(_packet.data());
        memcpy(eth->Source, source_mac.data(), sizeof(eth->Source));
        memcpy(eth->Destination, destination_mac.data(), sizeof(eth->Destination));
    }
    void
    set_ipv4_addresses(_In_ const in_addr* source_address, _In_ const in_addr* destination_address)
    {
        auto eth = reinterpret_cast<ebpf::ETHERNET_HEADER*>(_packet.data());
        auto ipv4 = reinterpret_cast<ebpf::IPV4_HEADER*>(eth + 1);

        ipv4->SourceAddress = source_address->s_addr;
        ipv4->DestinationAddress = destination_address->s_addr;
    }
    void
    set_ipv6_addresses(_In_ const in6_addr* source_address, _In_ const in6_addr* destination_address)
    {
        auto eth = reinterpret_cast<ebpf::ETHERNET_HEADER*>(_packet.data());
        auto ipv6 = reinterpret_cast<ebpf::IPV6_HEADER*>(eth + 1);

        memcpy(ipv6->SourceAddress, source_address, sizeof(ebpf::ipv6_address_t));
        memcpy(ipv6->DestinationAddress, destination_address, sizeof(ebpf::ipv6_address_t));
    }

    ADDRESS_FAMILY _address_family;
    std::vector<uint8_t> _packet;

} udp_packet_t;

#define SAMPLE_PATH ""

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
    fd_t port_map_fd = bpf_object__find_map_fd_by_name(object, "port_map");

    REQUIRE(hook.attach_link(program_fd, &link) == EBPF_SUCCESS);

    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);

    uint32_t key = 0;
    uint64_t value = 1000;
    REQUIRE(bpf_map_update_elem(port_map_fd, &key, &value, EBPF_ANY) == EBPF_SUCCESS);

    // Test that we drop the packet and increment the map
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};

    int hook_result;
    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 2);

    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value == 1001);

    REQUIRE(bpf_map_delete_elem(port_map_fd, &key) == EBPF_SUCCESS);

    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value == 0);

    packet = prepare_udp_packet(10, ETHERNET_TYPE_IPV4);
    xdp_md_t ctx2{packet.data(), packet.data() + packet.size()};

    REQUIRE(hook.fire(&ctx2, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 1);

    REQUIRE(bpf_map_lookup_elem(port_map_fd, &key, &value) == EBPF_SUCCESS);
    REQUIRE(value == 0);

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

    REQUIRE(hook.attach_link(program_fd, &link) == EBPF_SUCCESS);

    auto packet = prepare_udp_packet(0, ETHERNET_TYPE_IPV4);

    // Test that we drop the packet and increment the map
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};

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
emulate_bind(single_instance_hook_t& hook, uint64_t pid, const char* appid)
{
    int result;
    std::string app_id = appid;
    bind_md_t ctx{0};
    ctx.app_id_start = (uint8_t*)app_id.c_str();
    ctx.app_id_end = (uint8_t*)(app_id.c_str()) + app_id.size();
    ctx.process_id = pid;
    ctx.operation = BIND_OPERATION_BIND;
    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);
    return static_cast<bind_action_t>(result);
}

void
emulate_unbind(single_instance_hook_t& hook, uint64_t pid, const char* appid)
{
    int result;
    std::string app_id = appid;
    bind_md_t ctx{0};
    ctx.process_id = pid;
    ctx.operation = BIND_OPERATION_UNBIND;
    REQUIRE(hook.fire(&ctx, &result) == EBPF_SUCCESS);
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

    REQUIRE(hook.attach_link(program_fd, &link) == EBPF_SUCCESS);

    // Apply policy of maximum 2 binds per process
    set_bind_limit(limit_map_fd, 2);

    // Bind first port - success
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);

    // Bind second port - success
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 2);

    // Bind third port - blocked
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_DENY);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 2);

    // Unbind second port
    emulate_unbind(hook, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);

    // Unbind first port
    emulate_unbind(hook, fake_pid, "fake_app_1");
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 0);

    // Bind from two apps to test enumeration
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_1") == BIND_PERMIT);
    REQUIRE(get_bind_count_for_pid(process_map_fd, fake_pid) == 1);

    fake_pid = 54321;
    REQUIRE(emulate_bind(hook, fake_pid, "fake_app_2") == BIND_PERMIT);
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

static void
_utility_helper_functions_test(ebpf_execution_type_t execution_type)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);
    program_load_attach_helper_t program_helper(
        SAMPLE_PATH "test_utility_helpers.o", EBPF_PROGRAM_TYPE_XDP, "test_utility_helpers", execution_type, hook);
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
TEST_CASE("droppacket-interpret", "[end_to_end]") { droppacket_test(EBPF_EXECUTION_INTERPRET); }
TEST_CASE("divide_by_zero_interpret", "[end_to_end]") { divide_by_zero_test(EBPF_EXECUTION_INTERPRET); }
TEST_CASE("bindmonitor-interpret", "[end_to_end]") { bindmonitor_test(EBPF_EXECUTION_INTERPRET); }
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

    REQUIRE(ebpf_object_get(process_maps_name.c_str()) != ebpf_fd_invalid);

    REQUIRE(ebpf_object_get(limit_maps_name.c_str()) != ebpf_fd_invalid);

    REQUIRE(
        bpf_map__unpin(bpf_object__find_map_by_name(object, "process_map"), process_maps_name.c_str()) == EBPF_SUCCESS);
    REQUIRE(
        bpf_map__unpin(bpf_object__find_map_by_name(object, "limits_map"), limit_maps_name.c_str()) == EBPF_SUCCESS);

    REQUIRE(ebpf_object_get(limit_maps_name.c_str()) == ebpf_fd_invalid);

    REQUIRE(ebpf_object_get(process_maps_name.c_str()) == ebpf_fd_invalid);

    bpf_object__close(object);
}

TEST_CASE("enumerate_and_query_maps", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    const char* error_message = nullptr;
    fd_t map_fds[4] = {0};
    bpf_object* object;
    fd_t program_fd;
    uint32_t result;

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

    std::string process_maps_name = "process_map";
    std::string limit_maps_name = "limits_map";

    map_fds[0] = bpf_object__find_map_fd_by_name(object, process_maps_name.c_str());
    REQUIRE(map_fds[0] > 0);
    map_fds[1] = bpf_object__find_map_fd_by_name(object, limit_maps_name.c_str());
    REQUIRE(map_fds[1] > 0);

    fd_t fd_iterator = ebpf_fd_invalid;
    REQUIRE(ebpf_get_next_map(fd_iterator, &fd_iterator) == EBPF_SUCCESS);
    map_fds[2] = fd_iterator;
    REQUIRE(ebpf_get_next_map(fd_iterator, &fd_iterator) == EBPF_SUCCESS);
    map_fds[3] = fd_iterator;
    REQUIRE(ebpf_get_next_map(fd_iterator, &fd_iterator) == EBPF_SUCCESS);
    REQUIRE(fd_iterator == ebpf_fd_invalid);

    ebpf_map_definition_in_memory_t map_definitions[_countof(map_fds)];
    ebpf_map_definition_in_memory_t process_map = {
        sizeof(ebpf_map_definition_in_memory_t),
        BPF_MAP_TYPE_HASH,
        sizeof(uint64_t),
        sizeof(process_entry_t),
        1024,
        (uint32_t)-1};

    ebpf_map_definition_in_memory_t limits_map = {
        sizeof(ebpf_map_definition_in_memory_t),
        BPF_MAP_TYPE_ARRAY,
        sizeof(uint32_t),
        sizeof(uint32_t),
        1,
        (uint32_t)-1};

    for (size_t index = 0; index < _countof(map_fds); index++) {
        REQUIRE(
            ebpf_map_query_definition(
                map_fds[index],
                &map_definitions[index].size,
                reinterpret_cast<uint32_t*>(&map_definitions[index].type),
                &map_definitions[index].key_size,
                &map_definitions[index].value_size,
                &map_definitions[index].max_entries,
                &map_definitions[index].inner_map_id) == EBPF_SUCCESS);
        if (index % 2 == 0) {
            REQUIRE(memcmp(&process_map, &map_definitions[index], sizeof(process_map)) == 0);
        } else {
            REQUIRE(memcmp(&limits_map, &map_definitions[index], sizeof(process_map)) == 0);
        }
    }

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
    ebpf_close_fd(program_fd);
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
    ebpf_close_fd(program_fd);

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

    REQUIRE(hook.attach_link(program_fd, &link) == EBPF_SUCCESS);

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

    REQUIRE(hook.attach_link(program_fd, &link) == EBPF_SUCCESS);

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

    REQUIRE(hook.attach_link(program_fd, &link) == EBPF_SUCCESS);

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

    REQUIRE(hook.attach_link(program_fd, &link) == EBPF_SUCCESS);

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

    ebpf_result_t result;
    fd_t map_fd;
    uint32_t key = 0;
    uint64_t value = 10;
    int element_count = 2;

    result = ebpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint64_t), 5, 0, &map_fd);
    REQUIRE(result == EBPF_SUCCESS);
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
}

TEST_CASE("create_map_name", "[end_to_end]")
{
    _test_helper_end_to_end test_helper;

    ebpf_result_t result;
    fd_t map_fd;
    uint32_t key = 0;
    uint64_t value = 10;
    int element_count = 2;
    const char* map_name = "array_map";

    result = ebpf_create_map_name(BPF_MAP_TYPE_ARRAY, map_name, sizeof(uint32_t), sizeof(uint64_t), 5, 0, &map_fd);
    REQUIRE(result == EBPF_SUCCESS);
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
}

static void
_xdp_reflect_packet_test(ebpf_execution_type_t execution_type, ADDRESS_FAMILY address_family)
{
    _test_helper_end_to_end test_helper;
    single_instance_hook_t hook(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);
    program_info_provider_t xdp_program_info(EBPF_PROGRAM_TYPE_XDP);
    program_load_attach_helper_t program_helper(
        SAMPLE_PATH "reflect_packet.o", EBPF_PROGRAM_TYPE_XDP, "reflect_packet", execution_type, hook);

    // Dummy UDP datagram with fake IP and MAC addresses.
    udp_packet_t packet(address_family);
    packet.set_destination_port(ntohs(REFLECTION_TEST_PORT));

    // Dummy context (not used by the eBPF program).
    xdp_md_t ctx{packet.data(), packet.data() + packet.size()};

    int hook_result;
    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 3);

    ebpf::ETHERNET_HEADER* ethernet_header = reinterpret_cast<ebpf::ETHERNET_HEADER*>(ctx.data);
    REQUIRE(memcmp(ethernet_header->Destination, _test_source_mac.data(), sizeof(ethernet_header->Destination)) == 0);
    REQUIRE(memcmp(ethernet_header->Source, _test_destination_mac.data(), sizeof(ethernet_header->Source)) == 0);

    if (address_family == AF_INET) {
        ebpf::IPV4_HEADER* ipv4 = reinterpret_cast<ebpf::IPV4_HEADER*>(ethernet_header + 1);
        REQUIRE(ipv4->SourceAddress == _test_destination_ipv4.s_addr);
        REQUIRE(ipv4->DestinationAddress == _test_source_ipv4.s_addr);
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
    program_load_attach_helper_t program_helper(
        SAMPLE_PATH "reflect_packet.o", EBPF_PROGRAM_TYPE_XDP, "encap_reflect_packet", execution_type, hook);

    // Dummy UDP datagram with fake IP and MAC addresses.
    udp_packet_t packet(address_family);
    packet.set_destination_port(ntohs(REFLECTION_TEST_PORT));

    // Dummy context (not used by the eBPF program).
    xdp_md_helper_t ctx(packet.packet());
    uint8_t* ip_header = packet.packet().data() + sizeof(ebpf::ETHERNET_HEADER);
    std::vector<uint8_t> original_ip_datagram(ip_header, packet.packet().data() + packet.packet().size());

    int hook_result;
    REQUIRE(hook.fire(&ctx, &hook_result) == EBPF_SUCCESS);
    REQUIRE(hook_result == 3);

    ebpf::ETHERNET_HEADER* ethernet_header = reinterpret_cast<ebpf::ETHERNET_HEADER*>(ctx.data);
    REQUIRE(memcmp(ethernet_header->Destination, _test_source_mac.data(), sizeof(ethernet_header->Destination)) == 0);
    REQUIRE(memcmp(ethernet_header->Source, _test_destination_mac.data(), sizeof(ethernet_header->Source)) == 0);

    if (address_family == AF_INET) {
        ebpf::IPV4_HEADER* ipv4 = reinterpret_cast<ebpf::IPV4_HEADER*>(ethernet_header + 1);
        REQUIRE(ipv4->SourceAddress == _test_destination_ipv4.s_addr);
        REQUIRE(ipv4->DestinationAddress == _test_source_ipv4.s_addr);
        REQUIRE(ipv4->Protocol == IPPROTO_IPV4);
        uint8_t* inner_ip_header = (uint8_t*)(ipv4 + 1);
        REQUIRE(memcmp(inner_ip_header, original_ip_datagram.data(), original_ip_datagram.size()) == 0);
    } else {
        ebpf::IPV6_HEADER* ipv6 = reinterpret_cast<ebpf::IPV6_HEADER*>(ethernet_header + 1);
        REQUIRE(memcmp(ipv6->SourceAddress, &_test_destination_ipv6, sizeof(ebpf::ipv6_address_t)) == 0);
        REQUIRE(memcmp(ipv6->DestinationAddress, &_test_source_ipv6, sizeof(ebpf::ipv6_address_t)) == 0);
        REQUIRE(ipv6->NextHeader == IPPROTO_IPV6);
        uint8_t* inner_ip_header = (uint8_t*)(ipv6 + 1);
        REQUIRE(memcmp(inner_ip_header, original_ip_datagram.data(), original_ip_datagram.size()) == 0);
    }
}

TEST_CASE("xdp-reflect-v4-jit", "[xdp_tests]") { _xdp_reflect_packet_test(EBPF_EXECUTION_JIT, AF_INET); }
TEST_CASE("xdp-reflect-v6-jit", "[xdp_tests]") { _xdp_reflect_packet_test(EBPF_EXECUTION_JIT, AF_INET6); }
TEST_CASE("xdp-reflect-v4-interpret", "[xdp_tests]") { _xdp_reflect_packet_test(EBPF_EXECUTION_INTERPRET, AF_INET); }
TEST_CASE("xdp-reflect-v6-interpret", "[xdp_tests]") { _xdp_reflect_packet_test(EBPF_EXECUTION_INTERPRET, AF_INET6); }
TEST_CASE("xdp-encap-reflect-v4-jit", "[xdp_tests]") { _xdp_encap_reflect_packet_test(EBPF_EXECUTION_JIT, AF_INET); }
TEST_CASE("xdp-encap-reflect-v6-jit", "[xdp_tests]") { _xdp_encap_reflect_packet_test(EBPF_EXECUTION_JIT, AF_INET); }
TEST_CASE("xdp-encap-reflect-v4-interpret", "[xdp_tests]")
{
    _xdp_encap_reflect_packet_test(EBPF_EXECUTION_INTERPRET, AF_INET);
}
TEST_CASE("xdp-encap-reflect-v6-interpret", "[xdp_tests]")
{
    _xdp_encap_reflect_packet_test(EBPF_EXECUTION_INTERPRET, AF_INET);
}