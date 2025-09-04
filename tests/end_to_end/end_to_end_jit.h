// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

namespace ebpf {
#include "net/if_ether.h"
#include "net/ip.h"
#include "net/udp.h"
}; // namespace ebpf

#define SAMPLE_PATH ""

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

#define DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST2(file, name, attach_type, name_suffix, file_suffix, execution_type) \
    TEST_CASE("cgroup_sockaddr_load_test_" name "_" #attach_type "_" name_suffix, "[cgroup_sock_addr]")        \
    {                                                                                                          \
        cgroup_sock_addr_load_test(file file_suffix, name, attach_type, execution_type);                      \
    }

#if !defined(CONFIG_BPF_JIT_DISABLED)
#define DECLARE_CGROUP_SOCK_ADDR_LOAD_JIT_TEST(file, name, attach_type) \
    DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST2(file, name, attach_type, "jit", ".o", EBPF_EXECUTION_JIT)
#else
#define DECLARE_CGROUP_SOCK_ADDR_LOAD_JIT_TEST(file, name, attach_type)
#endif

inline std::vector<uint8_t>
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

inline int
get_total_map_count()
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

inline const in_addr _test_source_ipv4 = {10, 0, 0, 1};
inline const in_addr _test_destination_ipv4 = {20, 0, 0, 1};
inline const struct _ipv4_address_pair _test_ipv4_addrs = {_test_source_ipv4, _test_destination_ipv4};

inline const in_addr _test2_source_ipv4 = {30, 0, 0, 1};
inline const in_addr _test2_destination_ipv4 = {40, 0, 0, 1};
inline const struct _ipv4_address_pair _test2_ipv4_addrs = {_test2_source_ipv4, _test2_destination_ipv4};

inline const in6_addr _test_source_ipv6 = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2e, 0xfe, 0x12, 0x34};
inline const in6_addr _test_destination_ipv6 = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2e, 0xfe, 0x56, 0x78};
inline const struct _ipv6_address_pair _test_ipv6_addrs = {_test_source_ipv6, _test_destination_ipv6};

inline const in6_addr _test2_source_ipv6 = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2e, 0xfe, 0x9a, 0xbc};
inline const in6_addr _test2_destination_ipv6 = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2e, 0xfe, 0xde, 0xf0};
inline const struct _ipv6_address_pair _test2_ipv6_addrs = {_test2_source_ipv6, _test2_destination_ipv6};

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

const std::array<uint8_t, 6> _test_source_mac = {0, 1, 2, 3, 4, 5};
const std::array<uint8_t, 6> _test_destination_mac = {0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

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

int
ebpf_program_load(
    _In_z_ const char* file_name,
    bpf_prog_type prog_type,
    ebpf_execution_type_t execution_type,
    _Out_ bpf_object_ptr* unique_object,
    _Out_ fd_t* program_fd, // File descriptor of first program in the object.
    _Outptr_opt_result_maybenull_z_ const char** log_buffer);

void
cgroup_sock_addr_load_test(
    _In_z_ const char* file,
    _In_z_ const char* name,
    ebpf_attach_type_t& attach_type,
    ebpf_execution_type_t execution_type);

#if !defined(CONFIG_BPF_INTERPRETER_DISABLED) || !defined(CONFIG_BPF_JIT_DISABLED)
void
xdp_decapsulate_permit_packet_test(ebpf_execution_type_t execution_type, ADDRESS_FAMILY address_family);
#endif