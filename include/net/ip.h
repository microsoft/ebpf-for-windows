// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#define IPPROTO_IPV4 4
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_IPV6 41

#define AF_INET 2
#define AF_INET6 23

#ifndef DEFAULT_COMPARTMENT_ID
#define DEFAULT_COMPARTMENT_ID 1
#endif

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4201) // nonstandard extension used : nameless struct/union
#endif
typedef struct _IPV4_HEADER
{
    union
    {
        uint8_t VersionAndHeaderLength; // Version and header length.
        struct
        {
            uint8_t HeaderLength : 4;
            uint8_t Version : 4;
        };
        struct // Linux field names.
        {
            uint8_t ihl : 4;
            uint8_t version : 4;
        };
    };
    union
    {
        uint8_t tos;                      // Linux field name.
        uint8_t TypeOfServiceAndEcnField; // Type of service & ECN (RFC 3168).
        struct
        {
            uint8_t EcnField : 2;
            uint8_t TypeOfService : 6;
        };
    };
    union
    {
        uint16_t tot_len;     // Linux field name.
        uint16_t TotalLength; // Total length of datagram.
    };
    union
    {
        uint16_t id; // Linux field name.
        uint16_t Identification;
    };
    union
    {
        uint16_t frag_off;       // Linux field name.
        uint16_t FlagsAndOffset; // Flags and fragment offset.
        struct
        {
            // Order of fields here depends on MSVC compiler-specific behavior
            // See https://learn.microsoft.com/en-us/cpp/c-language/c-bit-fields?view=msvc-170
            uint16_t DontUse1 : 5; // High bits of fragment offset.
            uint16_t MoreFragments : 1;
            uint16_t DontFragment : 1;
            uint16_t Reserved : 1;
            uint16_t DontUse2 : 8; // Low bits of fragment offset.
        };
    };
    union
    {
        uint8_t ttl; // Linux field name.
        uint8_t TimeToLive;
    };
    union
    {
        uint8_t protocol; // Linux field name.
        uint8_t Protocol;
    };
    union
    {
        uint16_t check; // Linux field name.
        uint16_t HeaderChecksum;
    };
    union
    {
        uint32_t saddr; // Linux field name.
        uint32_t SourceAddress;
    };
    union
    {
        uint32_t daddr; // Linux field name.
        uint32_t DestinationAddress;
    };
} IPV4_HEADER, *PIPV4_HEADER;
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

typedef uint8_t ipv6_address_t[16];

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4201) // nonstandard extension used : nameless struct/union
#endif
typedef struct _IPV6_HEADER
{
    union
    {
        uint32_t VersionClassFlow; // 4 bits Version, 8 Traffic Class, 20 Flow Label.
        struct
        { // Convenience structure to access Version field only.
            uint32_t : 4;
            uint32_t Version : 4;
            uint32_t : 24;
        };
    };
    uint16_t PayloadLength; // Zero indicates Jumbo Payload hop-by-hop option.
    uint8_t NextHeader;     // Values are superset of IPv4's Protocol field.
    uint8_t HopLimit;
    ipv6_address_t SourceAddress;
    ipv6_address_t DestinationAddress;
} IPV6_HEADER, *PIPV6_HEADER;
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

// Linux mappings.
#define iphdr _IPV4_HEADER
