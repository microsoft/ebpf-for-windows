// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This file is included by sample eBPF programs.

#if defined(_MSC_VER)
typedef unsigned long long uint64_t;
#else
typedef unsigned long uint64_t;
#endif

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

#include "ebpf_nethooks.h"

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4201) // nonstandard extension used : nameless struct/union
#endif

uint16_t
ntohs(uint16_t us)
{
    return us << 8 | us >> 8;
}

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
    };
    union
    {
        uint8_t TypeOfServiceAndEcnField; // Type of service & ECN (RFC 3168).
        struct
        {
            uint8_t EcnField : 2;
            uint8_t TypeOfService : 6;
        };
    };
    uint16_t TotalLength; // Total length of datagram.
    uint16_t Identification;
    union
    {
        uint16_t FlagsAndOffset; // Flags and fragment offset.
        struct
        {
            uint16_t DontUse1 : 5; // High bits of fragment offset.
            uint16_t MoreFragments : 1;
            uint16_t DontFragment : 1;
            uint16_t Reserved : 1;
            uint16_t DontUse2 : 8; // Low bits of fragment offset.
        };
    };
    uint8_t TimeToLive;
    uint8_t Protocol;
    uint16_t HeaderChecksum;
    uint32_t SourceAddress;
    uint32_t DestinationAddress;
} IPV4_HEADER, *PIPV4_HEADER;

//
// IPv6 Internet address (RFC 2553)
// This is an 'on-wire' format structure.
//
typedef struct in6_addr {
    union {
        uint8_t       Byte[16];
        uint16_t      Word[8];
    } u;
} IN6_ADDR, *PIN6_ADDR;

//
// IPV6_HEADER
//
// The structure for an IPv6 header.
// RAW socket applications, packetization layer modules, and
// network-layer services all need access to this structure.
//
typedef struct _IPV6_HEADER {
    uint32_t VersionClassFlow;// 4 bits Version, 8 Traffic Class, 20 Flow Label.
    uint16_t PayloadLength;   // Zero indicates Jumbo Payload hop-by-hop option.
    uint8_t NextHeader;       // Values are superset of IPv4's Protocol field.
    uint8_t HopLimit;
    IN6_ADDR SourceAddress;
    IN6_ADDR DestinationAddress;
    // union
    // {
    //     uint8_t pVersionTrafficClassAndFlowLabel[4];
    //     struct
    //     {
    //         uint8_t r1 : 4;
    //         uint8_t value : 4;
    //         uint8_t r2;
    //         uint8_t r3;
    //         uint8_t r4;
    //     } version;
    // };
    // uint16_t payloadLength;
    // uint8_t nextHeader;
    // uint8_t hopLimit;
    // uint8_t pSourceAddress[16];
    // uint8_t pDestinationAddress[16];
} IPV6_HEADER, *PIPV6_HEADER;

typedef struct UDP_HEADER_
{
    uint16_t srcPort;
    uint16_t destPort;
    uint16_t length;
    uint16_t checksum;
} UDP_HEADER;

typedef struct TCP_HEADER_
{
    uint16_t srcPort;
    uint16_t destPort;
    uint32_t sequenceNumber;
    uint32_t ackNumber;
    uint16_t offsetAndFlags;
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;
} TCP_HEADER; // , *PTCP_HEADER;

// typedef struct TCP_HEADER_ {
//     uint16_t srcPort;
//     uint16_t destPort;
//     uint32_t sequenceNumber;
//     uint32_t ackNumber;
//     uint8_t th_x2 : 4;
//     uint8_t th_len : 4;
//     uint8_t th_flags;
//     uint16_t windowSize;
//     uint16_t checksum;
//     uint16_t urgentPointer;
// } TCP_HEADER

#if defined(_MSC_VER)
#pragma warning(pop)
#endif
