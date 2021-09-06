// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This file is included by sample eBPF programs that need
// definitions for IPv4 and UDP headers.

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

typedef struct _ETHERNET_HEADER
{
    uint8_t Destination[6];
    uint8_t Source[6];
    union
    {
        uint16_t Type;   // Ethernet
        uint16_t Length; // IEEE 802
    };
} ETHERNET_HEADER, *PETHERNET_HEADER;

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

typedef struct UDP_HEADER_
{
    uint16_t srcPort;
    uint16_t destPort;
    uint16_t length;
    uint16_t checksum;
} UDP_HEADER;

#if defined(_MSC_VER)
#pragma warning(pop)
#endif
