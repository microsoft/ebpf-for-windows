// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

typedef uint8_t mac_address_t[6];

#define ETHERNET_TYPE_IPV4 0x0800
#define ETHERNET_TYPE_IPV6 0x86dd

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4201) // nonstandard extension used : nameless struct/union
#endif
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
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

// Linux mappings for cross-platform eBPF programs.
#define h_proto Type
#define ethhdr _ETHERNET_HEADER
#define ETH_P_IP ETHERNET_TYPE_IPV4
