/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#if defined(_MSC_VER)
typedef unsigned long long uint64_t;
#else
typedef unsigned long uint64_t;
#endif

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

uint16_t
ntohs(uint16_t us)
{
    return us << 8 | us >> 8;
}

typedef struct _xdp_md
{
    void* data;
    void* data_end;
    uint64_t data_meta;
} xdp_md_t;

typedef struct _bind_md
{
    char* app_id_start;
    char* app_id_end;
    uint64_t process_id;
    uint8_t socket_address[16];
    uint8_t socket_address_length;
    uint8_t operation;
    uint8_t protocol;
} bind_md_t;

typedef enum _bind_operation
{
    BIND_OPERATION_BIND,      // Entry to bind
    BIND_OPERATION_POST_BIND, // After port allocation
    BIND_OPERATION_UNBIND,    // Release port
} bind_operation_t;

typedef enum _bind_action
{
    BIND_PERMIT,
    BIND_DENY,
    BIND_REDIRECT,
} bind_action_t;

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

typedef struct _bpf_map_def
{
    uint32_t size;
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
} bpf_map_def_t;

typedef enum _ebpf_map_type
{
    EBPF_MAP_TYPE_UNSPECIFIED = 0,
    EBPF_MAP_TYPE_HASH = 1,
    EBPF_MAP_TYPE_ARRAY = 2,
} ebpf_map_type_t;

typedef void* (*ebpf_map_lookup_elem_t)(bpf_map_def_t* map, void* key);
#define ebpf_map_lookup_elem ((ebpf_map_lookup_elem_t)1)

typedef void (*ebpf_map_update_element_t)(bpf_map_def_t* map, void* key, void* data, uint64_t flags);
#define ebpf_map_update_element ((ebpf_map_update_element_t)2)

typedef void (*ebpf_map_delete_elem_t)(bpf_map_def_t* map, void* key);
#define ebpf_map_delete_elem ((ebpf_map_delete_elem_t)3)