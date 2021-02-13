/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/

typedef unsigned long __u64;
typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned char __u8;

__u16 ntohs(__u16 us)
{
    return us << 8 | us >> 8;
}

typedef struct xdp_md_
{
   void* data;
   void* data_end;
   __u64 data_meta;
} xdp_md;

typedef struct _IPV4_HEADER {
    union {
        __u8 VersionAndHeaderLength;   // Version and header length.
        struct {
            __u8 HeaderLength : 4;
            __u8 Version : 4;
        };
    };
    union {
        __u8 TypeOfServiceAndEcnField; // Type of service & ECN (RFC 3168).
        struct {
            __u8 EcnField : 2;
            __u8 TypeOfService : 6;
        };
    };
    __u16 TotalLength;                 // Total length of datagram.
    __u16 Identification;
    union {
        __u16 FlagsAndOffset;          // Flags and fragment offset.
        struct {
            __u16 DontUse1 : 5;        // High bits of fragment offset.
            __u16 MoreFragments : 1;
            __u16 DontFragment : 1;
            __u16 Reserved : 1;
            __u16 DontUse2 : 8;        // Low bits of fragment offset.
        };
    };
    __u8 TimeToLive;
    __u8 Protocol;
    __u16 HeaderChecksum;
    __u32 SourceAddress;
    __u32 DestinationAddress;
} IPV4_HEADER, *PIPV4_HEADER;

typedef struct UDP_HEADER_ {
    __u16 srcPort;
    __u16 destPort;
    __u16 length;
    __u16 checksum;
} UDP_HEADER;

struct bpf_map_def {
      __u32 type;
      __u32 key_size;
      __u32 value_size;
      __u32 max_entries;
      __u32 map_flags;
      __u32 inner_map_idx;
      __u32 numa_node;
};
typedef void* (*ebpf_map_lookup_elem_t)(void * map, void* key);
#define ebpf_map_lookup_elem ((ebpf_map_lookup_elem_t)1)
