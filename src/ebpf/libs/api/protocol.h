/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/
#pragma once

typedef enum EbpfOperation_ {
    evidence, 
    resolve_helper,
    resolve_map,
    load_code,
    unload_code,
    attach,
    detach,
    create_map,
    map_lookup_element,
    map_update_element,
    map_delete_element
} EbpfOperation;

struct EbpfOpHeader {
    uint16_t length;
    EbpfOperation id;
};

struct EbpfOpEvidenceRequest {
    struct EbpfOpHeader header;
    uint8_t evidence[1];
};

struct EbpfOpEvidenceReply {
    struct EbpfOpHeader header;
    uint32_t status;
};

struct EbpfOpResolveHelperRequest {
    struct EbpfOpHeader header;
    uint32_t helper_id[1];
};

struct EbpfOpResolveHelperReply {
    struct EbpfOpHeader header;
    uint64_t address[1];
};

struct EbpfOpResolveMapRequest {
    struct EbpfOpHeader header;
    uint64_t map_id[1];
};

struct EbpfOpResolveMapReply {
    struct EbpfOpHeader header;
    uint64_t address[1];
};

struct EbpfOpLoadRequest {
    struct EbpfOpHeader header;
    uint8_t machine_code[1];
};

struct EbpfOpUnloadRequest {
    struct EbpfOpHeader header;
    uint64_t handle;
};

struct EbpfOpLoadReply {
    struct EbpfOpHeader header;
    uint64_t handle;
};

struct EbpfOpAttachDetachRequest {
    struct EbpfOpHeader header;
    uint64_t handle;
    uint32_t hook;
};

struct EbpfOpCreateMapRequest {
    struct EbpfOpHeader header;
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
};

struct EbpfOpCreateMapReply {
    struct EbpfOpHeader header;
    uint64_t handle;
};

struct EbpfOpMapLookupElementRequest {
    struct EbpfOpHeader header;
    uint64_t handle;
    uint8_t key[1];
};

struct EbpfOpMapLookupElementReply {
    struct EbpfOpHeader header;
    uint8_t value[1];
};

struct EpfOpMapUpdateElementRequest {
    struct EbpfOpHeader header;
    uint64_t handle;
    uint8_t data[1]; // data is key+value
};

struct EbpfOpMapDeleteElementRequest {
    struct EbpfOpHeader header;
    uint64_t handle;
    uint8_t key[1];
};
