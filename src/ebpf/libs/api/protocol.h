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
