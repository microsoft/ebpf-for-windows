// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <rpc.h>
#include "rpc_interface_h.h"

RPC_STATUS
initialize_rpc_binding(void);

RPC_STATUS
clean_up_rpc_binding(void);

int
ebpf_rpc_verify_program(ebpf_program_verify_info* info, const char** logs, uint32_t* logs_size);
