// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include "net_ebpf_ext.h"

/**
 * @brief Unregister PROCESS NPI providers.
 *
 */
void
net_ebpf_ext_process_unregister_providers();

/**
 * @brief Register PROCESS NPI providers.
 *
 * @retval STATUS_SUCCESS Operation succeeded.
 * @retval STATUS_UNSUCCESSFUL Operation failed.
 */
NTSTATUS
net_ebpf_ext_process_register_providers();
