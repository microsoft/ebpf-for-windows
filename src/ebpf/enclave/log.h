/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/
#pragma once

#define MAX_LOG_MESSAGE_SIZE 128
typedef enum {
    error,
    warning,
    info,
    verbose
} log_level;
void ebpf_enclave_log(log_level level, const char* format, ...);
