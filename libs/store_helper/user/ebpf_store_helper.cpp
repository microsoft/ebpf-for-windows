// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifdef USER_MODE
#include <windows.h>
#endif

#include "ebpf_store_helper.h"
#include "user\ebpf_registry_helper_um.h"

// Include the same C code as CPP
#include "ebpf_store_helper.c"