// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_store_helper.h"
#include "user\ebpf_registry_helper_um.h"

#ifdef USER_MODE
#include <winreg.h>
#endif

// Include the same C code as CPP
#include "ebpf_store_helper.c"