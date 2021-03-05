/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

/*++

Abstract:

   Header file for structures/prototypes of the driver.


Environment:

    Kernel mode

--*/

#pragma once 
#include "types.h"

//
// Shared function prototypes
//

NTSTATUS
ebpf_hook_register_callouts(
    _Inout_ void* device_object
);

void
ebpf_hook_unregister_callouts(void);


