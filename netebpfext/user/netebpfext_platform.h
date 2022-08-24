// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <ebpf_platform.h>
#include <dpfilter.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <fwpmtypes.h>
#include <fwpstypes.h>
#include <fwpvi.h>
#include <iphlpapi.h>
#include <winnt.h>
#include <netiodef.h>
#include <../km/netioddk.h>

#include "kernel_thunk.h"
#include "ndis_thunk.h"

// Note: fwpsk.h and fwpmk.h depend on NDIS definitions.
// The real NDIS definitions collide with Win32 headers and hence we need to first
// include the "ndis_thunk.h" before including the kernel mode FW headers.
#include <../km/fwpsk.h>
#include <../km/fwpmk.h>
