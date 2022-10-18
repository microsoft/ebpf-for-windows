// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <ebpf_platform.h>

#include <dpfilter.h>
#include <fwpmtypes.h>
#include <fwpstypes.h>
#include <fwpvi.h>
#include <ndis.h>
#include <netiodef.h>
// Note: iphlpapi.h requires ws2def.h and ws2ipdef.h.
#include <ws2def.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <winnt.h>

#include <../km/fwpsk.h>
#include <../km/fwpmk.h>
#include <../km/netioddk.h>
