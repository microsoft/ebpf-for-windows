// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
// ntifs.h needs to be included ahead of other headers to satisfy the Windows build system.
#include <ntifs.h>

#include <fwpmk.h>

#pragma warning(push)
#pragma warning(disable : 4201) // unnamed struct/union
#include <fwpsk.h>
#pragma warning(pop)