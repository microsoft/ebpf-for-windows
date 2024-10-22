// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "usersim/../../src/net_platform.h"

#define WFP_ERROR(status, error) ((status) == (FWP_E_##error))