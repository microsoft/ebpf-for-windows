// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// The system headers generate lots of warnings, so disable those around the ntddk.h inclusion.
// TODO(https://github.com/microsoft/usersim/issues/79): move this file to usersim
#pragma warning(push)
#pragma warning(disable : 6387)
#pragma warning(disable : 28160)
#pragma warning(disable : 28230)
#pragma warning(disable : 28252)
#pragma warning(disable : 28253)
#pragma warning(disable : 28285)
#pragma warning(disable : 28301)
#include "../km/ntddk.h"
#pragma warning(pop)
