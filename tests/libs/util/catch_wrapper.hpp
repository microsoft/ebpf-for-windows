// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#pragma warning(push)
#pragma warning(disable : 26451) // Arithmetic overflow
#pragma warning(disable : 26450) // Arithmetic overflow
#pragma warning(disable : 26439) // This kind of function may not throw. Declare it 'noexcept'
#pragma warning(disable : 26495) // Always initialize a member variable
#pragma warning(disable : 26812) // Prefer 'enum class' over 'enum'
#pragma warning(disable : 26816) // The pointer points to memory allocated on the stack

#define CATCH_CONFIG_COLOUR_NONE 1 // Disable color until https://github.com/catchorg/Catch2/issues/2345 is fixed.
#undef max
#undef min
#if defined(NUGET_CATCH)
#include "catch2/catch.hpp"
#else
#include "catch2/catch_all.hpp"
#endif
#pragma warning(pop)

#include "wer_report.hpp"
