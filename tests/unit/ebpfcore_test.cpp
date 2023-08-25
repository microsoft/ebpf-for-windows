// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "catch_wrapper.hpp"

TEST_CASE("DriverEntry", "[usersim]")
{
    HMODULE module = LoadLibraryW(L"ebpfcore_usersim.dll");
    REQUIRE(module != nullptr);

    FreeLibrary(module);
}