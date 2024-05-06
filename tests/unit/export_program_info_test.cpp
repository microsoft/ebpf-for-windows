// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "catch_wrapper.hpp"
#include "export_program_info.cpp"

static void
_populate_ebpf_store()
{
    REQUIRE(export_all_program_information() == 0);
    REQUIRE(export_all_section_information() == 0);
    REQUIRE(export_global_helper_information() == 0);
}

TEST_CASE("export_program_info", "[end_to_end]")
{
    REQUIRE(clear_ebpf_store() == 0);

    // Re-populate the ebpf store.
    _populate_ebpf_store();
}
