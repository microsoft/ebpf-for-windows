// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

/// @file JSON serializers for PREVAIL verifier data structures.
/// All serialization delegates to PREVAIL's own operator<< / to_string().

#include "prevail_headers.hpp"

#include <nlohmann/json.hpp>

namespace prevail_mcp {

nlohmann::json
label_to_json(const prevail::Label& label);
nlohmann::json
invariant_to_json(const prevail::StringInvariant& inv);
nlohmann::json
error_to_json(const prevail::VerificationError& error);
nlohmann::json
instruction_to_json(const prevail::Instruction& inst);
nlohmann::json
assertion_to_json(const prevail::Assertion& assertion);
nlohmann::json
line_info_to_json(const prevail::btf_line_info_t& info);
nlohmann::json
interval_to_json(const prevail::Interval& interval);

} // namespace prevail_mcp
