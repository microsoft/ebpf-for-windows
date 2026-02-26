// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "json_serializers.hpp"

#include <sstream>

namespace prevail_mcp {

nlohmann::json
label_to_json(const prevail::Label& label)
{
    nlohmann::json j;
    j["from"] = label.from;
    j["to"] = label.to;
    if (!label.stack_frame_prefix.empty()) {
        j["stack_frame_prefix"] = label.stack_frame_prefix;
    }
    if (!label.special_label.empty()) {
        j["special_label"] = label.special_label;
    }
    return j;
}

nlohmann::json
invariant_to_json(const prevail::StringInvariant& inv)
{
    if (inv.is_bottom()) {
        return nlohmann::json::array({"_|_"});
    }
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& s : inv.value()) {
        arr.push_back(s);
    }
    return arr;
}

nlohmann::json
error_to_json(const prevail::VerificationError& error)
{
    nlohmann::json j;
    if (error.where.has_value()) {
        j["label"] = label_to_json(*error.where);
        j["pc"] = error.where->from;
    }
    j["message"] = error.what();
    return j;
}

nlohmann::json
instruction_to_json(const prevail::Instruction& inst)
{
    std::ostringstream os;
    os << inst;
    return nlohmann::json{{"text", os.str()}};
}

nlohmann::json
assertion_to_json(const prevail::Assertion& assertion)
{
    std::ostringstream os;
    os << assertion;
    return nlohmann::json{{"text", os.str()}};
}

nlohmann::json
line_info_to_json(const prevail::btf_line_info_t& info)
{
    return {
        {"file", info.file_name},
        {"line", info.line_number},
        {"column", info.column_number},
        {"source", info.source_line},
    };
}

nlohmann::json
interval_to_json(const prevail::Interval& interval)
{
    std::ostringstream os;
    os << interval;
    return nlohmann::json{{"text", os.str()}};
}

} // namespace prevail_mcp
