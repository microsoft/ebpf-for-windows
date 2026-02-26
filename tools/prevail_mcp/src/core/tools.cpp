// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_common.hpp"
#include "ebpf_api.h"
#include "json_serializers.hpp"
#include "tools.hpp"

#include <algorithm>
#include <fstream>
#include <set>
#include <sstream>

using json = nlohmann::json;

namespace prevail_mcp {

// Helper: find the primary label for a given PC in the analysis session.
// Returns the first label with .to == -1 (sequential flow), or the first available label.
static prevail::Label
find_label_for_pc(const AnalysisSession& session, int pc)
{
    auto it = session.pc_to_labels.find(pc);
    if (it == session.pc_to_labels.end() || it->second.empty()) {
        throw std::runtime_error("No label found for PC " + std::to_string(pc));
    }
    // Prefer the sequential (non-jump) label.
    for (const auto& label : it->second) {
        if (label.to == -1) {
            return label;
        }
    }
    return it->second.front();
}

// Helper: get all labels for a PC (may include jump edge labels).
static const std::vector<prevail::Label>&
find_labels_for_pc(const AnalysisSession& session, int pc)
{
    auto it = session.pc_to_labels.find(pc);
    if (it == session.pc_to_labels.end()) {
        static const std::vector<prevail::Label> empty;
        return empty;
    }
    return it->second;
}

// ─── Tool: list_programs ───────────────────────────────────────────────────────

static json
handle_list_programs(const json& args, AnalysisEngine& engine)
{
    const std::string elf_path = args.at("elf_path").get<std::string>();
    auto entries = engine.list_programs(elf_path);

    json programs = json::array();
    for (const auto& entry : entries) {
        programs.push_back({
            {"section", entry.section},
            {"function", entry.function},
        });
    }
    return {{"programs", programs}};
}

// ─── Tool: verify_program ──────────────────────────────────────────────────────

static json
handle_verify_program(const json& args, AnalysisEngine& engine)
{
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");

    const auto& session = engine.analyze(elf_path, section, program, type);

    // Count errors.
    int error_count = 0;
    for (const auto& [label, inv_pair] : session.invariants) {
        if (!inv_pair.pre_is_bottom && inv_pair.error_message.has_value()) {
            error_count++;
        }
    }

    // Count unreachable: post is bottom and instruction is Assume with no error.
    int total_unreachable = 0;
    for (const auto& [label, inv_pair] : session.invariants) {
        if (inv_pair.pre_is_bottom) {
            continue;
        }
        if (inv_pair.post.is_bottom() && !inv_pair.error_message.has_value()) {
            if (std::get_if<prevail::Assume>(&session.program.instruction_at(label))) {
                total_unreachable++;
            }
        }
    }

    json j = {
        {"passed", !session.failed},
        {"max_loop_count", session.max_loop_count},
        {"exit_value", interval_to_json(session.exit_value)},
        {"error_count", error_count},
        {"total_unreachable", total_unreachable},
        {"instruction_count", static_cast<int>(session.inst_seq.size())},
        {"section", session.section},
        {"function", session.program_name},
    };

    // Scan invariants for first error.
    for (const auto& [label, inv_pair] : session.invariants) {
        if (!inv_pair.pre_is_bottom && inv_pair.error_message.has_value()) {
            json fe;
            if (inv_pair.error_label.has_value()) {
                fe["label"] = label_to_json(*inv_pair.error_label);
                fe["pc"] = inv_pair.error_label->from;
            }
            fe["message"] = *inv_pair.error_message;
            // Add source mapping if available.
            if (inv_pair.error_label.has_value()) {
                auto src_it = session.pc_to_source.find(inv_pair.error_label->from);
                if (src_it != session.pc_to_source.end()) {
                    fe["source"] = line_info_to_json(src_it->second);
                }
            }
            j["first_error"] = fe;
            break;
        }
    }

    return j;
}

// ─── Tool: get_invariant ───────────────────────────────────────────────────────

static json
handle_get_invariant(const json& args, AnalysisEngine& engine)
{
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string point_str = args.value("point", "pre");
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");

    const auto& session = engine.analyze(elf_path, section, program, type);
    const auto pcs = args.at("pcs").get<std::vector<int>>();

    // Helper: get invariant results for a single PC.
    auto get_invariant_for_pc = [&](int pc) -> json {
        const auto& labels = find_labels_for_pc(session, pc);
        if (labels.empty()) {
            return {{"pc", pc}, {"error", "No label found for PC " + std::to_string(pc)}};
        }

        json results = json::array();
        for (const auto& label : labels) {
            auto inv_it = session.invariants.find(label);
            if (inv_it == session.invariants.end()) {
                continue;
            }
            const auto& inv_pair = inv_it->second;
            const auto& domain = (point_str == "post") ? inv_pair.post : inv_pair.pre;

            json entry = {
                {"label", label_to_json(label)},
                {"point", point_str},
                {"constraints", invariant_to_json(domain)},
            };
            results.push_back(entry);
        }

        if (results.size() == 1) {
            return results[0];
        }
        return {{"pc", pc}, {"labels", results}};
    };

    if (pcs.size() == 1) {
        return get_invariant_for_pc(pcs[0]);
    }

    json batch_results = json::array();
    for (int pc : pcs) {
        json result = get_invariant_for_pc(pc);
        result["pc"] = pc;
        batch_results.push_back(result);
    }
    return {{"results", batch_results}};
}

// ─── Tool: get_instruction ─────────────────────────────────────────────────────

static json
handle_get_instruction(const json& args, AnalysisEngine& engine)
{
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");

    const auto& session = engine.analyze(elf_path, section, program, type);

    const auto pcs = args.at("pcs").get<std::vector<int>>();

    // Helper: get instruction detail for a single PC.
    auto get_instruction_for_pc = [&](int pc) -> json {
        const auto label = find_label_for_pc(session, pc);
        json j = {{"pc", pc}, {"label", label_to_json(label)}};

        // Instruction text.
        j["text"] = instruction_to_json(session.program.instruction_at(label))["text"];

        // Assertions.
        json assertions = json::array();
        for (const auto& a : session.program.assertions_at(label)) {
            assertions.push_back(assertion_to_json(a)["text"]);
        }
        j["assertions"] = assertions;

        // Invariants.
        auto inv_it = session.invariants.find(label);
        if (inv_it != session.invariants.end()) {
            j["pre_invariant"] = invariant_to_json(inv_it->second.pre);
            if (!inv_it->second.post.is_bottom()) {
                j["post_invariant"] = invariant_to_json(inv_it->second.post);
            } else {
                j["post_invariant"] = nullptr;
            }
            if (inv_it->second.error_message.has_value()) {
                j["error"] = *inv_it->second.error_message;
            }
        }

        // Source mapping.
        auto src_it = session.pc_to_source.find(pc);
        if (src_it != session.pc_to_source.end()) {
            j["source"] = line_info_to_json(src_it->second);
        }

        // CFG neighbors.
        json successors = json::array();
        for (const auto& child : session.program.cfg().children_of(label)) {
            successors.push_back(child.from);
        }
        j["successors"] = successors;

        json predecessors = json::array();
        for (const auto& parent : session.program.cfg().parents_of(label)) {
            predecessors.push_back(parent.from);
        }
        j["predecessors"] = predecessors;

        return j;
    };

    // Build results, returning structured errors for invalid PCs.
    json batch_results = json::array();
    for (int pc : pcs) {
        try {
            batch_results.push_back(get_instruction_for_pc(pc));
        } catch (const std::runtime_error& e) {
            batch_results.push_back({{"pc", pc}, {"error", e.what()}});
        }
    }
    return {{"results", batch_results}};
}

// ─── Tool: get_errors ──────────────────────────────────────────────────────────

static json
handle_get_errors(const json& args, AnalysisEngine& engine)
{
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");

    const auto& session = engine.analyze(elf_path, section, program, type);

    json errors = json::array();
    for (const auto& [label, inv_pair] : session.invariants) {
        if (inv_pair.pre_is_bottom) {
            continue;
        }
        if (inv_pair.error_message.has_value()) {
            json e;
            if (inv_pair.error_label.has_value()) {
                e["label"] = label_to_json(*inv_pair.error_label);
                e["pc"] = inv_pair.error_label->from;
            }
            e["message"] = *inv_pair.error_message;
            e["pre_invariant"] = invariant_to_json(inv_pair.pre);
            e["instruction"] = instruction_to_json(session.program.instruction_at(label))["text"];

            auto src_it = session.pc_to_source.find(label.from);
            if (src_it != session.pc_to_source.end()) {
                e["source"] = line_info_to_json(src_it->second);
            }
            errors.push_back(e);
        }
    }

    json unreachable = json::array();
    for (const auto& [label, inv_pair] : session.invariants) {
        if (inv_pair.pre_is_bottom) {
            continue;
        }
        if (inv_pair.post.is_bottom() && !inv_pair.error_message.has_value()) {
            if (const auto passume = std::get_if<prevail::Assume>(&session.program.instruction_at(label))) {
                std::string msg =
                    prevail::to_string(label) + ": Code becomes unreachable (" + prevail::to_string(*passume) + ")";
                unreachable.push_back({{"label", label_to_json(label)}, {"message", msg}});
            }
        }
    }

    return {
        {"passed", !session.failed},
        {"errors", errors},
        {"unreachable", unreachable},
    };
}

// ─── Tool: get_cfg ─────────────────────────────────────────────────────────────

static json
handle_get_cfg(const json& args, AnalysisEngine& engine)
{
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string format = args.value("format", "json");
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");

    const auto& session = engine.analyze(elf_path, section, program, type);

    if (format == "dot") {
        // Generate DOT format inline (same logic as print_dot in printing.cpp).
        std::ostringstream dot;
        dot << "digraph program {\n";
        dot << "    node [shape = rectangle];\n";
        for (const auto& label : session.program.labels()) {
            dot << "    \"" << label << "\"[label=\"";
            for (const auto& pre : session.program.assertions_at(label)) {
                dot << "assert " << pre << "\\l";
            }
            dot << session.program.instruction_at(label) << "\\l";
            dot << "\"];\n";
            for (const auto& next : session.program.cfg().children_of(label)) {
                dot << "    \"" << label << "\" -> \"" << next << "\";\n";
            }
            dot << "\n";
        }
        dot << "}\n";
        return {{"format", "dot"}, {"dot", dot.str()}};
    }

    // JSON mode: serialize basic blocks.
    auto basic_blocks = prevail::BasicBlock::collect_basic_blocks(session.program.cfg(), true);
    json blocks = json::array();
    for (const auto& bb : basic_blocks) {
        json block;
        block["first_pc"] = bb.first_label().from;
        block["last_pc"] = bb.last_label().from;

        json pcs = json::array();
        for (const auto& label : bb) {
            pcs.push_back(label.from);
        }
        block["pcs"] = pcs;

        json succs = json::array();
        for (const auto& child : session.program.cfg().children_of(bb.last_label())) {
            succs.push_back(child.from);
        }
        block["successors"] = succs;

        blocks.push_back(block);
    }

    return {{"format", "json"}, {"basic_blocks", blocks}};
}

// ─── Tool: get_source_mapping ──────────────────────────────────────────────────

static json
handle_get_source_mapping(const json& args, AnalysisEngine& engine)
{
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");

    const auto& session = engine.analyze(elf_path, section, program, type);

    if (args.contains("pc")) {
        const int pc = args["pc"].get<int>();
        auto it = session.pc_to_source.find(pc);
        if (it == session.pc_to_source.end()) {
            return {{"pc", pc}, {"source", nullptr}, {"note", "No BTF line info for this PC"}};
        }
        json j = {{"pc", pc}, {"source", line_info_to_json(it->second)}};
        // Also include instruction text.
        auto labels = find_labels_for_pc(session, pc);
        if (!labels.empty()) {
            j["instruction"] = instruction_to_json(session.program.instruction_at(labels.front()))["text"];
        }
        return j;
    }

    if (args.contains("source_line")) {
        const int source_line = args["source_line"].get<int>();
        const std::string source_file = args.value("source_file", "");

        // Search all source mappings for matching line.
        json matches = json::array();
        for (const auto& [key, pcs] : session.source_to_pcs) {
            if (key.second == source_line &&
                (source_file.empty() || key.first == source_file || key.first.find(source_file) != std::string::npos)) {
                for (int matched_pc : pcs) {
                    json m = {{"pc", matched_pc}};
                    auto labels = find_labels_for_pc(session, matched_pc);
                    if (!labels.empty()) {
                        m["instruction"] = instruction_to_json(session.program.instruction_at(labels.front()))["text"];
                    }
                    auto src_it = session.pc_to_source.find(matched_pc);
                    if (src_it != session.pc_to_source.end()) {
                        m["source"] = line_info_to_json(src_it->second);
                    }
                    matches.push_back(m);
                }
            }
        }
        return {{"source_line", source_line}, {"matches", matches}};
    }

    // Return entire source map.
    if (session.pc_to_source.empty()) {
        return {
            {"note", "No BTF line info available. Compile with -g to enable source mapping."},
            {"entries", json::array()},
        };
    }

    json entries = json::array();
    for (const auto& [pc, info] : session.pc_to_source) {
        entries.push_back({{"pc", pc}, {"source", line_info_to_json(info)}});
    }
    return {{"entries", entries}};
}

// ─── Tool: check_constraint ────────────────────────────────────────────────────

static json
handle_check_constraint(const json& args, AnalysisEngine& engine)
{
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string point_str = args.value("point", "pre");
    const std::string mode_str = args.value("mode", "consistent");
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");

    auto point = (point_str == "post") ? prevail::InvariantPoint::post : prevail::InvariantPoint::pre;

    // Support single-check or batch-check.
    // Single: { "pc": N, "constraints": [...] }
    // Batch:  { "checks": [{ "pc": N, "constraints": [...], "mode": "...", "point": "..." }, ...] }
    struct CheckQuery
    {
        int pc;
        prevail::InvariantPoint pt;
        std::string md;
        std::vector<std::string> constraints;
    };

    std::vector<CheckQuery> queries;

    if (args.contains("checks")) {
        // Batch mode.
        for (const auto& check : args["checks"]) {
            CheckQuery q;
            q.pc = check.at("pc").get<int>();
            q.constraints = check.at("constraints").get<std::vector<std::string>>();
            auto qs = check.value("point", point_str);
            q.pt = (qs == "post") ? prevail::InvariantPoint::post : prevail::InvariantPoint::pre;
            q.md = check.value("mode", mode_str);
            queries.push_back(std::move(q));
        }
    } else {
        // Single mode.
        CheckQuery q;
        q.pc = args.at("pc").get<int>();
        q.constraints = args.at("constraints").get<std::vector<std::string>>();
        q.pt = point;
        q.md = mode_str;
        queries.push_back(std::move(q));
    }

    // Run analysis once (engine caches the live session for reuse across calls).
    // We need the AnalysisSession for label lookup.
    const auto& session = engine.analyze(elf_path, section, program, type);

    // Process all queries against the same analysis.
    json results = json::array();
    for (const auto& q : queries) {
        json entry = {{"pc", q.pc}};
        try {
            auto label = find_label_for_pc(session, q.pc);

            std::set<std::string> constraint_set(q.constraints.begin(), q.constraints.end());
            prevail::StringInvariant observation{std::move(constraint_set)};

            auto check_result =
                engine.check_constraint(elf_path, section, program, type, label, q.pt, observation, q.md);
            entry["ok"] = check_result.ok;
            entry["message"] = check_result.message;

            // Include the invariant so agents can see what the verifier knows.
            auto inv = engine.get_live_invariant(label, q.pt);
            if (!inv.is_bottom()) {
                entry["invariant"] = invariant_to_json(inv);
            }
        } catch (const std::runtime_error& e) {
            entry["ok"] = false;
            entry["message"] = e.what();
        }
        results.push_back(std::move(entry));
    }

    // Single-query returns the result directly; batch returns array.
    if (!args.contains("checks") && results.size() == 1) {
        return results[0];
    }
    return {{"results", results}};
}

// ─── Tool: get_error_context ───────────────────────────────────────────────────

// Helper: build a backward trace from a given label.
static json
build_backward_trace(const AnalysisSession& session, const prevail::Label& start_label, int trace_depth)
{
    json backward_trace = json::array();
    std::set<prevail::Label> visited;
    prevail::Label current = start_label;
    visited.insert(current);

    for (int step = 0; step < trace_depth; step++) {
        const auto& parents = session.program.cfg().parents_of(current);
        if (parents.empty()) {
            break;
        }

        // Prefer sequential parent (non-jump edge) over jump edges.
        prevail::Label best_parent = *parents.begin();
        for (const auto& p : parents) {
            if (p.to == -1 && !visited.contains(p)) {
                best_parent = p;
                break;
            }
        }
        if (visited.contains(best_parent)) {
            break;
        }
        visited.insert(best_parent);

        json trace_step = {
            {"pc", best_parent.from},
            {"text", instruction_to_json(session.program.instruction_at(best_parent))["text"]},
        };

        auto inv_it = session.invariants.find(best_parent);
        if (inv_it != session.invariants.end() && !inv_it->second.post.is_bottom()) {
            trace_step["post_invariant"] = invariant_to_json(inv_it->second.post);
        }

        auto trace_src = session.pc_to_source.find(best_parent.from);
        if (trace_src != session.pc_to_source.end()) {
            trace_step["source"] = line_info_to_json(trace_src->second);
        }

        backward_trace.push_back(trace_step);
        current = best_parent;
    }

    std::reverse(backward_trace.begin(), backward_trace.end());
    return backward_trace;
}

static json
handle_get_error_context(const json& args, AnalysisEngine& engine)
{
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const int trace_depth = args.value("trace_depth", 10);
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");

    const auto& session = engine.analyze(elf_path, section, program, type);

    prevail::Label target_label = prevail::Label::entry;

    // Support two modes: by error_index (default) or by explicit pc.
    if (args.contains("pc")) {
        // Trace backward from a specific PC (not necessarily an error).
        const int pc = args["pc"].get<int>();
        target_label = find_label_for_pc(session, pc);
    } else {
        // Find the Nth error.
        const int error_index = args.value("error_index", 0);
        int idx = 0;
        bool found_error = false;
        for (const auto& [label, inv_pair] : session.invariants) {
            if (inv_pair.pre_is_bottom) {
                continue;
            }
            if (inv_pair.error_message.has_value()) {
                if (idx == error_index) {
                    target_label = label;
                    found_error = true;
                    break;
                }
                idx++;
            }
        }
        if (!found_error) {
            throw std::runtime_error("Error index " + std::to_string(error_index) + " not found");
        }
    }

    // Build the response.
    const auto& inv = session.invariants.at(target_label);

    json j = {{"pc", target_label.from}};
    j["instruction"] = instruction_to_json(session.program.instruction_at(target_label))["text"];
    j["pre_invariant"] = invariant_to_json(inv.pre);

    if (inv.error_message.has_value()) {
        json error_json;
        if (inv.error_label.has_value()) {
            error_json["label"] = label_to_json(*inv.error_label);
            error_json["pc"] = inv.error_label->from;
        }
        error_json["message"] = *inv.error_message;
        j["error"] = error_json;
    }

    // Assertions at this point.
    json assertions = json::array();
    for (const auto& a : session.program.assertions_at(target_label)) {
        assertions.push_back(assertion_to_json(a)["text"]);
    }
    j["assertions"] = assertions;

    // Source mapping.
    auto src_it = session.pc_to_source.find(target_label.from);
    if (src_it != session.pc_to_source.end()) {
        j["source"] = line_info_to_json(src_it->second);
    }

    j["backward_trace"] = build_backward_trace(session, target_label, trace_depth);

    return j;
}

// ─── Tool: get_disassembly ─────────────────────────────────────────────────────

static json
handle_get_disassembly(const json& args, AnalysisEngine& engine)
{
    const std::string elf_path = args.at("elf_path").get<std::string>();
    const std::string section = args.value("section", "");
    const std::string program = args.value("program", "");
    const std::string type = args.value("program_type", "");
    const int from_pc = args.value("from_pc", -1);
    const int to_pc = args.value("to_pc", -1);

    const auto& session = engine.analyze(elf_path, section, program, type);

    json instructions = json::array();
    int pc = 0;
    for (const auto& [label, inst, line_info] : session.inst_seq) {
        if ((from_pc >= 0 && pc < from_pc) || (to_pc >= 0 && pc > to_pc)) {
            pc += prevail::size(inst);
            continue;
        }

        json entry = {{"pc", pc}};
        std::ostringstream os;
        os << inst;
        entry["text"] = os.str();

        if (line_info.has_value()) {
            entry["source"] = line_info_to_json(*line_info);
        }

        instructions.push_back(entry);
        pc += prevail::size(inst);
    }

    return {{"instructions", instructions}, {"count", static_cast<int>(instructions.size())}};
}

// ─── Tool Registration ─────────────────────────────────────────────────────────

void
register_all_tools(McpServer& server, AnalysisEngine& engine)
{
    server.register_tool({
        "list_programs",
        "List all eBPF programs (sections and function names) in an ELF file.",
        {{"type", "object"},
         {"properties", {{"elf_path", {{"type", "string"}, {"description", "Path to .o ELF file"}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_list_programs(args, engine); },
    });

    server.register_tool({
        "verify_program",
        "Verify an eBPF program with the PREVAIL verifier. Returns pass/fail, error summary, and statistics.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}, {"description", "Path to .o ELF file"}}},
           {"section", {{"type", "string"}, {"description", "ELF section name (optional)"}}},
           {"program", {{"type", "string"}, {"description", "Program/function name (optional)"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_verify_program(args, engine); },
    });

    server.register_tool({
        "get_invariant",
        "Get the pre or post invariant (abstract state) at one or more BPF instructions. Shows register types, value "
        "ranges, and all constraints the verifier has proven at that point.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"pcs",
            {{"type", "array"}, {"items", {{"type", "integer"}}}, {"description", "Program counter(s) to query"}}},
           {"point", {{"type", "string"}, {"enum", json::array({"pre", "post"})}, {"default", "pre"}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path", "pcs"})}},
        [&engine](const json& args) { return handle_get_invariant(args, engine); },
    });

    server.register_tool({
        "get_instruction",
        "Get full detail for one or more BPF instructions: disassembly, safety assertions, pre/post invariants, "
        "verification error (if any), source line, and CFG neighbors.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"pcs",
            {{"type", "array"}, {"items", {{"type", "integer"}}}, {"description", "Program counter(s) to query"}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path", "pcs"})}},
        [&engine](const json& args) { return handle_get_instruction(args, engine); },
    });

    server.register_tool({
        "get_errors",
        "Get all verification errors with full context: failing instruction, assertion, pre-invariant, and source "
        "line. Also reports unreachable code.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_get_errors(args, engine); },
    });

    server.register_tool({
        "get_cfg",
        "Get the control-flow graph: basic blocks with instruction PCs and edges. Supports JSON or DOT format.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"format", {{"type", "string"}, {"enum", json::array({"json", "dot"})}, {"default", "json"}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_get_cfg(args, engine); },
    });

    server.register_tool({
        "get_source_mapping",
        "Map between C source lines and BPF instructions. Query by PC to find source, by source_line to find BPF "
        "instructions, or omit both to get the full map. Requires ELF compiled with -g.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"pc", {{"type", "integer"}, {"description", "BPF instruction PC to look up"}}},
           {"source_line", {{"type", "integer"}, {"description", "C source line number to look up"}}},
           {"source_file", {{"type", "string"}, {"description", "Source file name filter (optional)"}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_get_source_mapping(args, engine); },
    });

    server.register_tool({
        "check_constraint",
        "Check if constraints are consistent with, entailed by, or proven by the verifier's state at a given "
        "instruction. Use 'consistent' mode to test if constraints are possible (not contradicted by the invariant). "
        "Use 'proven' mode to test if the verifier guarantees the constraints must hold. Use 'entailed' mode only "
        "with near-complete observations. The response includes the invariant at the queried point. "
        "Supports batch mode: pass 'checks' array instead of 'pc'/'constraints' to test multiple hypotheses "
        "in a single call (runs analysis once).",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"pc", {{"type", "integer"}}},
           {"constraints",
            {{"type", "array"}, {"items", {{"type", "string"}}}, {"description", "Constraint strings to check"}}},
           {"checks",
            {{"type", "array"},
             {"description",
              "Batch mode: array of checks to run in a single analysis pass. "
              "Each check has pc, constraints, and optional mode/point overrides."},
             {"items",
              {{"type", "object"},
               {"properties",
                {{"pc", {{"type", "integer"}}},
                 {"constraints", {{"type", "array"}, {"items", {{"type", "string"}}}}},
                 {"mode", {{"type", "string"}, {"enum", json::array({"consistent", "entailed", "proven"})}}},
                 {"point", {{"type", "string"}, {"enum", json::array({"pre", "post"})}}}}},
               {"required", json::array({"pc", "constraints"})}}}}},
           {"point", {{"type", "string"}, {"enum", json::array({"pre", "post"})}, {"default", "pre"}}},
           {"mode",
            {{"type", "string"},
             {"enum", json::array({"consistent", "entailed", "proven"})},
             {"default", "consistent"},
             {"description",
              "consistent: constraints are possible (not contradicted). "
              "proven: verifier guarantees the constraints (invariant implies observation). "
              "entailed: observation is a sub-state of invariant (requires near-complete constraint set)."}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_check_constraint(args, engine); },
    });

    server.register_tool({
        "get_error_context",
        "Get context for a verification error or any instruction: pre-invariant, assertions, source line, and a "
        "backward trace of preceding instructions. Use error_index to examine a specific error, or pc to trace "
        "backward from any instruction.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"error_index",
            {{"type", "integer"}, {"default", 0}, {"description", "Which error to examine (0 = first)"}}},
           {"pc",
            {{"type", "integer"},
             {"description", "Trace backward from this PC instead of an error (overrides error_index)"}}},
           {"trace_depth",
            {{"type", "integer"}, {"default", 10}, {"description", "Number of predecessor instructions to trace"}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_get_error_context(args, engine); },
    });

    server.register_tool({
        "get_disassembly",
        "Get the disassembly listing for a range of instructions. Returns instruction text and source lines. "
        "Use from_pc/to_pc to limit the range, or omit for the full listing.",
        {{"type", "object"},
         {"properties",
          {{"elf_path", {{"type", "string"}}},
           {"from_pc", {{"type", "integer"}, {"description", "Start PC (inclusive, default: 0)"}}},
           {"to_pc", {{"type", "integer"}, {"description", "End PC (inclusive, default: last)"}}},
           {"section", {{"type", "string"}}},
           {"program", {{"type", "string"}}},
           {"program_type",
            {{"type", "string"}, {"description", "Program type name override (e.g. \"xdp\", \"bind\")"}}}}},
         {"required", json::array({"elf_path"})}},
        [&engine](const json& args) { return handle_get_disassembly(args, engine); },
    });
}

} // namespace prevail_mcp
