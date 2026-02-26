// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "analysis_engine.hpp"
#include "api_common.hpp"
#include "ebpf_api.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

#ifdef _WIN32
#include <ElfWrapper.h>
#endif

namespace prevail_mcp {

AnalysisEngine::AnalysisEngine(const prevail::ebpf_platform_t* platform, size_t max_cache_size)
    : platform_(platform), max_cache_size_(max_cache_size)
{
}

std::string
AnalysisEngine::make_cache_key(
    const std::string& elf_path, const std::string& section, const std::string& program, const std::string& type) const
{
    return elf_path + "|" + section + "|" + program + "|" + type;
}

void
AnalysisEngine::evict_if_full()
{
    while (cache_.size() >= max_cache_size_ && !lru_order_.empty()) {
        const std::string& oldest_key = lru_order_.back();
        cache_.erase(oldest_key);
        lru_order_.pop_back();
    }
}

void
AnalysisEngine::invalidate(const std::string& elf_path)
{
    auto it = cache_.begin();
    while (it != cache_.end()) {
        if (it->second.elf_path == elf_path) {
            lru_order_.remove(it->first);
            it = cache_.erase(it);
        } else {
            ++it;
        }
    }
}

static std::string
load_file(const std::string& path)
{
    std::ifstream stream(path, std::ios::in | std::ios::binary);
    if (!stream) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    return std::string((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
}

std::vector<ProgramEntry>
AnalysisEngine::list_programs(const std::string& elf_path)
{
    std::string data = load_file(elf_path);

#ifdef _WIN32
    // ElfCheckElf takes non-const uint8_t* despite not modifying the data.
    if (!ElfCheckElf(
            data.size(),
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(data.data())),
            static_cast<uint32_t>(data.size()))) {
        throw std::runtime_error("ELF file is malformed: " + elf_path);
    }
#endif

    ebpf_api_program_info_t* infos = nullptr;
    const char* error_message = nullptr;
    ebpf_result_t result = ebpf_enumerate_programs(elf_path.c_str(), false, &infos, &error_message);
    if (result != EBPF_SUCCESS) {
        std::string err = error_message ? error_message : "Unknown error";
        ebpf_free_string(error_message);
        throw std::runtime_error("Failed to enumerate programs: " + err);
    }

    std::vector<ProgramEntry> entries;
    for (const ebpf_api_program_info_t* p = infos; p != nullptr; p = p->next) {
        entries.push_back({p->section_name ? p->section_name : "", p->program_name ? p->program_name : ""});
    }
    ebpf_free_programs(infos);
    return entries;
}

const AnalysisSession&
AnalysisEngine::analyze(
    const std::string& elf_path, const std::string& section, const std::string& program, const std::string& type)
{
    const std::string key = make_cache_key(elf_path, section, program, type);

    // Check cache.
    auto cached = cache_.find(key);
    if (cached != cache_.end()) {
        auto current_mtime = std::filesystem::last_write_time(elf_path);
        if (current_mtime == cached->second.file_mtime) {
            lru_order_.remove(key);
            lru_order_.push_front(key);
            return cached->second;
        }
        lru_order_.remove(key);
        cache_.erase(cached);
    }

    evict_if_full();

    // Follow bpf2c's _verify_program_from_string + _ebpf_api_elf_verify_program_from_stream
    // pattern as a single pass, but retain the AnalysisResult for MCP queries.

    // Step 1: Load and validate ELF.
    std::string data = load_file(elf_path);

#ifdef _WIN32
    // ElfCheckElf takes non-const uint8_t* despite not modifying the data.
    if (!ElfCheckElf(
            data.size(),
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(data.data())),
            static_cast<uint32_t>(data.size()))) {
        throw std::runtime_error("ELF file is malformed: " + elf_path);
    }
#endif

    // Step 2: Clear TLS and set program type (same as _verify_program_from_string).
    ebpf_clear_thread_local_storage();
    set_global_program_and_attach_type(nullptr, nullptr);

    // Step 2b: If a type override was given, resolve and set it (same as bpf2c --type).
    ebpf_program_type_t type_override{};
    ebpf_attach_type_t attach_override{};
    bool type_override_set = false;
    if (!type.empty()) {
        if (ebpf_get_program_type_by_name(type.c_str(), &type_override, &attach_override) != EBPF_SUCCESS) {
            throw std::runtime_error("Unknown program type: " + type);
        }
        set_global_program_and_attach_type(&type_override, &attach_override);
        type_override_set = true;
    }

    // Step 3: Determine target program using the C API (same as bpf2c).
    std::string target_section = section;
    std::string target_program = program;
    if (target_section.empty() && target_program.empty()) {
        auto entries = list_programs(elf_path);
        // Prefer a program with a non-.text section (entry point) over .text (callee).
        for (const auto& entry : entries) {
            if (entry.section != ".text") {
                target_section = entry.section;
                target_program = entry.function;
                break;
            }
        }
        if (target_section.empty() && !entries.empty()) {
            target_section = entries.front().section;
            target_program = entries.front().function;
        }
    }

    // Step 4: read_elf → unmarshal → analyze (mirrors _ebpf_api_elf_verify_program_from_stream
    // but calls analyze() directly instead of ebpf_verify_program() to retain the AnalysisResult).
    // If this fails (e.g. unrecognized program type), fall back to the C API for a clean error.
    try {

        prevail::ThreadLocalGuard tls_guard;

        prevail::ebpf_verifier_options_t options = ebpf_get_default_verifier_options();
        options.cfg_opts.check_for_termination = true;
        options.verbosity_opts.print_failures = true;
        options.verbosity_opts.print_line_info = true;

        std::istringstream input_stream(data);
        auto raw_progs = prevail::read_elf(input_stream, elf_path, target_section, std::string(), options, platform_);

        // Find the target program (same logic as _ebpf_api_elf_verify_program_from_stream).
        prevail::RawProgram* found = nullptr;
        for (auto& rp : raw_progs) {
            if (target_program.empty() || rp.function_name == target_program) {
                found = &rp;
                break;
            }
        }
        if (!found) {
            throw std::runtime_error("Program not found: " + target_program + " in " + elf_path);
        }

        // Unmarshal.
        std::vector<std::vector<std::string>> notes;
        auto prog_or_error = prevail::unmarshal(*found, notes, options);
        if (auto* err = std::get_if<std::string>(&prog_or_error)) {
            throw std::runtime_error("Unmarshal error: " + *err);
        }
        auto& inst_seq = std::get<prevail::InstructionSeq>(prog_or_error);

        // Build CFG + analyze (single pass).
        prevail::Program prog = prevail::Program::from_sequence(inst_seq, found->info, options);
        prevail::AnalysisResult result = prevail::analyze(prog);

        // Build session with serialized invariants (while TLS is alive).
        AnalysisSession session;
        session.elf_path = elf_path;
        session.section = found->section_name;
        session.program_name = found->function_name;
        session.inst_seq = std::move(inst_seq);
        session.program = std::move(prog);
        session.failed = result.failed;
        session.max_loop_count = result.max_loop_count;
        session.exit_value = result.exit_value;
        session.file_mtime = std::filesystem::last_write_time(elf_path);

        for (const auto& [label, inv_pair] : result.invariants) {
            AnalysisSession::SerializedInvariant si;
            si.pre_is_bottom = inv_pair.pre.is_bottom();
            try {
                if (!si.pre_is_bottom) {
                    si.pre = inv_pair.pre.to_set();
                }
                if (!inv_pair.post.is_bottom()) {
                    si.post = inv_pair.post.to_set();
                }
            } catch (const std::exception& e) {
                std::cerr << "prevail_mcp: warning: failed to serialize invariant at label " << label.from << ": "
                          << e.what() << std::endl;
            }
            if (inv_pair.error.has_value()) {
                si.error_message = inv_pair.error->what();
                si.error_label = inv_pair.error->where;
            }
            session.invariants.emplace(label, std::move(si));
        }

        // Build source maps from BTF line info.
        int pc = 0;
        for (const auto& [label, inst, line_info] : session.inst_seq) {
            if (line_info.has_value()) {
                session.pc_to_source[pc] = *line_info;
                auto src_key = std::make_pair(line_info->file_name, static_cast<int>(line_info->line_number));
                session.source_to_pcs[src_key].push_back(pc);
            }
            pc += prevail::size(inst);
        }

        // Build PC → Label lookup.
        for (const auto& [label, inv] : session.invariants) {
            session.pc_to_labels[label.from].push_back(label);
        }

        auto [it, inserted] = cache_.emplace(key, std::move(session));
        lru_order_.push_front(key);
        return it->second;

    } catch (...) {
        // Direct analysis failed (bad program type, access violation, etc.).
        // Fall back to the C API to get a clean error message, matching bpf2c's behavior.
        ebpf_clear_thread_local_storage();
        const char* report = nullptr;
        const char* error_msg = nullptr;
        ebpf_api_verifier_stats_t stats{};

        uint32_t verify_result = ebpf_api_elf_verify_program_from_memory(
            data.c_str(),
            data.size(),
            target_section.empty() ? nullptr : target_section.c_str(),
            target_program.empty() ? nullptr : target_program.c_str(),
            type_override_set ? &type_override : nullptr,
            EBPF_VERIFICATION_VERBOSITY_NORMAL,
            &report,
            &error_msg,
            &stats);

        std::string fallback_error = "Analysis failed";
        if (error_msg) {
            fallback_error = error_msg;
        }
        ebpf_free_string(error_msg);
        ebpf_free_string(report);

        if (verify_result != 0) {
            throw std::runtime_error(fallback_error);
        }
        // C API passed but direct analysis crashed — shouldn't happen, but report it.
        throw std::runtime_error("Analysis crashed unexpectedly for " + elf_path);
    }
}

// ─── Live session for check_constraint ─────────────────────────────────────────

void
AnalysisEngine::run_live_analysis(
    const std::string& cache_key,
    const std::string& elf_path,
    const std::string& section,
    const std::string& program,
    const std::string& type)
{
    // Tear down any existing live session (destroys TLS guard).
    live_session_.reset();

    ebpf_clear_thread_local_storage();
    set_global_program_and_attach_type(nullptr, nullptr);

    if (!type.empty()) {
        ebpf_program_type_t type_override{};
        ebpf_attach_type_t attach_override{};
        if (ebpf_get_program_type_by_name(type.c_str(), &type_override, &attach_override) != EBPF_SUCCESS) {
            throw std::runtime_error("Unknown program type: " + type);
        }
        set_global_program_and_attach_type(&type_override, &attach_override);
    }

    auto live = std::make_unique<LiveSession>();
    live->cache_key = cache_key;
    live->tls_guard = std::make_unique<prevail::ThreadLocalGuard>();

    prevail::ebpf_verifier_options_t options = ebpf_get_default_verifier_options();
    options.cfg_opts.check_for_termination = true;
    options.verbosity_opts.print_failures = true;

    std::string data = load_file(elf_path);
    std::istringstream input_stream(data);

    // Determine target section/program.
    std::string target_section = section;
    std::string target_program = program;
    if (target_section.empty() && target_program.empty()) {
        auto entries = list_programs(elf_path);
        for (const auto& entry : entries) {
            if (entry.section != ".text") {
                target_section = entry.section;
                target_program = entry.function;
                break;
            }
        }
        if (target_section.empty() && !entries.empty()) {
            target_section = entries.front().section;
            target_program = entries.front().function;
        }
    }

    auto raw_progs = prevail::read_elf(input_stream, elf_path, target_section, std::string(), options, platform_);
    if (raw_progs.empty()) {
        throw std::runtime_error("No programs found in " + elf_path);
    }

    prevail::RawProgram* found_prog = nullptr;
    for (auto& rp : raw_progs) {
        if (target_program.empty() || rp.function_name == target_program) {
            found_prog = &rp;
            break;
        }
    }
    if (!found_prog) {
        throw std::runtime_error("Program not found: " + target_program);
    }

    auto prog_or_error = prevail::unmarshal(*found_prog, options);
    if (auto* err = std::get_if<std::string>(&prog_or_error)) {
        throw std::runtime_error("Unmarshal error: " + *err);
    }
    auto& inst_seq = std::get<prevail::InstructionSeq>(prog_or_error);
    auto prog = prevail::Program::from_sequence(inst_seq, found_prog->info, options);
    live->result = prevail::analyze(prog);

    live_session_ = std::move(live);
}

prevail::ObservationCheckResult
AnalysisEngine::check_constraint(
    const std::string& elf_path,
    const std::string& section,
    const std::string& program,
    const std::string& type,
    const prevail::Label& label,
    prevail::InvariantPoint point,
    const prevail::StringInvariant& observation,
    const std::string& mode_str)
{
    const std::string key = make_cache_key(elf_path, section, program, type);

    // Reuse live session if it matches.
    if (!live_session_ || live_session_->cache_key != key) {
        run_live_analysis(key, elf_path, section, program, type);
    }

    if (mode_str == "proven") {
        // "proven" mode: check if invariant implies observation (A ⊑ C).
        // This is handled in the MCP layer by directly comparing EbpfDomain objects.
        auto it = live_session_->result.invariants.find(label);
        if (it == live_session_->result.invariants.end()) {
            return {.ok = false, .message = "No invariant available for label"};
        }
        const auto& abstract_state = (point == prevail::InvariantPoint::post) ? it->second.post : it->second.pre;
        if (abstract_state.is_bottom()) {
            return {.ok = false, .message = "Invariant at label is bottom (unreachable)"};
        }

        // Build observed EbpfDomain from constraint strings.
        const auto observed_state = observation.is_bottom()
                                        ? prevail::EbpfDomain::bottom()
                                        : prevail::EbpfDomain::from_constraints(
                                              observation.value(), prevail::thread_local_options.setup_constraints);
        if (observed_state.is_bottom()) {
            return {.ok = false, .message = "Observation constraints are unsatisfiable"};
        }

        if (abstract_state <= observed_state) {
            return {.ok = true, .message = ""};
        }
        return {
            .ok = false,
            .message = "Invariant does not prove the constraint (A ⊑ C is false). "
                       "The verifier's state includes possibilities outside the observation."};
    }

    // Delegate consistent/entailed to PREVAIL.
    auto mode =
        (mode_str == "entailed") ? prevail::ObservationCheckMode::entailed : prevail::ObservationCheckMode::consistent;
    return live_session_->result.check_observation_at_label(label, point, observation, mode);
}

prevail::StringInvariant
AnalysisEngine::get_live_invariant(const prevail::Label& label, prevail::InvariantPoint point) const
{
    if (!live_session_) {
        return prevail::StringInvariant::bottom();
    }
    auto it = live_session_->result.invariants.find(label);
    if (it == live_session_->result.invariants.end()) {
        return prevail::StringInvariant::bottom();
    }
    const auto& abstract_state = (point == prevail::InvariantPoint::post) ? it->second.post : it->second.pre;
    if (abstract_state.is_bottom()) {
        return prevail::StringInvariant::bottom();
    }
    return abstract_state.to_set();
}

} // namespace prevail_mcp
