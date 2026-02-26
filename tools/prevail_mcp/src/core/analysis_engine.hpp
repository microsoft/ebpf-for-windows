// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

/// @file Analysis engine: runs the PREVAIL pipeline and caches results.

#include "prevail_headers.hpp"

#include <filesystem>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace prevail_mcp {

/// Holds all outputs from a single verification run.
/// Invariants are pre-serialized to StringInvariant during analysis because
/// EbpfDomain::to_set() depends on PREVAIL's thread-local variable_registry
/// which is cleared after analysis completes.
struct AnalysisSession
{
    std::string elf_path;
    std::string section;
    std::string program_name;

    // The instruction sequence (labels + instructions + btf_line_info).
    prevail::InstructionSeq inst_seq;

    // The CFG program (for instruction_at, assertions_at, cfg navigation).
    prevail::Program program;

    // Overall result metadata.
    bool failed = false;
    int max_loop_count = 0;
    prevail::Interval exit_value = prevail::Interval::top();

    /// Pre-serialized invariant data per label (serialized while TLS is alive).
    struct SerializedInvariant
    {
        prevail::StringInvariant pre;
        prevail::StringInvariant post;
        std::optional<std::string> error_message;  // VerificationError::what().
        std::optional<prevail::Label> error_label; // VerificationError::where.
        bool pre_is_bottom = false;
    };
    std::map<prevail::Label, SerializedInvariant> invariants;

    // Derived: PC → source line info (built from BTF in InstructionSeq).
    std::map<int, prevail::btf_line_info_t> pc_to_source;

    // Derived: (file, line) → list of PCs.
    std::map<std::pair<std::string, int>, std::vector<int>> source_to_pcs;

    // Derived: PC → labels in the invariant map that have this PC as .from.
    std::map<int, std::vector<prevail::Label>> pc_to_labels;

    // File modification time at analysis time (for cache invalidation).
    std::filesystem::file_time_type file_mtime;
};

/// Entry in the program list returned by AnalysisEngine::list_programs().
struct ProgramEntry
{
    std::string section;
    std::string function;
};

/// Holds a live AnalysisResult with EbpfDomain objects that can be used for
/// check_constraint without re-running analysis. The TLS guard keeps the
/// thread-local variable_registry alive so EbpfDomain operations work.
struct LiveSession
{
    std::string cache_key;
    std::unique_ptr<prevail::ThreadLocalGuard> tls_guard;
    prevail::AnalysisResult result;
};

/// Runs the PREVAIL pipeline and caches results.
class AnalysisEngine
{
  public:
    explicit AnalysisEngine(const prevail::ebpf_platform_t* platform, size_t max_cache_size = 8);

    /// Run analysis on the given ELF file (or return cached result).
    /// Follows bpf2c's pattern: ElfCheckElf → read_elf → unmarshal → analyze,
    /// with fallback to ebpf_api_elf_verify_program_from_memory for clean error messages.
    /// @param type  Optional program type name override (e.g. "xdp", "bind").
    ///              When set, overrides the type inferred from the ELF section name.
    /// @throws std::runtime_error on ELF parse, unmarshal, or analysis failure.
    const AnalysisSession&
    analyze(
        const std::string& elf_path,
        const std::string& section = "",
        const std::string& program = "",
        const std::string& type = "");

    /// Check constraints against a live AnalysisResult, reusing the cached live session
    /// when the same program was recently analyzed. Avoids re-running the full pipeline.
    /// @param mode_str  "consistent", "entailed", or "proven". The "proven" mode (A ⊑ C)
    ///                  is implemented here in the MCP layer using EbpfDomain::operator<=.
    prevail::ObservationCheckResult
    check_constraint(
        const std::string& elf_path,
        const std::string& section,
        const std::string& program,
        const std::string& type,
        const prevail::Label& label,
        prevail::InvariantPoint point,
        const prevail::StringInvariant& observation,
        const std::string& mode_str);

    /// Get the serialized invariant at a label from the live session (if available).
    /// Returns empty StringInvariant if no live session or label not found.
    prevail::StringInvariant
    get_live_invariant(const prevail::Label& label, prevail::InvariantPoint point) const;

    /// List all programs in an ELF file using ebpf_enumerate_programs (same as bpf2c).
    std::vector<ProgramEntry>
    list_programs(const std::string& elf_path);

    /// Invalidate any cached session for the given file.
    void
    invalidate(const std::string& elf_path);

    /// Get the platform pointer (for tools that need to re-run analysis).
    const prevail::ebpf_platform_t*
    platform() const
    {
        return platform_;
    }

  private:
    std::string
    make_cache_key(
        const std::string& elf_path,
        const std::string& section,
        const std::string& program,
        const std::string& type) const;
    void
    evict_if_full();

    /// Run a fresh analysis within a TLS scope and store as the live session.
    void
    run_live_analysis(
        const std::string& cache_key,
        const std::string& elf_path,
        const std::string& section,
        const std::string& program,
        const std::string& type);

    const prevail::ebpf_platform_t* platform_;
    size_t max_cache_size_;

    // LRU cache: front = most recently used (serialized sessions).
    std::list<std::string> lru_order_;
    std::map<std::string, AnalysisSession> cache_;

    // Live session: holds the most recent AnalysisResult with live EbpfDomain objects.
    // Kept alive by the TLS guard. Invalidated when a different program is analyzed.
    std::unique_ptr<LiveSession> live_session_;
};

} // namespace prevail_mcp
