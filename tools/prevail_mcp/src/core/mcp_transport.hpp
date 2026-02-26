// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

/// @file MCP JSON-RPC 2.0 transport over stdio.
///
/// Supports two framing modes, auto-detected from the first byte of input:
///   - Content-Length framing (VS Code, spec-compliant clients)
///   - Newline-delimited JSON / NDJSON (GitHub Copilot CLI)

#include <cstdio>
#include <functional>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>

namespace prevail_mcp {

/// Reads JSON-RPC 2.0 messages from stdin and writes responses to a dedicated
/// output FILE* using either Content-Length or NDJSON framing.
///
/// The output FILE* should be the original stdout pipe, opened in binary mode
/// with buffering disabled.  This separation allows linked libraries that write
/// to std::cout / stdout (e.g. the PREVAIL verifier's dump_btf_types or the
/// eBPF API's verbose parse-failure messages) to be safely redirected to stderr
/// without corrupting the protocol framing.
class McpTransport
{
  public:
    /// @param output FILE* for writing MCP protocol messages.
    ///        Must be in binary mode; caller should disable buffering with setvbuf.
    explicit McpTransport(FILE* output);

    /// Read one JSON-RPC message from stdin.
    /// On the first call, peeks at stdin to auto-detect the framing mode.
    /// @return Parsed JSON message, or nullptr on EOF/error.
    nlohmann::json
    read_message();

    /// Write one JSON-RPC message to the MCP output stream.
    void
    write_message(const nlohmann::json& msg);

    /// Main event loop.  Reads requests, dispatches to handler, writes responses.
    /// The handler receives (method, params) and returns a result JSON.
    /// For notifications (no "id") the handler is still called but the return value is ignored.
    /// The loop exits on EOF or when the handler throws.
    using Handler = std::function<nlohmann::json(const std::string& method, const nlohmann::json& params)>;
    void
    run(Handler handler);

  private:
    enum class Framing
    {
        unknown,
        content_length, // "Content-Length: N\r\n\r\n{...}"
        ndjson,         // "{...}\n"
    };

    nlohmann::json
    read_content_length();
    nlohmann::json
    read_ndjson();

    FILE* output_;
    Framing framing_ = Framing::unknown;
};

} // namespace prevail_mcp
