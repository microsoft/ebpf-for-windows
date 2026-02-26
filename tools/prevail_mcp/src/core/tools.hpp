// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

/// @file MCP tool declarations and registration.

#include "analysis_engine.hpp"
#include "mcp_server.hpp"

namespace prevail_mcp {

/// Register all PREVAIL MCP tools with the server.
void
register_all_tools(McpServer& server, AnalysisEngine& engine);

} // namespace prevail_mcp
