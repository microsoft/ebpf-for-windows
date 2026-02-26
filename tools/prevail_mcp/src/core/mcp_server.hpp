// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

/// @file MCP server: tool registry, capability negotiation, and request dispatch.

#include "mcp_transport.hpp"

#include <functional>
#include <map>
#include <nlohmann/json.hpp>
#include <string>

namespace prevail_mcp {

/// Metadata and handler for a single MCP tool.
struct ToolInfo
{
    std::string name;
    std::string description;
    nlohmann::json input_schema; // JSON Schema object for the tool's parameters.
    std::function<nlohmann::json(const nlohmann::json& arguments)> handler;
};

/// MCP server that registers tools and dispatches incoming requests.
class McpServer
{
  public:
    static constexpr const char* server_name = "prevail-verifier";
    static constexpr const char* server_version = "0.1.0";

    void
    register_tool(ToolInfo tool);

    /// Dispatch a JSON-RPC request.  Suitable as the handler for McpTransport::run().
    nlohmann::json
    dispatch(const std::string& method, const nlohmann::json& params);

  private:
    nlohmann::json
    handle_initialize(const nlohmann::json& params);
    nlohmann::json
    handle_tools_list(const nlohmann::json& params);
    nlohmann::json
    handle_tools_call(const nlohmann::json& params);

    std::map<std::string, ToolInfo> tools_;
};

} // namespace prevail_mcp
