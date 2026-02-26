// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "mcp_server.hpp"

#include <stdexcept>

namespace prevail_mcp {

void
McpServer::register_tool(ToolInfo tool)
{
    const std::string name = tool.name;
    tools_.emplace(name, std::move(tool));
}

nlohmann::json
McpServer::dispatch(const std::string& method, const nlohmann::json& params)
{
    if (method == "initialize") {
        return handle_initialize(params);
    }
    if (method == "tools/list") {
        return handle_tools_list(params);
    }
    if (method == "tools/call") {
        return handle_tools_call(params);
    }
    if (method == "notifications/initialized" || method == "notifications/cancelled") {
        return nullptr; // Notifications return nothing.
    }

    throw std::runtime_error("Unknown method: " + method);
}

nlohmann::json
McpServer::handle_initialize(const nlohmann::json& /*params*/)
{
    return {
        {"protocolVersion", "2024-11-05"},
        {"capabilities",
         {
             {"tools", nlohmann::json::object()},
         }},
        {"serverInfo",
         {
             {"name", server_name},
             {"version", server_version},
         }},
    };
}

nlohmann::json
McpServer::handle_tools_list(const nlohmann::json& /*params*/)
{
    nlohmann::json tool_list = nlohmann::json::array();
    for (const auto& [name, info] : tools_) {
        tool_list.push_back({
            {"name", info.name},
            {"description", info.description},
            {"inputSchema", info.input_schema},
        });
    }
    return {{"tools", tool_list}};
}

nlohmann::json
McpServer::handle_tools_call(const nlohmann::json& params)
{
    const std::string tool_name = params.value("name", "");
    const nlohmann::json arguments = params.value("arguments", nlohmann::json::object());

    auto it = tools_.find(tool_name);
    if (it == tools_.end()) {
        throw std::runtime_error("Unknown tool: " + tool_name);
    }

    try {
        nlohmann::json result = it->second.handler(arguments);
        return {
            {"content",
             {{
                 {"type", "text"},
                 {"text", result.dump(2)},
             }}},
        };
    } catch (const std::exception& e) {
        return {
            {"content",
             {{
                 {"type", "text"},
                 {"text", std::string("Error: ") + e.what()},
             }}},
            {"isError", true},
        };
    }
}

} // namespace prevail_mcp
