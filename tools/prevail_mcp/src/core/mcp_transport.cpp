// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "mcp_transport.hpp"

#include <cstdio>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace prevail_mcp {

McpTransport::McpTransport(FILE* output) : output_(output) {}

nlohmann::json
McpTransport::read_content_length()
{
    // Read headers until blank line.
    size_t content_length = 0;
    bool found_content_length = false;

    std::string line;
    while (std::getline(std::cin, line)) {
        // Remove trailing \r if present (Content-Length: N\r\n).
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            break; // End of headers.
        }
        const std::string prefix = "Content-Length: ";
        if (line.substr(0, prefix.size()) == prefix) {
            content_length = std::stoull(line.substr(prefix.size()));
            found_content_length = true;
        }
        // Ignore other headers (Content-Type, etc.).
    }

    if (!found_content_length || std::cin.eof()) {
        return nullptr;
    }

    // Read exactly content_length bytes of body.
    std::string body(content_length, '\0');
    std::cin.read(body.data(), static_cast<std::streamsize>(content_length));
    if (std::cin.gcount() != static_cast<std::streamsize>(content_length)) {
        return nullptr;
    }

    return nlohmann::json::parse(body);
}

nlohmann::json
McpTransport::read_ndjson()
{
    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue; // Skip blank lines.
        }
        return nlohmann::json::parse(line);
    }
    return nullptr; // EOF.
}

nlohmann::json
McpTransport::read_message()
{
    if (framing_ == Framing::unknown) {
        // Auto-detect: peek at the first non-whitespace byte.
        // '{' → NDJSON, 'C' → Content-Length.
        int ch;
        while ((ch = std::cin.peek()) != EOF) {
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
                std::cin.get(); // Consume whitespace.
                continue;
            }
            break;
        }
        if (ch == EOF) {
            return nullptr;
        }

        if (ch == '{') {
            framing_ = Framing::ndjson;
            std::cerr << "prevail_mcp: using NDJSON framing" << std::endl;
        } else {
            framing_ = Framing::content_length;
            std::cerr << "prevail_mcp: using Content-Length framing" << std::endl;
        }
    }

    return (framing_ == Framing::ndjson) ? read_ndjson() : read_content_length();
}

void
McpTransport::write_message(const nlohmann::json& msg)
{
    const std::string body = msg.dump();

    if (framing_ == Framing::ndjson) {
        // NDJSON: single line of JSON followed by newline.
        fwrite(body.data(), 1, body.size(), output_);
        fputc('\n', output_);
    } else {
        // Content-Length framing.
        const std::string frame = "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
        fwrite(frame.data(), 1, frame.size(), output_);
    }
    fflush(output_);
}

void
McpTransport::run(Handler handler)
{
    while (true) {
        nlohmann::json request = read_message();
        if (request.is_null()) {
            break; // EOF or read error.
        }

        const std::string method = request.value("method", "");
        const nlohmann::json params = request.value("params", nlohmann::json::object());
        const bool is_notification = !request.contains("id");

        try {
            nlohmann::json result = handler(method, params);

            if (!is_notification) {
                nlohmann::json response = {
                    {"jsonrpc", "2.0"},
                    {"id", request["id"]},
                    {"result", std::move(result)},
                };
                write_message(response);
            }
        } catch (const std::exception& e) {
            if (!is_notification) {
                nlohmann::json error_response = {
                    {"jsonrpc", "2.0"},
                    {"id", request["id"]},
                    {"error",
                     {
                         {"code", -32603}, // Internal error.
                         {"message", e.what()},
                     }},
                };
                write_message(error_response);
            } else {
                std::cerr << "prevail_mcp: notification handler error: " << e.what() << std::endl;
            }
        }
    }
}

} // namespace prevail_mcp
