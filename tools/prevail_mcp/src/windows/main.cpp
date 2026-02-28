// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/// @file Entry point for the PREVAIL MCP server (Windows/ebpf-for-windows build).
/// Sets up the eBPF platform and starts the MCP server loop.

#ifdef _WIN32
#include <Windows.h>
#include <eh.h>
#include <fcntl.h>
#include <io.h>
#endif

#include "analysis_engine.hpp"
#include "mcp_server.hpp"
#include "mcp_transport.hpp"
#include "tools.hpp"

#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <string>

// The submodule's prevail_headers.hpp handles MSVC warning suppression.
#include "ebpf_api.h"
#include "platform_ops_windows.hpp"
#include "prevail_headers.hpp"
#include "windows_platform.hpp"

// Required by api_common (external linkage contract). When true, falls back to registry
// cache for program info when the eBPF service is not running (same as bpf2c via ebpfapi.dll).
bool use_ebpf_store = true;

#ifdef _WIN32
// SEH-to-C++ exception translator. With /EHa, this converts access violations
// and other structured exceptions into catchable C++ exceptions.
class seh_exception : public std::runtime_error
{
  public:
    explicit seh_exception(unsigned int code)
        : std::runtime_error("Structured exception 0x" + to_hex(code)), code_(code)
    {
    }
    unsigned int
    code() const
    {
        return code_;
    }

  private:
    static std::string
    to_hex(unsigned int v)
    {
        char buf[16];
        snprintf(buf, sizeof(buf), "%08X", v);
        return buf;
    }
    unsigned int code_;
};

static void
seh_translator(unsigned int code, EXCEPTION_POINTERS*)
{
    throw seh_exception(code);
}
#endif

int
main()
{
#ifdef _WIN32
    // --- Stdout protection ---
    // Linked libraries (PREVAIL verifier, eBPF API) contain std::cout writes
    // that would corrupt MCP Content-Length framing if they reach the client.
    // Save the original stdout pipe for exclusive MCP use, then redirect
    // stdout/std::cout to stderr so library diagnostics are harmless.
    int mcp_fd = _dup(_fileno(stdout));
    _setmode(mcp_fd, _O_BINARY); // Must set before _fdopen; "wb" alone doesn't change fd mode.
    _dup2(_fileno(stderr), _fileno(stdout));

    FILE* mcp_out = _fdopen(mcp_fd, "wb"); // binary mode, no \r\n translation.
    if (!mcp_out) {
        std::cerr << "prevail_mcp: fatal: cannot open MCP output stream" << std::endl;
        return 1;
    }
    setvbuf(mcp_out, NULL, _IONBF, 0); // Unbuffered — bypass CRT pipe buffering.

    // Set stdin to binary mode (no \r\n translation for MCP message reads).
    _setmode(_fileno(stdin), _O_BINARY);

    // Untie cin from cout (cout now goes to stderr; the tie is no longer useful).
    std::cin.tie(nullptr);

    // Install SEH translator so access violations become catchable C++ exceptions.
    _set_se_translator(seh_translator);
#else
    FILE* mcp_out = stdout;
#endif

    try {
        // Use the Windows eBPF platform (same as bpf2c via ebpfapi).
        const prevail::ebpf_platform_t* platform = &g_ebpf_platform_windows;
        prevail_mcp::WindowsPlatformOps ops(platform);

        prevail_mcp::AnalysisEngine engine(&ops);
        prevail_mcp::McpServer server("ebpf-verifier");
        prevail_mcp::register_all_tools(server, engine);

        std::cerr << "prevail_mcp: server started" << std::endl;

        prevail_mcp::McpTransport transport(mcp_out);
        transport.run([&server](const std::string& method, const nlohmann::json& params) {
            return server.dispatch(method, params);
        });

        std::cerr << "prevail_mcp: server stopped" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "prevail_mcp: fatal error: " << e.what() << std::endl;
        return 1;
    }
}
