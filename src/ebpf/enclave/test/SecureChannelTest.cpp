/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <io.h>
#include <thread>
#include <algorithm>
#define CATCH_CONFIG_MAIN

#include <windows.h>
#include <schannel.h>
#include "helper/SspPackage.h"

extern "C"
{
#include "../secure_channel.h"
#include "../log.h"
#include <openenclave/host.h>
#include "EbpfEnclave_u.h"
#include "../../libs/enclavehost/EbpfEnclave_host.h"

}

#include <catch.hpp>

void ebpf_enclave_log(log_level level, const char* format, ...)
{
    char buffer[8192];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    printf("%d:%s\n", level, buffer);
}

TEST_CASE("Secure channel init / free", "[init]") {
    struct secure_channel_state* state = NULL;
    REQUIRE(secure_channel_init(&state) == 0);
    REQUIRE(state != nullptr);
    REQUIRE(secure_channel_free(state) == 0);
}

TEST_CASE("Secure channel generate cert", "[generate_cert]") {
    struct secure_channel_state* state = NULL;
    REQUIRE(secure_channel_init(&state) == 0);
    REQUIRE(state != nullptr);
    REQUIRE(secure_channel_generate_cert(state, "CN=foo") == 0);
    REQUIRE(secure_channel_free(state) == 0);
}

struct schannel_state
{
    std::vector<unsigned char> token;

    SCHANNEL_CRED sccred;

    SspCredentialPtr cred;
    SspContextPtr ctx;

} sc_state;


TEST_CASE("Secure channel open", "[open]") {

    struct secure_channel_state* state = NULL;

    memset(&sc_state.sccred, 0, sizeof(sc_state.sccred));
    sc_state.sccred.dwVersion = SCHANNEL_CRED_VERSION;
    sc_state.sccred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_SERVERNAME_CHECK;
    sc_state.cred = SspPackage::GetCredential(nullptr, "Schannel", &sc_state.sccred, true, false);
    sc_state.ctx = sc_state.cred->CreateClientContext(nullptr);

    // Get initial blob
    sc_state.ctx->ProcessToken(sc_state.token);

    REQUIRE(secure_channel_init(&state) == 0);
    REQUIRE(state != nullptr);
    REQUIRE(secure_channel_generate_cert(state, "CN=foo") == 0);

    auto send = [](void* context, const unsigned char* buffer, size_t length) -> int {
        schannel_state* state = (schannel_state*)context;
        state->token.resize(length);
        std::copy(buffer, buffer + length, state->token.begin());
        state->ctx->ProcessToken(state->token);
        return length;
    };
    auto receive = [](void* context, unsigned char* buffer, size_t length) -> int {
        schannel_state* state = (schannel_state*)context;
        size_t recv = min(state->token.size(), length);
        std::copy(state->token.begin(), state->token.begin() + recv, buffer);
        if (state->token.size() > recv)
        {
            std::vector<unsigned char> temp(state->token.size() - recv);
            std::copy(state->token.begin() + recv, state->token.end(), temp.begin());
            state->token = temp;
        }
        else
        {
            state->token.resize(0);
        }
        return recv;
    };

    REQUIRE(secure_channel_open(state, &sc_state, send, receive) == 0);

    REQUIRE(secure_channel_free(state) == 0);
}

TEST_CASE("Invoke JIT", "[jit]") {
    unsigned short byte_code[] = { 0x00b7, 0x0000, 0x0000, 0x0000, 0x0095, 0x0000, 0x0000, 0x0000 };
    unsigned char machine_code[1024] = { 0 };
    size_t machine_code_size = sizeof(machine_code);
    REQUIRE(ebpf_verify_jit((unsigned char*)byte_code, sizeof(byte_code), machine_code, &machine_code_size) == 0);
}

uint64_t ocall_open_execution_context()
{
    schannel_state* state = new schannel_state();
    memset(&state->sccred, 0, sizeof(state->sccred));
    state->sccred.dwVersion = SCHANNEL_CRED_VERSION;
    state->sccred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_SERVERNAME_CHECK;
    state->cred = SspPackage::GetCredential(nullptr, "Schannel", &state->sccred, true, false);
    state->ctx = state->cred->CreateClientContext(nullptr);

    // Get initial blob
    state->ctx->ProcessToken(state->token);

    return (uint64_t)state;
}

void ocall_close_execution_context(uint64_t context)
{
    schannel_state* state = (schannel_state*)context;
    delete state;
}

size_t ocall_write_execution_context(uint64_t context, const unsigned char* buffer, size_t buffer_size)
{
    schannel_state* state = (schannel_state*)context;
    state->token.resize(buffer_size);
    std::copy(buffer, buffer + buffer_size, state->token.begin());
    state->ctx->ProcessToken(state->token);
    return buffer_size;
}

size_t ocall_read_execution_context(uint64_t context, unsigned char* buffer, size_t buffer_size)
{
    schannel_state* state = (schannel_state*)context;
    size_t recv = min(state->token.size(), buffer_size);
    std::copy(state->token.begin(), state->token.begin() + recv, buffer);
    if (state->token.size() > recv)
    {
        std::vector<unsigned char> temp(state->token.size() - recv);
        std::copy(state->token.begin() + recv, state->token.end(), temp.begin());
        state->token = temp;
    }
    else
    {
        state->token.resize(0);
    }
    return recv;
}

void ocall_ebpf_enclave_log(int level, const char* message)
{
    const char* prefix;
    switch (level)
    {
    case error:
        prefix = "ERROR:";
        break;
    case warning:
        prefix = "WARN:";
        break;
    case info:
        prefix = "INFO:";
        break;
    case verbose:
        prefix = "VERB:";
        break;
    default:
        prefix = "UNKN:";
        break;
    }
    printf("%s%s", prefix, message);
}