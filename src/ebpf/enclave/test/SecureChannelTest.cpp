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

TEST_CASE("Secure channel open", "[open]") {

    struct secure_channel_state* state = NULL;
    struct schannel_state
    {
        std::vector<unsigned char> token;

        SCHANNEL_CRED sccred;

        SspCredentialPtr cred;
        SspContextPtr ctx; 

    } sc_state;


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

