/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/
#include "stdafx.h"
#include "SspContextImpl.h"
#include <security.h>
#include "UnwindHelper.h"

#define CHECK_SEC_STATUS(func) \
    {\
        SECURITY_STATUS status = func;\
        const char * msg = #func  " failed in " __FUNCTION__; \
        if (status < SEC_E_OK) { \
            printf("%s failed %x\n", msg, status);\
            throw std::exception(msg);\
        }\
    }\

#define CHECK_SEC_STATUS_RET(func, status) \
    {\
        status = func;\
        const char * msg = #func  " failed in " __FUNCTION__; \
        if (status < SEC_E_OK) { \
            printf("%s failed %x\n", msg, status);\
            throw std::exception(msg);\
        }\
    }\


SspContextImpl::SspContextImpl(bool Client, CredHandle & Cred, const char * Target) : Client(Client), Cred(Cred), Handle({ 0,0 })
{
    if (Target) {
        this->Target = Target;
    }
}

void SspContextImpl::ProcessToken(Buffer & Token)
{
    SECURITY_STATUS status;
    DWORD reqAttributes = ISC_REQ_ALLOCATE_MEMORY |ISC_REQ_CONFIDENTIALITY | ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT;
    DWORD actualAttrbiutes = 0;
    SecBuffer inputToken = { static_cast<ULONG>(Token.size()), SECBUFFER_TOKEN, Token.data() };
    SecBuffer outputToken[2] = { { 0, SECBUFFER_TOKEN, nullptr }, {0, SECBUFFER_EMPTY, nullptr} };
    SecBufferDesc input = { SECBUFFER_VERSION, 1, &inputToken };
    SecBufferDesc output = { SECBUFFER_VERSION, 2, outputToken };
    TimeStamp expiry = { 0 };
    UnwindHelper unwind([&] {
        if (outputToken[0].pvBuffer) {
            FreeContextBuffer(outputToken[0].pvBuffer);
        }
    });
    if (Client) {
        if (!ValidHandle()) {
            CHECK_SEC_STATUS_RET(InitializeSecurityContext(&Cred, nullptr, nullptr, reqAttributes, 0, SECURITY_NETWORK_DREP, nullptr, 0, &Handle, &output, &actualAttrbiutes, &expiry), status);
        }
        else {
            CHECK_SEC_STATUS_RET(InitializeSecurityContext(&Cred, &Handle, nullptr, reqAttributes, 0, SECURITY_NETWORK_DREP, &input, 0, nullptr, &output, &actualAttrbiutes, &expiry), status);
        }
        Token.resize(outputToken[0].cbBuffer);
        std::copy(reinterpret_cast<UCHAR*>(outputToken[0].pvBuffer), reinterpret_cast<UCHAR*>(outputToken[0].pvBuffer) + outputToken[0].cbBuffer, Token.begin());
    }
    else {
        if (!ValidHandle()) {
            CHECK_SEC_STATUS_RET(AcceptSecurityContext(&Cred, nullptr, &input, reqAttributes, SECURITY_NETWORK_DREP, &Handle, &output, &actualAttrbiutes, &expiry), status);
        }
        else {
            CHECK_SEC_STATUS_RET(AcceptSecurityContext(&Cred, &Handle, &input, reqAttributes, SECURITY_NETWORK_DREP, nullptr, &output, &actualAttrbiutes, &expiry), status);
        }
        Token.resize(outputToken[0].cbBuffer);
        std::copy(reinterpret_cast<UCHAR*>(outputToken[0].pvBuffer), reinterpret_cast<UCHAR*>(outputToken[0].pvBuffer) + outputToken[0].cbBuffer, Token.begin());
    }
}

void SspContextImpl::EncryptMessage(Buffer & Data)
{
    SecBuffer buffers[4];
    unsigned char Header[16];
    unsigned char Trailer[16];
    SecBufferDesc desc = { SECBUFFER_VERSION, _countof(buffers), buffers };
    UnwindHelper unwind([&] {
        if (buffers[0].pvBuffer) {
            FreeContextBuffer(buffers[0].pvBuffer);
        }
        if (buffers[2].pvBuffer) {
            FreeContextBuffer(buffers[0].pvBuffer);
        }
        if (buffers[3].pvBuffer) {
            FreeContextBuffer(buffers[0].pvBuffer);
        }
    });
    buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
    buffers[0].cbBuffer = _countof(Header);
    buffers[0].pvBuffer = Header;
    buffers[1].BufferType = SECBUFFER_DATA;
    buffers[1].cbBuffer = Data.size();
    buffers[1].pvBuffer = Data.data();
    buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
    buffers[2].cbBuffer = _countof(Trailer);
    buffers[2].pvBuffer = Trailer;
    buffers[3].BufferType = SECBUFFER_EMPTY;
    CHECK_SEC_STATUS(::EncryptMessage(&Handle, 0, &desc, 0));
}

void SspContextImpl::DecryptMessage(Buffer & Data)
{
}

SspContextImpl::~SspContextImpl()
{
    if (ValidHandle()) {
        DeleteSecurityContext(&Handle);
    }
}
