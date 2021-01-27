/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/
#include "stdafx.h"
#include "SspCredentialImpl.h"
#include "SspContextImpl.h"

#define CHECK_SEC_STATUS(func) \
    {\
        SECURITY_STATUS status = func;\
        const char * msg = #func  " failed in " __FUNCTION__; \
        if (status < SEC_E_OK) { \
            throw std::exception(msg);\
        }\
    }\


SspCredentialImpl::SspCredentialImpl(const char * Principal, const char * Package, const void * CredBlob, bool Client, bool Server) : Creds({0, 0})
{
    DWORD credUse = (Client ? SECPKG_CRED_OUTBOUND : 0) | (Server ? SECPKG_CRED_INBOUND : 0);
    CHECK_SEC_STATUS(AcquireCredentialsHandleA(const_cast<LPSTR>(Principal), const_cast<LPSTR>(Package), credUse, nullptr, const_cast<void*>(CredBlob), nullptr, nullptr, &Creds, &Expiry));
}

SspCredentialImpl::~SspCredentialImpl()
{
    FreeCredentialHandle(&Creds);
}

std::shared_ptr<SspContext> SspCredentialImpl::CreateClientContext(const char * Target)
{
    return std::make_shared<SspContextImpl>(true, Creds, Target);
}

std::shared_ptr<SspContext> SspCredentialImpl::CreateServerContext(const char * Target)
{
    return std::make_shared<SspContextImpl>(false, Creds, Target);
}
