/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/
#pragma once
#include "SspContext.h"
#define SECURITY_WIN32
#include <Security.h>

class SspContextImpl : public SspContext
{
public:
    SspContextImpl(bool Client, CredHandle & Cred, const char * Target);
    virtual void ProcessToken(Buffer & Token);
    virtual void EncryptMessage(Buffer & Data);
    virtual void DecryptMessage(Buffer & Data);
    virtual ~SspContextImpl();
private:
    bool ValidHandle() {
        return !((Handle.dwLower == 0) && (Handle.dwUpper == 0));
    }

    bool Client;
    CredHandle & Cred;
    CtxtHandle Handle;
    std::string Target;
    size_t maxToken;
};

