/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/
#pragma once
#include "SspCredential.h"
#define SECURITY_WIN32
#include <Security.h>

class SspCredentialImpl : public SspCredential
{
public:
    SspCredentialImpl(const char * Principal, const char * Package, const void * CredBlob, bool Client, bool Server);
    virtual ~SspCredentialImpl();
    virtual std::shared_ptr<SspContext> CreateClientContext(const char * Target);
    virtual std::shared_ptr<SspContext> CreateServerContext(const char * Target);
private:
    CredHandle Creds;
    TimeStamp Expiry;
};