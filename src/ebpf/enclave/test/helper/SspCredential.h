/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/
#pragma once
#include <memory>
#include "SspContext.h"
class SspCredential
{
public:
    virtual std::shared_ptr<SspContext> CreateClientContext(const char * Target) = 0;
    virtual std::shared_ptr<SspContext> CreateServerContext(const char * Target) = 0;
    virtual ~SspCredential() {}
};

typedef std::shared_ptr<SspCredential> SspCredentialPtr;