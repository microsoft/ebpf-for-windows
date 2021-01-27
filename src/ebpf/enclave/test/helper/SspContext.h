/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/
#pragma once
#include <vector>
class SspContext
{
public:
    typedef std::vector<unsigned char> Buffer;
    virtual void ProcessToken(Buffer & Token) = 0;
    virtual void EncryptMessage(Buffer & Data) = 0;
    virtual void DecryptMessage(Buffer & Data) = 0;
    virtual ~SspContext() {}
};
typedef std::shared_ptr<SspContext> SspContextPtr;
