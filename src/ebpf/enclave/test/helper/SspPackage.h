/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/
#pragma once
#include <string>
#include <vector>
#include "SspPackage.h"
#include "SspCredential.h"
#pragma comment(lib, "secur32.lib")


class SspPackage
{
public:
    typedef struct {
        unsigned long Capabilities;
        unsigned short Version;
        unsigned long WireRpcId;
        size_t MaxTokenSize;
        std::string Name;
        std::string Description;
    } Info;

    static std::vector<Info> Enumerate();
    static std::shared_ptr<SspCredential> GetCredential(const char * Principal, const char * Package, const void * Cred, bool Client, bool Server);
    virtual ~SspPackage();
};

typedef std::shared_ptr<SspPackage> SspPackagePtr;
