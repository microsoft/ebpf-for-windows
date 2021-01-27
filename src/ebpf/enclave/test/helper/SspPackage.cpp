/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/
#include "stdafx.h"
#include "SspPackage.h"
#define SECURITY_WIN32
#include <Security.h>
#include "SspCredentialImpl.h"

#define CHECK_SEC_STATUS(func) \
    {\
        SECURITY_STATUS status = func;\
        const char * msg = #func  " failed in " __FUNCTION__; \
        if (status != SEC_E_OK) { \
            throw std::exception(msg);\
        }\
    }\

std::vector<SspPackage::Info> SspPackage::Enumerate()
{
    std::vector<SspPackage::Info> packages;
    unsigned long packageCount = 0;
    PSecPkgInfoA pkgInfo = nullptr;
    CHECK_SEC_STATUS(EnumerateSecurityPackagesA(&packageCount, &pkgInfo));
    for (unsigned long i = 0; i < packageCount; i++) {
        Info info = {
            pkgInfo[i].fCapabilities,
            pkgInfo[i].wVersion,
            pkgInfo[i].wRPCID,
            pkgInfo[i].cbMaxToken,
            pkgInfo[i].Name,
            pkgInfo[i].Comment
        };
        packages.push_back(info);
    }
    return packages;
}

std::shared_ptr<SspCredential> SspPackage::GetCredential(const char * Principal, const char * Package, const void * Cred, bool Client, bool Server)
{
    return std::make_shared<SspCredentialImpl>(Principal, Package, Cred, Client, Server);
}

SspPackage::~SspPackage()
{
}
