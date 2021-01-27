/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/

#pragma once
#include <Wincrypt.h>
#pragma comment(lib, "Crypt32.lib")
#include <string>
#include <memory>
#include <vector>
class X509
{
public:
    X509();
    ~X509();
    class Certificate;
    class Store;

    typedef std::shared_ptr<Certificate> CertificatePtr;
    typedef std::shared_ptr<Store> StorePtr;
    typedef std::vector<unsigned char> Hash;

    class Certificate
    {
    public:
        ~Certificate() {}
        virtual operator PCCERT_CONTEXT() = 0;
        virtual Hash GetThumbPrint() = 0;
    };

    class Store
    {
    public:
        virtual CertificatePtr FindCertByHash(const Hash& Hash) = 0;
        virtual ~Store() {}
    };

    static StorePtr OpenStore(const char * Name);
    static StorePtr OpenSystemStore(const char * Name);
    static Hash HashFromHexString(const char * pHashString);
    static void LogError(const char * Message, DWORD Error);

private:
    class StoreImpl;

    class CertificateImpl : public Certificate
    {
    public:
        CertificateImpl(PCCERT_CONTEXT & Cert, StoreImpl & Parent);
        virtual ~CertificateImpl();
        virtual operator PCCERT_CONTEXT();
        Hash GetThumbPrint();
        void LogError(const char * Message, DWORD Error);

    private:
        StoreImpl & Parent;
        PCCERT_CONTEXT CertContext;
    };

    class StoreImpl : public Store
    {
    public:
        StoreImpl(HCERTSTORE hCertStore);
        virtual ~StoreImpl();
        virtual CertificatePtr FindCertByHash(const Hash& Hash);
        void LogError(const char * Message, DWORD Error);
    private:
        HCERTSTORE hCertStore;
    };
};

