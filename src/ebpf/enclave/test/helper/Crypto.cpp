/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/
#include "stdafx.h"
#include "Crypto.h"

inline bool NT_SUCCESS(NTSTATUS Status) { return Status >= 0; }

#define NONCE_LENGTH 12

#define CHECK_NTSTATUS(func) \
    {\
        NTSTATUS status = func;\
        const char * msg = #func  " failed in " __FUNCTION__; \
        if (!NT_SUCCESS(status)) { \
            LogError(msg, status);\
            throw std::exception(msg);\
        }\
    }\

Crypto::AlgorithmPtr RNG = Crypto::OpenAlgorithm(BCRYPT_RNG_ALGORITHM);

Crypto::AlgorithmPtr Crypto::OpenAlgorithm(const wchar_t * Algorithm, LogFn Log)
{
    return std::make_shared<AlgorithmImpl>(Algorithm, Log);
}

Crypto::KeyImpl::KeyImpl(AlgorithmImpl & Algorithm, const KeyMaterial & Material) : Algorithm(Algorithm)
{
    ULONG cb;
    Property prop = Algorithm.GetProperty(BCRYPT_OBJECT_LENGTH);
    KeyStorage.resize(*reinterpret_cast<DWORD*>(prop.data()));
    CHECK_NTSTATUS(BCryptGenerateSymmetricKey(Algorithm.Handle, &Handle, KeyStorage.data(), static_cast<ULONG>(KeyStorage.size()), const_cast<unsigned char *>(Material.data()), static_cast<ULONG>(Material.size()), 0));
    CHECK_NTSTATUS(BCryptGetProperty(Algorithm.Handle, BCRYPT_AUTH_TAG_LENGTH, reinterpret_cast<PUCHAR>(&AuthTagLengths), static_cast<ULONG>(sizeof(AuthTagLengths)), &cb, 0));
    BlockSize = Algorithm.GetBlockLength();
}

Crypto::KeyImpl::~KeyImpl()
{
    BCryptDestroyKey(Handle);
}

void Crypto::KeyImpl::Encrypt(const Blob & Iv, const Blob & ClearText, Blob & CypherText)
{
    Blob tempIv = Iv;
    ULONG cypherTextLength = 0;
    CHECK_NTSTATUS(BCryptEncrypt(Handle, const_cast<unsigned char*>(ClearText.data()), static_cast<ULONG>(ClearText.size()), nullptr, tempIv.data(), static_cast<ULONG>(tempIv.size()), nullptr, 0, &cypherTextLength, BCRYPT_BLOCK_PADDING));
    CypherText.resize(cypherTextLength);
    CHECK_NTSTATUS(BCryptEncrypt(Handle, const_cast<unsigned char*>(ClearText.data()), static_cast<ULONG>(ClearText.size()), nullptr, tempIv.data(), static_cast<ULONG>(tempIv.size()), CypherText.data(), cypherTextLength, &cypherTextLength, BCRYPT_BLOCK_PADDING));
    CypherText.resize(cypherTextLength);
}

void Crypto::KeyImpl::Decrypt(const Blob & Iv, const Blob & CypherText, Blob & ClearText)
{
    Blob tempIv = Iv;
    ULONG clearTextLength = 0;
    CHECK_NTSTATUS(BCryptDecrypt(Handle, const_cast<unsigned char*>(CypherText.data()), static_cast<ULONG>(CypherText.size()), nullptr, tempIv.data(), static_cast<ULONG>(tempIv.size()), nullptr, 0, &clearTextLength, BCRYPT_BLOCK_PADDING));
    ClearText.resize(clearTextLength);
    CHECK_NTSTATUS(BCryptDecrypt(Handle, const_cast<unsigned char*>(CypherText.data()), static_cast<ULONG>(CypherText.size()), nullptr, tempIv.data(), static_cast<ULONG>(tempIv.size()), ClearText.data(), clearTextLength, &clearTextLength, BCRYPT_BLOCK_PADDING));
    ClearText.resize(clearTextLength);
}

void Crypto::KeyImpl::AuthEncrypt(const Blob & ClearText, Blob & CypherText)
{
    ULONG cypherTextLength = static_cast<ULONG>(ClearText.size());
    size_t offset = 0;
    CypherText.resize(cypherTextLength + AuthTagLengths.dwMinLength + BlockSize * 3);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.cbNonce = NONCE_LENGTH;
    authInfo.pbNonce = &CypherText[0];
    authInfo.cbTag = AuthTagLengths.dwMinLength;
    authInfo.pbTag = &CypherText[12];
    offset = authInfo.cbNonce + authInfo.cbTag;
    cypherTextLength = static_cast<ULONG>(CypherText.size() - offset);
    RNG->FillRandom(CypherText.begin(), CypherText.begin() + NONCE_LENGTH);

    CHECK_NTSTATUS(BCryptEncrypt(Handle, const_cast<unsigned char*>(ClearText.data()), static_cast<ULONG>(ClearText.size()), &authInfo, nullptr, 0, &CypherText[offset], cypherTextLength, &cypherTextLength, 0));
    CypherText.resize(cypherTextLength + offset);
}

void Crypto::KeyImpl::AuthDecrypt(const Blob & CypherText, Blob & ClearText)
{
    size_t offset = 0;
    ULONG clearTextLength = static_cast<ULONG>(CypherText.size());
    ULONG cypherTextLength;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.cbNonce = NONCE_LENGTH;
    authInfo.pbNonce = const_cast<unsigned char*>(&CypherText[0]);
    authInfo.cbTag = AuthTagLengths.dwMinLength;
    authInfo.pbTag = const_cast<unsigned char*>(&CypherText[NONCE_LENGTH]);

    offset = authInfo.cbTag + authInfo.cbNonce;
    ClearText.resize(clearTextLength);
    cypherTextLength = static_cast<ULONG>(CypherText.size() - offset);

    CHECK_NTSTATUS(BCryptDecrypt(Handle, const_cast<unsigned char*>(&CypherText[offset]), cypherTextLength, &authInfo, nullptr, 0, ClearText.data(), clearTextLength, &clearTextLength, 0));
    ClearText.resize(clearTextLength);
}

void Crypto::AlgorithmImpl::FillRandom(Blob::iterator Start, Blob::iterator End)
{
    CHECK_NTSTATUS(BCryptGenRandom(Handle, &*Start, static_cast<ULONG>(End - Start), 0));
}

void Crypto::KeyImpl::LogError(const char * Message, NTSTATUS Status)
{
    Algorithm.LogError(Message, Status);
}

Crypto::AlgorithmImpl::AlgorithmImpl(const wchar_t * Algorithm, LogFn Log) : Log(Log)
{
    CHECK_NTSTATUS(BCryptOpenAlgorithmProvider(&Handle, Algorithm, nullptr, 0));
}

Crypto::AlgorithmImpl::~AlgorithmImpl()
{
    BCryptCloseAlgorithmProvider(Handle, 0);
}

Crypto::Property Crypto::AlgorithmImpl::GetProperty(const wchar_t * Name)
{
    Property prop;
    unsigned long propLength = 0;
    CHECK_NTSTATUS(BCryptGetProperty(Handle, Name, nullptr, 0, &propLength, 0));
    prop.resize(propLength);
    CHECK_NTSTATUS(BCryptGetProperty(Handle, Name, prop.data(), propLength, &propLength, 0));
    prop.resize(propLength);
    return prop;
}

void Crypto::AlgorithmImpl::SetProperty(const wchar_t * Name, const Property & Value)
{
    CHECK_NTSTATUS(BCryptSetProperty(Handle, Name, const_cast<unsigned char*>(Value.data()), static_cast<ULONG>(Value.size()), 0));
}

void Crypto::AlgorithmImpl::SetProperty(const wchar_t * Name, const wchar_t * Value)
{
    CHECK_NTSTATUS(BCryptSetProperty(Handle, Name, reinterpret_cast<unsigned char*>(const_cast<wchar_t*>(Value)), static_cast<ULONG>(wcslen(Value) * sizeof(*Value)), 0));
}

Crypto::KeyPtr Crypto::AlgorithmImpl::CreateSymetricKey(const KeyMaterial & Material)
{
    return std::make_shared<KeyImpl>(*this, Material);
}

size_t Crypto::AlgorithmImpl::GetBlockLength()
{
    return *reinterpret_cast<ULONG*>(GetProperty(BCRYPT_BLOCK_LENGTH).data());
}

void Crypto::AlgorithmImpl::LogError(const char * Message, NTSTATUS Status)
{
    if (Log) Log(Message, Status);
}
