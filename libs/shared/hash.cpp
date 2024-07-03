// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "hash.h"

#include <windows.h>
#include <bcrypt.h>
#include <codecvt>
#include <exception>
#include <string>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")

_hash::_hash(const std::string& algorithm)
{
    HRESULT hr;
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
    std::wstring wide_algorithm = converter.from_bytes(algorithm);

    hr = BCryptOpenAlgorithmProvider(&algorithm_handle, wide_algorithm.c_str(), nullptr, BCRYPT_HASH_REUSABLE_FLAG);
    if (!SUCCEEDED(hr)) {
        throw std::runtime_error(
            std::string("BCryptOpenAlgorithmProvider failed with algorithm: ") + algorithm +
            " HR=" + std::to_string(hr));
    }
}
_hash::~_hash() { BCryptCloseAlgorithmProvider(algorithm_handle, 0); }

std::vector<uint8_t>
_hash::hash_string(const std::string& data)
{
    byte_range_t byte_range;
    append_byte_range(byte_range, data);
    return hash_byte_ranges(byte_range);
}

std::vector<uint8_t>
_hash::hash_byte_ranges(const byte_range_t& byte_ranges)
{
    uint32_t hash_length;
    std::vector<uint8_t> hash;
    BCRYPT_HASH_HANDLE hash_handle;
    HRESULT hr;
    hr = BCryptCreateHash(algorithm_handle, &hash_handle, nullptr, 0, nullptr, 0, 0);
    if (!SUCCEEDED(hr)) {
        throw std::runtime_error(std::string("BCryptCreateHash failed with HR=") + std::to_string(hr));
    }

    for (const auto& [data, length] : byte_ranges) {
        hr = BCryptHashData(hash_handle, const_cast<uint8_t*>(data), static_cast<unsigned long>(length), 0);
        if (!SUCCEEDED(hr)) {
            BCryptDestroyHash(hash_handle);
            throw std::runtime_error(std::string("BCryptHashData failed with HR=") + std::to_string(hr));
        }
    }

    unsigned long bytes_written;
    hr = BCryptGetProperty(
        algorithm_handle,
        BCRYPT_HASH_LENGTH,
        reinterpret_cast<uint8_t*>(&hash_length),
        sizeof(hash_length),
        &bytes_written,
        0);
    if (!SUCCEEDED(hr)) {
        BCryptDestroyHash(hash_handle);
        throw std::runtime_error(
            std::string("BCryptGetProperty failed with BCRYPT_HASH_LENGTH  HR=") + std::to_string(hr));
    }
    hash.resize(hash_length);
    hr = BCryptFinishHash(hash_handle, hash.data(), static_cast<unsigned long>(hash.size()), 0);
    BCryptDestroyHash(hash_handle);
    if (!SUCCEEDED(hr)) {
        throw std::runtime_error(std::string("BCryptFinishHash failed with HR=") + std::to_string(hr));
    }
    return hash;
}
