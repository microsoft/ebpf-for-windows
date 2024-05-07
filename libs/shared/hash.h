// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include <stdexcept>
#include <string>
#include <vector>

typedef class _hash
{
  public:
    typedef std::vector<std::tuple<const uint8_t*, size_t>> byte_range_t;
    template <typename T>
    static void
    append_byte_range(_Inout_ byte_range_t& byte_range, _In_ const T& value)
    {
        if constexpr (std::is_same<T, const char*>::value) {
            byte_range.push_back({reinterpret_cast<const uint8_t*>(value), strlen(value)});
        } else if constexpr (std::is_same<T, const std::string>::value || std::is_same<T, std::string>::value) {
            byte_range.push_back({reinterpret_cast<const uint8_t*>(value.data()), value.size()});
        } else if constexpr (std::is_pointer<T>::value) {
            throw std::runtime_error("Can't hash pointer");
        } else {
            byte_range.push_back({reinterpret_cast<const uint8_t*>(&value), sizeof(value)});
        }
    };
    _hash(const std::string& algorithm);
    ~_hash();

    std::vector<uint8_t>
    hash_string(const std::string& data);

    std::vector<uint8_t>
    hash_byte_ranges(const byte_range_t& byte_ranges);

  private:
    void* algorithm_handle;
} hash_t;
