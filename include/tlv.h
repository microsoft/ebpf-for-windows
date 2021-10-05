// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#include <stdint.h>
#include <string>
#include <vector>

typedef enum class _tlv_type
{
    BLOB,    ///< Opaque byte blob.
    UINT,    ///< Unsigned integer.
    INT,     ///< Signed integer.
    STRING,  ///< String.
    SEQUENCE ///< Sequence of other tlv_type_t values.
} tlv_type_t;

typedef struct _tlv_type_length_value
{
    uint32_t type : 4;
    uint32_t length : 28;
    unsigned char value[1];
} tlv_type_length_value_t;

typedef std::vector<std::vector<uint8_t>> tlv_sequence;

template <typename data_type_t>
inline std::vector<uint8_t>
tlv_pack(const data_type_t& data)
{
    tlv_type_length_value_t* header;
    std::vector<uint8_t> retval;
    if constexpr (std::is_same<data_type_t, tlv_sequence>::value) {
        retval.resize(offsetof(tlv_type_length_value_t, value));
        for (const auto& v : data) {
            retval.insert(retval.end(), v.begin(), v.end());
        }
        header = reinterpret_cast<decltype(header)>(retval.data());
        header->type = static_cast<uint16_t>(tlv_type_t::SEQUENCE);
        header->length = retval.size();
    } else if constexpr (std::is_same<data_type_t, std::vector<uint8_t>>::value) {
        retval.resize(offsetof(tlv_type_length_value_t, value));
        retval.insert(retval.end(), data.begin(), data.end());
        header = reinterpret_cast<decltype(header)>(retval.data());
        header->type = static_cast<uint16_t>(tlv_type_t::BLOB);
        header->length = retval.size();
    } else if constexpr (std::is_same<data_type_t, const char*>::value) {
        size_t string_length = strlen(data);
        retval.resize(offsetof(tlv_type_length_value_t, value) + string_length);
        header = reinterpret_cast<decltype(header)>(retval.data());
        header->type = static_cast<uint16_t>(tlv_type_t::STRING);
        header->length = retval.size();
        memcpy(header->value, data, string_length);
    } else {
        retval.resize(offsetof(tlv_type_length_value_t, value) + sizeof(data));
        header = reinterpret_cast<decltype(header)>(retval.data());
        header->type = static_cast<uint16_t>(tlv_type_t::UINT);
        header->length = retval.size();
        memcpy(header->value, &data, sizeof(data));
    }
    return retval;
}

inline const tlv_type_length_value_t*
tlv_next(const tlv_type_length_value_t* current_tlv)
{
    return reinterpret_cast<const tlv_type_length_value_t*>(
        reinterpret_cast<const uint8_t*>(current_tlv) + current_tlv->length);
}

inline const tlv_type_length_value_t*
tlv_child(const tlv_type_length_value_t* current_tlv)
{
    return reinterpret_cast<const tlv_type_length_value_t*>(current_tlv->value);
}

template <typename inner_type>
inline inner_type
tlv_value(const tlv_type_length_value_t* tlv)
{
    if constexpr (std::is_same<inner_type, std::string>::value) {
        std::string value;
        value.insert(
            0, reinterpret_cast<const char*>(tlv->value), tlv->length - offsetof(tlv_type_length_value_t, value));
        return value;
    } else {
        return *reinterpret_cast<const inner_type*>(tlv->value);
    }
}
