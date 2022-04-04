/*++

Copyright (c) Microsoft Corporation

Module Name:

EverParseEndianness.h

Abstract:

This is an EverParse-related file to read integer values from raw
bytes.

Authors:

nswamy, protz, taramana 5-Feb-2020

--*/
/* This is a hand-written header that selectively includes relevant bits from
 * kremlib.h -- it has to be updated manually to track upstream changes. */

#pragma once

/*****************************************************************************
 ********* Implementation of LowStar.Endianness (selected bits) **************
 *****************************************************************************/

#include <string.h>

/* ... for Windows (MSVC)... not targeting XBOX 360! */

#include <stdlib.h>
#include <stdint.h>

#include <windef.h>

typedef const char* EverParseString;
typedef EverParseString PrimsString;

#define htobe16(x) _byteswap_ushort(x)
#define htole16(x) (x)
#define be16toh(x) _byteswap_ushort(x)
#define le16toh(x) (x)

#define htobe32(x) _byteswap_ulong(x)
#define htole32(x) (x)
#define be32toh(x) _byteswap_ulong(x)
#define le32toh(x) (x)

#define htobe64(x) _byteswap_uint64(x)
#define htole64(x) (x)
#define be64toh(x) _byteswap_uint64(x)
#define le64toh(x) (x)

inline static uint16_t
Load16(uint8_t* b)
{
    uint16_t x;
    memcpy(&x, b, 2);
    return x;
}

inline static uint32_t
Load32(uint8_t* b)
{
    uint32_t x;
    memcpy(&x, b, 4);
    return x;
}

inline static uint64_t
Load64(uint8_t* b)
{
    uint64_t x;
    memcpy(&x, b, 8);
    return x;
}

inline static void
Store16(uint8_t* b, uint16_t i)
{
    memcpy(b, &i, 2);
}

inline static void
Store32(uint8_t* b, uint32_t i)
{
    memcpy(b, &i, 4);
}

inline static void
Store64(uint8_t* b, uint64_t i)
{
    memcpy(b, &i, 8);
}

#define Load16Le(b) (le16toh(Load16(b)))
#define Store16Le(b, i) (Store16(b, htole16(i)))
#define Load16Be(b) (be16toh(Load16(b)))
#define Store16Be(b, i) (Store16(b, htobe16(i)))

#define Load32Le(b) (le32toh(Load32(b)))
#define Store32Le(b, i) (Store32(b, htole32(i)))
#define Load32Be(b) (be32toh(Load32(b)))
#define Store32Be(b, i) (Store32(b, htobe32(i)))

#define Load64Le(b) (le64toh(Load64(b)))
#define Store64Le(b, i) (Store64(b, htole64(i)))
#define Load64Be(b) (be64toh(Load64(b)))
#define Store64Be(b, i) (Store64(b, htobe64(i)))
