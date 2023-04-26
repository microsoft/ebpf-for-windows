// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once

#define TOKEN_ATTACHED L"attached"
#define TOKEN_COMPARTMENT L"compartment"
#define TOKEN_EXECUTION L"execution"
#define TOKEN_FILENAME L"filename"
#define TOKEN_ID L"id"
#define TOKEN_INTERFACE L"interface"
#define TOKEN_LEVEL L"level"
#define TOKEN_PINNED L"pinned"
#define TOKEN_PINPATH L"pinpath"
#define TOKEN_SECTION L"section"
#define TOKEN_TYPE L"type"

typedef enum
{
    VL_NORMAL = 0,
    VL_VERBOSE = 1,
} VERBOSITY_LEVEL;

extern TOKEN_VALUE g_LevelEnum[2];
