// Copyright (C) Microsoft.
// SPDX-License-Identifier: MIT
#pragma once

#define TOKEN_FILENAME L"filename"
#define TOKEN_LEVEL    L"level"
#define TOKEN_SECTION  L"section"
#define TOKEN_PINNED   L"pinned"
#define TOKEN_TYPE     L"type"
#define TOKEN_EXECUTION L"execution"

typedef enum {
    VL_NORMAL = 0,
    VL_VERBOSE = 1,
} VERBOSITY_LEVEL;

extern TOKEN_VALUE g_LevelEnum[2];
