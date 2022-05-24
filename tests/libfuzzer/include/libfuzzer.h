// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#if defined(_DEBUG)
#pragma comment(lib, "clang_rt.fuzzer_MDd-x86_64.lib")
#pragma comment(lib, "libsancov.lib")
#else
#pragma comment(lib, "clang_rt.fuzzer_MD-x86_64.lib")
#pragma comment(lib, "libsancov.lib")
#endif

#ifdef __cplusplus
#define FUZZ_EXPORT extern "C" __declspec(dllexport)
#else #define FUZZ_EXPORT __declspec(dllexport)
#endif
