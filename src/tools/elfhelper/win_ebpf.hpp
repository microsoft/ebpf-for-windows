// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#pragma once
#ifndef _WIN_EBPF_H
#define _WIN_EBPF_H

#include <cinttypes>
using namespace std;

// ebpf instruction schema
struct ebpf_inst
{
    uint8_t opcode;
    uint8_t dst : 4; //< Destination register
    uint8_t src : 4; //< Source register
    int16_t offset;
    int32_t imm; //< Immediate constant
};

enum class BpfProgType : int
{
    UNSPEC,
    XDP
};

enum class MapType : unsigned int
{
    UNSPEC,
    HASH,
    ARRAY
};

struct map_def
{
    int original_fd;
    MapType type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int inner_map_fd;
};

struct ptype_descr
{
    int size{};
    int data = -1;
    int end = -1;
    int meta = -1; // data to meta is like end to data. i.e. meta <= data <= end
};

struct program_info
{
    BpfProgType program_type;
    std::vector<map_def> map_defs;
    ptype_descr descriptor;
};

extern program_info global_program_info;

struct raw_program
{
    std::string filename;
    std::string section;
    std::vector<char> prog;
    program_info info;
};

constexpr int xdp_regions = 5 * 4;
constexpr ptype_descr xdp_md = {xdp_regions, 0, 1 * 4, 2 * 4};

#endif // ! _WIN_EBPF_H
