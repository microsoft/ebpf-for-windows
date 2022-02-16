// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once
#include <map>
#include <stdint.h>
#include <string>
#include <vector>

typedef struct _line_info
{
    std::string file_name;
    std::string source_line;
    uint32_t line_number = {};
    uint32_t column_number = {};
} line_info_t;

typedef std::map<std::string, std::map<size_t, line_info_t>> btf_section_to_instruction_to_line_info_t;

/**
 * @brief Parse a .btf and .btf.ext section from an ELF file.
 *
 * @param[in] btf The .btf section (containing type info and strings).
 * @param[in] btf_ext The .btf.ext section (containing function info and
 * line info).
 * @return Map of section name to map of offset to line information.
 */
btf_section_to_instruction_to_line_info_t
btf_parse_line_information(const std::vector<uint8_t>& btf, const std::vector<uint8_t>& btf_ext);
