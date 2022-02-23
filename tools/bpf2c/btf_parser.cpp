// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "btf_parser.h"

#include <stdexcept>
#include <string.h>

#include "btf.h"
#include <ebpf.h>

btf_section_to_instruction_to_line_info_t
btf_parse_line_information(const std::vector<uint8_t>& btf, const std::vector<uint8_t>& btf_ext)
{
    btf_section_to_instruction_to_line_info_t section_line_info;
    std::map<size_t, std::string> string_table;

    auto btf_header = reinterpret_cast<const btf_header_t*>(btf.data());
    if (btf_header->magic != BTF_HEADER_MAGIC) {
        throw std::runtime_error("Invalid .btf section - wrong magic");
    }
    if (btf_header->version != BTF_HEADER_VERSION) {
        throw std::runtime_error("Invalid .btf section - wrong version");
    }
    if (btf_header->hdr_len < sizeof(btf_header_t)) {
        throw std::runtime_error("Invalid .btf section - wrong size");
    }
    if (btf_header->hdr_len > btf.size()) {
        throw std::runtime_error("Invalid .btf section - invalid header length");
    }
    if (btf_header->str_off > btf.size()) {
        throw std::runtime_error("Invalid .btf section - invalid string offest");
    }
    if ((static_cast<size_t>(btf_header->str_off) + static_cast<size_t>(btf_header->str_len) +
         static_cast<size_t>(btf_header->hdr_len)) > btf.size()) {
        throw std::runtime_error("Invalid .btf section - invalid string length");
    }

    for (size_t offset = btf_header->str_off + static_cast<size_t>(btf_header->hdr_len);
         offset < static_cast<size_t>(btf_header->str_off) + static_cast<size_t>(btf_header->str_len);) {
        size_t remaining_length = btf_header->str_len - offset;
        size_t string_length = strnlen(reinterpret_cast<const char*>(btf.data()) + offset, remaining_length);
        std::string value(reinterpret_cast<const char*>(btf.data()) + offset, string_length);
        size_t string_offset =
            offset - static_cast<size_t>(btf_header->str_off) - static_cast<size_t>(btf_header->hdr_len);
        offset += string_length + 1;
        string_table.insert(std::make_pair(string_offset, value));
    }
    auto bpf_ext_header = reinterpret_cast<const btf_ext_header_t*>(btf_ext.data());
    if (bpf_ext_header->magic != BTF_HEADER_MAGIC) {
        throw std::runtime_error("Invalid .btf.ext section - wrong magic");
    }
    if (bpf_ext_header->version != BTF_HEADER_VERSION) {
        throw std::runtime_error("Invalid .btf.ext section - wrong version");
    }
    if (bpf_ext_header->hdr_len < sizeof(btf_ext_header_t)) {
        throw std::runtime_error("Invalid .btf.ext section - wrong size");
    }
    if (bpf_ext_header->line_info_off > btf_ext.size()) {
        throw std::runtime_error("Invalid .btf.ex section - invalid line info offest");
    }
    if ((static_cast<size_t>(bpf_ext_header->line_info_off) + static_cast<size_t>(bpf_ext_header->line_info_len) +
         static_cast<size_t>(bpf_ext_header->hdr_len)) > btf_ext.size()) {
        throw std::runtime_error("Invalid .btf section - invalid string length");
    }

    uint32_t line_info_record_size = *reinterpret_cast<const uint32_t*>(
        btf_ext.data() + static_cast<size_t>(bpf_ext_header->hdr_len) +
        static_cast<size_t>(bpf_ext_header->line_info_off));

    for (size_t offset = static_cast<size_t>(bpf_ext_header->hdr_len) +
                         static_cast<size_t>(bpf_ext_header->line_info_off) + sizeof(uint32_t);
         offset < static_cast<size_t>(bpf_ext_header->hdr_len) + static_cast<size_t>(bpf_ext_header->line_info_off) +
                      static_cast<size_t>(bpf_ext_header->line_info_len);) {
        auto section_info = reinterpret_cast<const btf_ext_info_sec_t*>(btf_ext.data() + offset);
        auto section_name = string_table.find(section_info->sec_name_off);
        if (section_name == string_table.end()) {
            throw std::runtime_error(
                std::string("Invalid .btf section - invalid string offset ") +
                std::to_string(section_info->sec_name_off));
        }
        for (size_t index = 0; index < section_info->num_info; index++) {
            auto btf_line_info =
                reinterpret_cast<const bpf_line_info_t*>(section_info->data + index * line_info_record_size);
            auto file_name = string_table.find(btf_line_info->file_name_off);
            auto source = string_table.find(btf_line_info->line_off);
            line_info_t line_info;
            if (file_name != string_table.end()) {
                line_info.file_name = file_name->second;
            }
            if (source != string_table.end()) {
                line_info.source_line = source->second;
            }
            line_info.line_number = BPF_LINE_INFO_LINE_NUM(btf_line_info->line_col);
            line_info.column_number = BPF_LINE_INFO_LINE_COL(btf_line_info->line_col);
            if (line_info.line_number == 0) {
                continue;
            }
            section_line_info[section_name->second][btf_line_info->insn_off / sizeof(ebpf_inst)] = line_info;
        }
        offset += offsetof(btf_ext_info_sec_t, data) +
                  static_cast<size_t>(line_info_record_size) * static_cast<size_t>(section_info->num_info);
    }
    return section_line_info;
}
