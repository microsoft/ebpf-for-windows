// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "CLI11.hpp"
#include "elfio/elfio.hpp"
#include "framework.h"
#include "win_ebpf.hpp"

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

using std::string;
using std::vector;

// Section name MUST indicate the program type.
static BpfProgType
section_to_progtype(const std::string& section)
{
    if (section.find("xdp") != std::string::npos) {
        return BpfProgType::XDP;
    }
    return BpfProgType::UNSPEC;
}

// template <typename T>
static vector<char>
vector_of(ELFIO::section* sec)
{
    if (!sec) {
        return {};
    }
    auto data = sec->get_data();
    auto size = sec->get_size();
    // assert(size % sizeof(T) == 0);
    return {(char*)data, (char*)(data + size)};
}

vector<raw_program>
read_elf(const std::string& path, const std::string& desired_section)
{
    ELFIO::elfio reader;
    if (!reader.load(path)) {
        throw std::runtime_error(string("Can't find or process ELF file ") + path);
    }

    vector<raw_program> res;
    program_info info;

    // Go through the sections to find the required section.
    // Extract the instructions to be passed to the jitter.
    for (const auto section : reader.sections) {
        const string name = section->get_name();
        std::cout << "section " << name << endl;

        if (!desired_section.empty() && name != desired_section) {
            continue;
        }
        if (name == "license" || name == "version" || name == "maps") {
            continue;
        }
        if (name != ".text" && name.find('.') == 0) {
            continue;
        }
        info.program_type = section_to_progtype(name);

        if (section->get_size() == 0) {
            continue;
        }
        raw_program prog{path, name, vector_of(section), info};

        res.push_back(prog);
    }

    if (res.empty()) {
        throw std::runtime_error(string("Can't find section ") + desired_section + " in file " + path);
    }
    return res;
}

int __cdecl main(int argc, char** argv)
{
    CLI::App app{"Elf Reader"};

    std::string filename;
    app.add_option("path", filename, "Path to elf file")->required()->type_name("FILE");

    std::string desired_section;
    app.add_option("section", desired_section, "Section name")->type_name("SECTION");

    bool list = false;
    app.add_flag("-l", list, "List sections");

    CLI11_PARSE(app, argc, argv);

    // load elf file
    vector<raw_program> raw_progs = read_elf(filename, desired_section);

    // Print out the sections
    if (list || raw_progs.size() != 1) {
        // sections
        for (const raw_program& raw_prog : raw_progs) {
            std::cout << raw_prog.section << " ";
            // raw instructions
            if (raw_prog.section == ".text") {
                int count = 0;
                std::cout << endl;
                for (char inst : raw_prog.prog) {
                    std::cout << " 0x" << std::hex << (int)inst;
                    // new line after 8 bytes
                    if (count++ == 7) {
                        std::cout << endl;
                        count = 0;
                    }
                }
            }
        }
        std::cout << endl;
    }
    return 0;
}
