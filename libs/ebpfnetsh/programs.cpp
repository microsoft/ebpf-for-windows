// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <string>
#include <vector>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <netsh.h>
#include "ebpf_windows.h"
#include "programs.h"
#include "tokens.h"

#include "ebpf_api.h"
#include <iostream>
#include <iomanip>

class program_state_t final
{
  public:
    std::string program_filename;
    std::string program_section;
    ebpf_handle_t program_handle;
    ebpf_handle_t link_handle;
    ebpf_handle_t map_handles[10];

    program_state_t(std::string filename, std::string section)
        : program_filename(filename), program_section(section), program_handle(INVALID_HANDLE_VALUE),
          link_handle(INVALID_HANDLE_VALUE)
    {
        for (int i = 0; i < _countof(map_handles); i++) {
            map_handles[i] = INVALID_HANDLE_VALUE;
        }
    }

    void
    clean(void)
    {
        close_handle(&link_handle);
        close_handle(&program_handle);
        for (int i = 0; i < _countof(map_handles); i++) {
            close_handle(&map_handles[i]);
        }
    }

  private:
    void
    close_handle(ebpf_handle_t* handle)
    {
        if (*handle != INVALID_HANDLE_VALUE) {
            ebpf_api_close_handle(*handle);
            *handle = INVALID_HANDLE_VALUE;
        }
    }
};

static std::vector<program_state_t> _programs;

typedef enum
{
    PINNED_ANY = 0,
    PINNED_YES = 1,
    PINNED_NO = 2,
} PINNED_CONSTRAINT;

static TOKEN_VALUE _pinned_enum[] = {
    {L"any", PINNED_ANY},
    {L"yes", PINNED_YES},
    {L"no", PINNED_NO},
};

// TODO: ebpf_attach_type_index_t, _ebpf_attach_type_enum, and
// _ebpf_attach_type_guids should all be replaced as soon as we
// can query the information from ebpfapi.

// Index into the _ebpf_attach_type_guids array below (this need
// not match an integer used anywhere outside this file).
typedef enum _ebpf_attach_type_index
{
    EBPF_ATTACH_TYPE_UNSPECIFIED_INDEX = 0,
    EBPF_ATTACH_TYPE_XDP_INDEX = 1,
    EBPF_ATTACH_TYPE_BIND_INDEX = 2
} ebpf_attach_type_index_t;

static TOKEN_VALUE _ebpf_attach_type_enum[] = {
    {L"unknown", EBPF_ATTACH_TYPE_UNSPECIFIED_INDEX},
    {L"xdp", EBPF_ATTACH_TYPE_XDP_INDEX},
    {L"bind", EBPF_ATTACH_TYPE_BIND_INDEX},

};

GUID _ebpf_attach_type_guids[] = {
    EBPF_ATTACH_TYPE_UNSPECIFIED,
    EBPF_ATTACH_TYPE_XDP,
    EBPF_ATTACH_TYPE_BIND,
};

static TOKEN_VALUE _ebpf_execution_type_enum[] = {
    {L"jit", EBPF_EXECUTION_JIT},
    {L"interpret", EBPF_EXECUTION_INTERPRET},

};

std::string
down_cast_from_wstring(const std::wstring& wide_string);

unsigned long
handle_ebpf_add_program(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {{TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
                       {TOKEN_SECTION, NS_REQ_PRESENT, FALSE},
                       {TOKEN_TYPE, NS_REQ_ZERO, FALSE},
                       {TOKEN_PINNED, NS_REQ_ZERO, FALSE},
                       {TOKEN_EXECUTION, NS_REQ_ZERO, FALSE}};
    ULONG tag_type[_countof(tags)] = {0};

    ULONG status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    std::string filename;
    std::string pinned;
    std::string section = ""; // Use the first code section by default.
    ebpf_attach_type_t attach_type = EBPF_ATTACH_TYPE_XDP;
    ebpf_execution_type_t execution = EBPF_EXECUTION_JIT;
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case 0: // FILENAME
        {
            filename = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case 1: // SECTION
        {
            section = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case 2: // TYPE
        {
            ebpf_attach_type_index_t attach_type_index;
            status = MatchEnumTag(
                NULL,
                argv[current_index + i],
                _countof(_ebpf_attach_type_enum),
                _ebpf_attach_type_enum,
                (PULONG)&attach_type_index);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            } else {
                attach_type = _ebpf_attach_type_guids[attach_type_index];
            }
            break;
        }
        case 3: // PINNED
            pinned = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        case 4: // EXECUTION
            status = MatchEnumTag(
                NULL,
                argv[current_index + i],
                _countof(_ebpf_execution_type_enum),
                _ebpf_execution_type_enum,
                (PULONG)&execution);
            break;
        default:
            status = ERROR_INVALID_SYNTAX;
            break;
        }
    }
    if (status != NO_ERROR) {
        return status;
    }

    const char* error_message = nullptr;
    program_state_t program(filename, section);
    uint32_t count_of_map_handles = _countof(program.map_handles);
    status = ebpf_api_load_program(
        filename.c_str(),
        section.c_str(),
        execution,
        &program.program_handle,
        &count_of_map_handles,
        program.map_handles,
        &error_message);
    if (status != ERROR_SUCCESS) {
        if (error_message != nullptr) {
            std::cerr << error_message << std::endl;
        } else {
            std::cerr << "error " << status << ": could not load program" << std::endl;
        }
        ebpf_free_string(error_message);
        program.clean();
        return ERROR_SUPPRESS_OUTPUT;
    }

    status = ebpf_api_link_program(program.program_handle, attach_type, &program.link_handle);
    if (status != ERROR_SUCCESS) {
        std::cerr << "error " << status << ": could not attach program, unloading it" << std::endl;
        program.clean();
        return ERROR_SUPPRESS_OUTPUT;
    }

    if (!pinned.empty()) {
        // TODO (issue #83) replace ebpf_api_pin_object with ebpf_program_pin (aka bpf_program__pin)
        // once it exists.
        status = ebpf_api_pin_object(
            program.program_handle, reinterpret_cast<const uint8_t*>(pinned.c_str()), (uint32_t)pinned.length());
        if (status != ERROR_SUCCESS) {
            std::cerr << "error " << status << ": could not pin program, unloading it" << std::endl;
            program.clean();
            return ERROR_SUPPRESS_OUTPUT;
        }
    }

    _programs.push_back(program);
    return ERROR_SUCCESS;
}

static fd_t
_find_program_fd(const char* filename, const char* section)
{
    fd_t program_fd = ebpf_fd_invalid;
    for (;;) {
        fd_t next_program_fd;
        ebpf_result_t status = ebpf_get_next_program(program_fd, &next_program_fd);
        if (status != EBPF_SUCCESS) {
            break;
        }
        if (program_fd != ebpf_fd_invalid) {
            ebpf_close_fd(program_fd);
        }

        program_fd = next_program_fd;
        if (program_fd == ebpf_fd_invalid) {
            break;
        }

        const char* program_file_name;
        const char* program_section_name;
        ebpf_execution_type_t program_execution_type;
        status =
            ebpf_program_query_info(program_fd, &program_execution_type, &program_file_name, &program_section_name);
        if (status != ERROR_SUCCESS) {
            break;
        }

        bool found = (strcmp(program_file_name, filename) == 0 && strcmp(program_section_name, section) == 0);

        ebpf_free_string(program_file_name);
        ebpf_free_string(program_section_name);

        if (found) {
            return program_fd;
        }
    }

    if (program_fd != ebpf_fd_invalid) {
        ebpf_close_fd(program_fd);
    }
    return ebpf_fd_invalid;
}

DWORD
handle_ebpf_delete_program(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {
        {TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
        {TOKEN_SECTION, NS_REQ_ZERO, FALSE},
    };
    ULONG tag_type[_countof(tags)] = {0};

    ULONG status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    std::string filename;
    std::string section = ""; // Use the first code section by default.
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case 0: // FILENAME
        {
            filename = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case 1: // SECTION
        {
            section = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        default:
            status = ERROR_INVALID_SYNTAX;
            break;
        }
    }
    if (status != NO_ERROR) {
        return status;
    }

    // TODO: If the program is pinned, unpin the specified program.
    // TODO (issue #83): call ebpf_program_unpin() once it exists.
    // The temporary API ebpf_api_unpin_object requires knowing the name a priori
    // and we have no way to get it yet.

    // Remove from our list of programs to release our own reference if we took one.
    // If there are no other references to the program, it will be unloaded.
    auto found = std::find_if(_programs.begin(), _programs.end(), [filename, section](program_state_t& program) {
        return program.program_filename == filename && program.program_section == section;
    });
    if (found != _programs.end()) {
        found->clean();
        _programs.erase(found);
    } else {
        std::cout << "Program not found\n";
        return ERROR_SUPPRESS_OUTPUT;
    }

    // TODO: see if the program is still loaded, in which case some other process holds
    // a reference. Get the PID of that process and display it.

    return ERROR_SUCCESS;
}

DWORD
handle_ebpf_set_program(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {
        {TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
        {TOKEN_SECTION, NS_REQ_PRESENT, FALSE},
        {TOKEN_PINNED, NS_REQ_ZERO, FALSE},
    };
    ULONG tag_type[_countof(tags)] = {0};

    ULONG status = PreprocessCommand(
        nullptr,
        argv,
        current_index,
        argc,
        tags,
        _countof(tags),
        0,
        3, // Two required tags plus at least one optional tag.
        tag_type);

    std::string filename;
    std::string section = ""; // Use the first code section by default.
    std::string pinned;
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case 0: // FILENAME
        {
            filename = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case 1: // SECTION
        {
            section = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case 2: // PINNED
            pinned = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        default:
            status = ERROR_INVALID_SYNTAX;
            break;
        }
    }
    if (status != NO_ERROR) {
        return status;
    }

    if (pinned.empty()) {
        // TODO (issue #190): call ebpf_program_unpin() once it exists.
        // The temporary API ebpf_api_unpin_object requires knowing the name a priori
        // and we have no way to get it.
        return ERROR_CALL_NOT_IMPLEMENTED;
    } else {
        // Try to find the program with the specified filename and section.
        fd_t program_fd = _find_program_fd(filename.c_str(), section.c_str());
        if (program_fd == ebpf_fd_invalid) {
            std::cerr << "Program not found." << std::endl;
            return ERROR_SUPPRESS_OUTPUT;
        }

        // TODO (issue #83) replace ebpf_api_pin_object with ebpf_program_pin (aka bpf_program__pin)
        // once it exists.
        status = ebpf_object_pin(program_fd, pinned.c_str());
        if (status != EBPF_SUCCESS) {
            std::cerr << "error " << status << ": could not pin program" << std::endl;
            return ERROR_SUPPRESS_OUTPUT;
        }

        ebpf_close_fd(program_fd);
    }

    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD
handle_ebpf_show_programs(
    LPCWSTR machine, LPWSTR* argv, DWORD current_index, DWORD argc, DWORD flags, LPCVOID data, BOOL* done)
{
    UNREFERENCED_PARAMETER(machine);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(done);

    TAG_TYPE tags[] = {
        {TOKEN_TYPE, NS_REQ_ZERO, FALSE},
        {TOKEN_PINNED, NS_REQ_ZERO, FALSE},
        {TOKEN_LEVEL, NS_REQ_ZERO, FALSE},
        {TOKEN_FILENAME, NS_REQ_ZERO, FALSE},
        {TOKEN_SECTION, NS_REQ_ZERO, FALSE},
    };
    ULONG tag_type[_countof(tags)] = {0};

    ULONG status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    ebpf_attach_type_t attach_type = EBPF_ATTACH_TYPE_XDP;
    PINNED_CONSTRAINT pinned = PINNED_ANY;
    VERBOSITY_LEVEL level = VL_NORMAL;
    std::string filename;
    std::string section;
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case 0: // TYPE
        {
            ebpf_attach_type_index_t attach_type_index;
            status = MatchEnumTag(
                NULL,
                argv[current_index + i],
                _countof(_ebpf_attach_type_enum),
                _ebpf_attach_type_enum,
                (PULONG)&attach_type_index);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            } else {
                attach_type = _ebpf_attach_type_guids[attach_type_index];
            }
            break;
        }
        case 1: // PINNED
            status = MatchEnumTag(NULL, argv[current_index + i], _countof(_pinned_enum), _pinned_enum, (PULONG)&pinned);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        case 2: // LEVEL
            status = MatchEnumTag(NULL, argv[current_index + i], _countof(g_LevelEnum), g_LevelEnum, (PULONG)&level);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        case 3: // FILENAME
        {
            filename = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case 4: // SECTION
        {
            section = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        default:
            status = ERROR_INVALID_SYNTAX;
            break;
        }
    }
    if (status != NO_ERROR) {
        return status;
    }

    // If the user specified a filename and no level, default to verbose.
    if (tags[3].bPresent && !tags[2].bPresent) {
        level = VL_VERBOSE;
    }

    // TODO(issue #83): We need to implement level, other columns, and implement filtering by pinned.

    std::cout << "\n";
    std::cout << "           File Name          Section  Requested Execution Type\n";
    std::cout << "====================  ===============  ========================\n";

    fd_t program_fd = ebpf_fd_invalid;
    for (;;) {
        const char* program_file_name;
        const char* program_section_name;
        const char* program_type_name;
        ebpf_execution_type_t program_execution_type;
        fd_t next_program_fd;
        status = ebpf_get_next_program(program_fd, &next_program_fd);
        if (status != ERROR_SUCCESS) {
            break;
        }

        if (program_fd != ebpf_fd_invalid) {
            ebpf_close_fd(program_fd);
        }
        program_fd = next_program_fd;

        if (program_fd == ebpf_fd_invalid) {
            break;
        }

        // TODO(issue #83): we also need the program type so we can filter on it.
        status =
            ebpf_program_query_info(program_fd, &program_execution_type, &program_file_name, &program_section_name);

        if (status != ERROR_SUCCESS) {
            break;
        }

        if (filename.empty() || strcmp(program_file_name, filename.c_str()) == 0) {
            if (section.empty() || strcmp(program_section_name, section.c_str()) == 0) {
                program_type_name = program_execution_type == EBPF_EXECUTION_JIT ? "JIT" : "INTERPRET";
                std::cout << std::setw(20) << std::right << program_file_name << "  " << std::setw(15) << std::right
                          << program_section_name << "  " << std::setw(24) << std::right << program_type_name << "\n";
            }
        }

        ebpf_free_string(program_file_name);
        ebpf_free_string(program_section_name);
    }
    if (program_fd != ebpf_fd_invalid) {
        ebpf_close_fd(program_fd);
    }
    return status;
}
