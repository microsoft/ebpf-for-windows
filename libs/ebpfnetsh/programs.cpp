// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <combaseapi.h>
#include <netsh.h>
#include "bpf.h"
#include "ebpf_api.h"
#include "libbpf.h"
#include "platform.h"
#include "programs.h"
#include "tokens.h"

typedef enum
{
    BC_ANY = 0,
    BC_YES = 1,
    BC_NO = 2,
} BOOLEAN_CONSTRAINT;

static TOKEN_VALUE _boolean_constraint_enum[] = {
    {L"any", BC_ANY},
    {L"yes", BC_YES},
    {L"no", BC_NO},
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

    TAG_TYPE tags[] = {
        {TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
        {TOKEN_TYPE, NS_REQ_ZERO, FALSE},
        {TOKEN_PINNED, NS_REQ_ZERO, FALSE},
        {TOKEN_EXECUTION, NS_REQ_ZERO, FALSE}};
    ULONG tag_type[_countof(tags)] = {0};

    ULONG status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    std::string filename;
    std::string pinned;
    ebpf_program_type_t program_type = EBPF_PROGRAM_TYPE_UNSPECIFIED;
    ebpf_attach_type_t attach_type = EBPF_ATTACH_TYPE_UNSPECIFIED;
    ebpf_execution_type_t execution = EBPF_EXECUTION_JIT;
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case 0: // FILENAME
        {
            filename = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case 1: // TYPE
        {
            std::string type_name = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            ebpf_result_t result = ebpf_get_program_type_by_name(type_name.c_str(), &program_type, &attach_type);
            if (result != EBPF_SUCCESS) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        }
        case 2: // PINNED
            pinned = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        case 3: // EXECUTION
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

    struct bpf_object* object;
    int program_fd;
    PCSTR error_message;
    ebpf_result_t result = ebpf_program_load(
        filename.c_str(),
        (tags[1].bPresent ? &program_type : nullptr),
        (tags[1].bPresent ? &attach_type : nullptr),
        EBPF_EXECUTION_ANY,
        &object,
        &program_fd,
        &error_message);
    if (result != EBPF_SUCCESS) {
        std::cerr << "error " << result << ": could not load program" << std::endl;
        std::cerr << error_message << std::endl;
        ebpf_free_string(error_message);
        return ERROR_SUPPRESS_OUTPUT;
    }

    // TODO(#188): add option to pin all programs in the object.
    struct bpf_program* program = bpf_program__next(nullptr, object);
    struct bpf_link* link;
    result = ebpf_program_attach(program, (tags[1].bPresent ? &attach_type : nullptr), nullptr, 0, &link);
    if (result != EBPF_SUCCESS) {
        std::cerr << "error " << result << ": could not attach program" << std::endl;
        return ERROR_SUPPRESS_OUTPUT;
    }

    if (!pinned.empty()) {
        if (bpf_program__pin(program, pinned.c_str()) < 0) {
            std::cerr << "error " << errno << ": could not pin program" << std::endl;
            return ERROR_SUPPRESS_OUTPUT;
        }
    }

    // Get the ID and display it.
    struct bpf_prog_info info;
    uint32_t info_size = sizeof(info);
    if (bpf_obj_get_info_by_fd(program_fd, &info, &info_size) < 0) {
        std::cerr << "error " << errno << ": loaded program but could not get ID" << std::endl;
        return ERROR_SUPPRESS_OUTPUT;
    }
    std::cout << "Loaded with ID " << info.id << std::endl;

    ebpf_link_close(link);

    return ERROR_SUCCESS;
}

static DWORD
_unpin_program_by_id(ebpf_id_t id)
{
    ebpf_result_t result;
    DWORD status = NO_ERROR;
    char name[EBPF_MAX_PIN_PATH_LENGTH] = {0};

    for (;;) {
        result = ebpf_get_next_pinned_program_name(name, name);
        if (result != EBPF_SUCCESS) {
            break;
        }
        int fd = bpf_obj_get(name);
        if (fd < 0) {
            continue;
        }
        bpf_prog_info info;
        uint32_t info_size = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd, &info, &info_size) == 0) {
            if (id == info.id) {
                result = ebpf_object_unpin(name);
                if (result != EBPF_SUCCESS) {
                    printf("Error %d unpinning %d from %s\n", result, id, name);
                    status = ERROR_SUPPRESS_OUTPUT;
                } else {
                    printf("Unpinned %d from %s\n", id, name);
                }
            }
        }
        Platform::_close(fd);
    }
    return status;
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
        {TOKEN_ID, NS_REQ_PRESENT, FALSE},
    };
    ULONG tag_type[_countof(tags)] = {0};

    ULONG status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    ebpf_id_t id = EBPF_ID_NONE;
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc) && (i < _countof(tag_type)); i++) {
        switch (tag_type[i]) {
        case 0: // ID
        {
            id = (uint32_t)_wtoi(argv[current_index + i]);
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

    // If the program is pinned, unpin the specified program.
    status = _unpin_program_by_id(id);
    if (status != NO_ERROR) {
        return status;
    }

    // Remove from our list of programs to release our own reference if we took one.
    // If there are no other references to the program, it will be unloaded.
    bpf_object* object;
    bpf_object* next_object;
    bpf_object__for_each_safe(object, next_object)
    {
        bpf_program* program;
        bpf_object__for_each_program(program, object)
        {
            int program_fd = bpf_program__fd(program);
            struct bpf_prog_info info;
            uint32_t info_size = sizeof(info);
            if (bpf_obj_get_info_by_fd(program_fd, &info, &info_size) < 0) {
                continue;
            }
            if (info.id == id) {
                bpf_object__close(object);

                // TODO: see if the program is still loaded, in which case some other process holds
                // a reference. Get the PID of that process and display it.

                return NO_ERROR;
            }
        }
    }

    // TODO: see if the program is still loaded, in which case some other process holds
    // a reference. Get the PID of that process and display it.

    std::cout << "Program not found\n";
    return ERROR_SUPPRESS_OUTPUT;
}

ebpf_result_t
ebpf_program_attach_by_id(ebpf_id_t program_id, ebpf_attach_type_t attach_type)
{
    fd_t program_fd = bpf_prog_get_fd_by_id(program_id);
    if (program_fd < 0) {
        return EBPF_INVALID_ARGUMENT;
    }

    struct bpf_link* link;
    ebpf_result_t result = ebpf_program_attach_by_fd(program_fd, &attach_type, nullptr, 0, &link);

    Platform::_close(program_fd);
    ebpf_link_close(link);
    return result;
}

int // errno value
ebpf_program_detach_by_id(ebpf_id_t program_id)
{
    // Use the same APIs as bpftool.
    uint32_t link_id = 0;
    while (bpf_link_get_next_id(link_id, &link_id) == 0) {
        fd_t link_fd = bpf_link_get_fd_by_id(link_id);
        if (link_fd < 0) {
            continue;
        }

        struct bpf_link_info link_info;
        uint32_t info_len = sizeof(link_info);
        if (bpf_obj_get_info_by_fd(link_fd, &link_info, &info_len) == 0) {
            if (link_info.prog_id == program_id) {
                if (bpf_link_detach(link_fd) < 0) {
                    return errno;
                }
                Platform::_close(link_fd);
                return NO_ERROR;
            }
        }
        Platform::_close(link_fd);
    }
    return ERROR_NOT_FOUND;
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
        {TOKEN_ID, NS_REQ_PRESENT, FALSE},
        {TOKEN_ATTACHED, NS_REQ_ZERO, FALSE},
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

    uint32_t id;
    std::string pinned;
    ebpf_attach_type_t attach_type = EBPF_ATTACH_TYPE_UNSPECIFIED;
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case 0: // ID
        {
            id = (uint32_t)_wtoi(argv[current_index + i]);
            break;
        }
        case 1: // ATTACHED
        {
            if (argv[current_index + i][0] != 0) {
                std::string type_name = down_cast_from_wstring(std::wstring(argv[current_index + i]));
                ebpf_program_type_t program_type;
                ebpf_result_t result = ebpf_get_program_type_by_name(type_name.c_str(), &program_type, &attach_type);
                if (result != EBPF_SUCCESS) {
                    status = ERROR_INVALID_SYNTAX;
                }
            }
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

    if (tags[1].bPresent) {
        if (memcmp(&attach_type, &EBPF_ATTACH_TYPE_UNSPECIFIED, sizeof(ebpf_attach_type_t)) != 0) {
            ebpf_result_t result = ebpf_program_attach_by_id(id, attach_type);
            if (result != NO_ERROR) {
                std::cerr << "error " << result << ": could not detach program" << std::endl;
                return ERROR_SUPPRESS_OUTPUT;
            }
        } else {
            int error = ebpf_program_detach_by_id(id);
            if (error != NO_ERROR) {
                std::cerr << "error " << error << ": could not detach program" << std::endl;
                return ERROR_SUPPRESS_OUTPUT;
            }
        }
    }

    if (tags[2].bPresent) {
        if (pinned.empty()) {
            // Unpin a program from all names to which it is currently pinned.
            return _unpin_program_by_id(id);
        } else {
            // Try to find the program with the specified ID.
            fd_t program_fd = bpf_prog_get_fd_by_id(id);
            if (program_fd == ebpf_fd_invalid) {
                std::cerr << "Program not found." << std::endl;
                return ERROR_SUPPRESS_OUTPUT;
            }

            status = bpf_obj_pin(program_fd, pinned.c_str());
            if (status != EBPF_SUCCESS) {
                std::cerr << "error " << status << ": could not pin program" << std::endl;
                return ERROR_SUPPRESS_OUTPUT;
            }

            Platform::_close(program_fd);
        }
    }

    return ERROR_OKAY;
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
        {TOKEN_ATTACHED, NS_REQ_ZERO, FALSE},
        {TOKEN_PINNED, NS_REQ_ZERO, FALSE},
        {TOKEN_LEVEL, NS_REQ_ZERO, FALSE},
        {TOKEN_FILENAME, NS_REQ_ZERO, FALSE},
        {TOKEN_SECTION, NS_REQ_ZERO, FALSE},
        {TOKEN_ID, NS_REQ_ZERO, FALSE},
    };
    ULONG tag_type[_countof(tags)] = {0};

    ULONG status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    ebpf_program_type_t program_type = EBPF_PROGRAM_TYPE_UNSPECIFIED;
    BOOLEAN_CONSTRAINT attached = BC_ANY;
    BOOLEAN_CONSTRAINT pinned = BC_ANY;
    VERBOSITY_LEVEL level = VL_NORMAL;
    std::string filename;
    std::string section;
    ebpf_id_t id = 0;
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case 0: // TYPE
        {
            std::string type_name = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            ebpf_attach_type_t expected_attach_type;
            ebpf_result_t result =
                ebpf_get_program_type_by_name(type_name.c_str(), &program_type, &expected_attach_type);
            if (result != EBPF_SUCCESS) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        }
        case 1: // ATTACHED
            status = MatchEnumTag(
                NULL,
                argv[current_index + i],
                _countof(_boolean_constraint_enum),
                _boolean_constraint_enum,
                (PULONG)&attached);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        case 2: // PINNED
            status = MatchEnumTag(
                NULL,
                argv[current_index + i],
                _countof(_boolean_constraint_enum),
                _boolean_constraint_enum,
                (PULONG)&pinned);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        case 3: // LEVEL
            status = MatchEnumTag(NULL, argv[current_index + i], _countof(g_LevelEnum), g_LevelEnum, (PULONG)&level);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        case 4: // FILENAME
        {
            filename = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case 5: // SECTION
        {
            section = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case 6: // ID
        {
            id = (uint32_t)_wtoi(argv[current_index + i]);
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

    // TODO(#188): We need to implement level, other columns, and implement filtering by attached and pinned.

    std::cout << "\n";
    std::cout << "    ID            File Name         Section             Name      Mode\n";
    std::cout << "====== ==================== =============== ================ =========\n";

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
            Platform::_close(program_fd);
        }
        program_fd = next_program_fd;

        if (program_fd == ebpf_fd_invalid) {
            break;
        }

        struct bpf_prog_info info;
        uint32_t info_size = (uint32_t)sizeof(info);
        int error = bpf_obj_get_info_by_fd(program_fd, &info, &info_size);
        if (error < 0) {
            break;
        }

        if ((id != 0) && (info.id != id)) {
            continue;
        }
        if (tags[0].bPresent && (memcmp(&info.type_uuid, &program_type, sizeof(program_type)) != 0)) {
            continue;
        }

        status =
            ebpf_program_query_info(program_fd, &program_execution_type, &program_file_name, &program_section_name);
        if (status != ERROR_SUCCESS) {
            break;
        }

        if (filename.empty() || strcmp(program_file_name, filename.c_str()) == 0) {
            if (section.empty() || strcmp(program_section_name, section.c_str()) == 0) {
                program_type_name = program_execution_type == EBPF_EXECUTION_JIT ? "JIT" : "INTERPRET";
                printf(
                    "%6u %20s %15s %16s %9s\n",
                    info.id,
                    program_file_name,
                    program_section_name,
                    info.name,
                    program_type_name);
            }
        }

        ebpf_free_string(program_file_name);
        ebpf_free_string(program_section_name);
    }
    if (program_fd != ebpf_fd_invalid) {
        Platform::_close(program_fd);
    }
    return status;
}
