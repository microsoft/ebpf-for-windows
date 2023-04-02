// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "platform.h"
#include "programs.h"
#include "tokens.h"
#include "utilities.h"

#include <iomanip>
#include <set>
#include <string>
#include <vector>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <combaseapi.h>
#include <netsh.h>

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

typedef enum
{
    PT_NONE,  // Don't pin any programs in an eBPF object.
    PT_FIRST, // Pin only the first program in an object.
    PT_ALL,   // Pin all programs in an object.
} pinned_type_t;

static TOKEN_VALUE _ebpf_pinned_type_enum[] = {
    {L"none", PT_NONE},
    {L"first", PT_FIRST},
    {L"all", PT_ALL},
};

std::vector<struct bpf_object*> _ebpf_netsh_objects;

bool
_prog_type_supports_interface(bpf_prog_type prog_type)
{
    return (prog_type == BPF_PROG_TYPE_XDP);
}

_Must_inspect_result_ ebpf_result_t
_process_interface_parameter(
    _In_ const _Null_terminated_ wchar_t* interface_parameter, bpf_prog_type prog_type, _Out_ uint32_t* if_index)
{
    ebpf_result_t result = EBPF_SUCCESS;
    if (_prog_type_supports_interface(prog_type)) {
        result = parse_if_index(interface_parameter, if_index);
        if (result != EBPF_SUCCESS) {
            std::cerr << "Interface parameter is invalid." << std::endl;
        }
    } else {
        std::cerr << "Interface parameter is not allowed for program types that don't support interfaces." << std::endl;
        result = EBPF_INVALID_ARGUMENT;
    }
    return result;
}

struct _program_unloader
{
    struct bpf_object* object;
    ~_program_unloader() { bpf_object__close(object); }
};

struct _link_deleter
{
    struct bpf_link* link;
    ~_link_deleter()
    {
        if (link != nullptr) {
            ebpf_link_close(link);
        }
    }
};

// The following function uses windows specific input type to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
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
        {TOKEN_PINPATH, NS_REQ_ZERO, FALSE},
        {TOKEN_INTERFACE, NS_REQ_ZERO, FALSE},
        {TOKEN_PINNED, NS_REQ_ZERO, FALSE},
        {TOKEN_EXECUTION, NS_REQ_ZERO, FALSE}};
    const int FILENAME_INDEX = 0;
    const int TYPE_INDEX = 1;
    const int PINPATH_INDEX = 2;
    const int INTERFACE_INDEX = 3;
    const int PINNED_INDEX = 4;
    const int EXECUTION_INDEX = 5;

    unsigned long tag_type[_countof(tags)] = {0};

    unsigned long status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    std::string filename;
    std::string pinpath;
    bpf_prog_type prog_type = BPF_PROG_TYPE_UNSPEC;
    bpf_attach_type attach_type = BPF_ATTACH_TYPE_UNSPEC;
    pinned_type_t pinned_type = PT_FIRST; // Like bpftool, we default to pin first.
    ebpf_execution_type_t execution = EBPF_EXECUTION_JIT;
    wchar_t* interface_parameter = nullptr;

    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case FILENAME_INDEX: {
            filename = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case TYPE_INDEX: {
            std::string type_name = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            if (libbpf_prog_type_by_name(type_name.c_str(), &prog_type, &attach_type) < 0) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        }
        case INTERFACE_INDEX: {
            interface_parameter = argv[current_index + i];
            break;
        }
        case PINPATH_INDEX:
            pinpath = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        case PINNED_INDEX:
            status = MatchEnumTag(
                NULL,
                argv[current_index + i],
                _countof(_ebpf_pinned_type_enum),
                _ebpf_pinned_type_enum,
                (unsigned long*)&pinned_type);
            break;
        case EXECUTION_INDEX:
            status = MatchEnumTag(
                NULL,
                argv[current_index + i],
                _countof(_ebpf_execution_type_enum),
                _ebpf_execution_type_enum,
                (unsigned long*)&execution);
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
    object = bpf_object__open(filename.c_str());
    if (object == nullptr) {
        std::cerr << "error " << errno << ": could not open file" << std::endl;
        return ERROR_SUPPRESS_OUTPUT;
    }

    struct bpf_program* program = bpf_object__next_program(object, nullptr);
    if (prog_type != BPF_PROG_TYPE_UNSPEC) {
        bpf_program__set_type(program, prog_type);
    }

    if (bpf_object__load(object) < 0) {
        std::cerr << "error " << errno << ": could not load program" << std::endl;
        size_t error_message_size;
        error_message = bpf_program__log_buf(program, &error_message_size);
        if (error_message != nullptr) {
            std::cerr << error_message << std::endl;
        }
        bpf_object__close(object);
        return ERROR_SUPPRESS_OUTPUT;
    }
    program_fd = bpf_program__fd(program);

    // Program loaded. Populate the unloader with object pointer, such that
    // the program gets unloaded automatically, if this function fails somewhere.
    struct _program_unloader unloader = {object};

    ebpf_result_t result;
    uint32_t if_index;
    void* attach_parameters = nullptr;
    size_t attach_parameters_size = 0;
    if (interface_parameter != nullptr) {
        result = _process_interface_parameter(interface_parameter, bpf_program__type(program), &if_index);
        if (result == EBPF_SUCCESS) {
            attach_parameters = &if_index;
            attach_parameters_size = sizeof(if_index);
        } else {
            return ERROR_SUPPRESS_OUTPUT;
        }
    }

    struct bpf_link* link;
    result = ebpf_program_attach(program, nullptr, attach_parameters, attach_parameters_size, &link);
    if (result != EBPF_SUCCESS) {
        std::cerr << "error " << result << ": could not attach program" << std::endl;
        return ERROR_SUPPRESS_OUTPUT;
    }

    // Link attached. Populate the deleter with link pointer, such that link
    // object is closed when the function returns.
    struct _link_deleter link_deleter = {link};

    if (pinned_type == PT_FIRST) {
        // The pinpath specified is like a "file" under which to pin programs.
        // This matches the "bpftool prog load" behavior.
        if (pinpath.empty()) {
            pinpath = bpf_program__name(program);
        }
        if (bpf_program__pin(program, pinpath.c_str()) < 0) {
            std::cerr << "error " << errno << ": could not pin to " << pinpath << std::endl;
            return ERROR_SUPPRESS_OUTPUT;
        }
    } else if (pinned_type == PT_ALL) {
        // The pinpath specified is like a "directory" under which to pin programs.
        // This matches the "bpftool prog loadall" behavior.
        if (bpf_object__pin_programs(object, pinpath.c_str()) < 0) {
            std::cerr << "error " << errno << ": could not pin to " << pinpath << std::endl;
            return ERROR_SUPPRESS_OUTPUT;
        }
    }

    // Get the ID and display it.
    struct bpf_prog_info info = {};
    uint32_t info_size = sizeof(info);
    if (bpf_obj_get_info_by_fd(program_fd, &info, &info_size) < 0) {
        std::cerr << "error " << errno << ": loaded program but could not get ID" << std::endl;
        return ERROR_SUPPRESS_OUTPUT;
    }
    std::cout << "Loaded with ID " << info.id << std::endl;
    unloader.object = nullptr;

    _ebpf_netsh_objects.push_back(object);

    return ERROR_SUCCESS;
}

// Given a program ID, unpin the program from all paths to which
// it is currently pinned.
static unsigned long
_unpin_program_by_id(ebpf_id_t id)
{
    ebpf_result_t result;
    unsigned long status = NO_ERROR;

    // Read all pin paths.  Currently we get them in a non-deterministic
    // order, so we use a std::set to sort them in code point order.
    char pinpath[EBPF_MAX_PIN_PATH_LENGTH] = "";
    std::set<std::string> paths;
    while (ebpf_get_next_pinned_program_path(pinpath, pinpath) == EBPF_SUCCESS) {
        paths.insert(pinpath);
    }

    // Now walk through all paths in code point order.
    for (auto path : paths) {
        int fd = bpf_obj_get(path.c_str());
        if (fd < 0) {
            continue;
        }
        bpf_prog_info info = {};
        uint32_t info_size = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd, &info, &info_size) == 0) {
            if (id == info.id) {
                result = ebpf_object_unpin(path.c_str());
                if (result != EBPF_SUCCESS) {
                    printf("Error %d unpinning %d from %s\n", result, id, path.c_str());
                    status = ERROR_SUPPRESS_OUTPUT;
                } else {
                    printf("Unpinned %d from %s\n", id, path.c_str());
                }
            }
        }
        Platform::_close(fd);
    }
    return status;
}

static std::vector<struct bpf_object*>::const_iterator
_find_object_with_program(ebpf_id_t id)
{
    for (auto object = _ebpf_netsh_objects.begin(); object != _ebpf_netsh_objects.end(); object++) {
        bpf_program* program;
        bpf_object__for_each_program(program, *object)
        {
            int program_fd = bpf_program__fd(program);
            struct bpf_prog_info info = {};
            uint32_t info_size = sizeof(info);
            if (bpf_obj_get_info_by_fd(program_fd, &info, &info_size) < 0) {
                continue;
            }
            if (info.id == id) {
                return object;
            }
        }
    }
    return _ebpf_netsh_objects.end();
}

// The following function uses windows specific type to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
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
    const int ID_INDEX = 0;
    unsigned long tag_type[_countof(tags)] = {0};

    unsigned long status =
        PreprocessCommand(nullptr, argv, current_index, argc, tags, _countof(tags), 0, _countof(tags), tag_type);

    ebpf_id_t id = EBPF_ID_NONE;
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc) && (i < _countof(tag_type)); i++) {
        switch (tag_type[i]) {
        case ID_INDEX: {
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

    int program_fd = bpf_prog_get_fd_by_id(id);
    if (program_fd == ebpf_fd_invalid) {
        std::cout << "Program not found\n";
        return ERROR_SUPPRESS_OUTPUT;
    }
    Platform::_close(program_fd);

    // If the program is pinned, unpin the specified program.
    status = _unpin_program_by_id(id);
    if (status != NO_ERROR) {
        return status;
    }

    // Remove from our list of programs to release our own reference if we took one.
    // If there are no other references to the program, it will be unloaded.
    std::vector<struct bpf_object*>::const_iterator object = _find_object_with_program(id);
    if (object != _ebpf_netsh_objects.end()) {
        bpf_object__close(*object);
        _ebpf_netsh_objects.erase(object);
    }

    // TODO: see if the program is still loaded, in which case some other process holds
    // a reference. Get the PID of that process and display it.

    return NO_ERROR;
}

_Must_inspect_result_ ebpf_result_t
_ebpf_program_attach_by_id(
    ebpf_id_t program_id, ebpf_attach_type_t attach_type, _In_opt_z_ const wchar_t* interface_parameter)
{
    ebpf_result_t result = EBPF_SUCCESS;
    uint32_t if_index;
    void* attach_parameters = nullptr;
    size_t attach_parameters_size = 0;

    fd_t program_fd = bpf_prog_get_fd_by_id(program_id);
    if (program_fd < 0) {
        return EBPF_INVALID_ARGUMENT;
    }

    if (interface_parameter != nullptr) {
        struct bpf_prog_info info = {};
        uint32_t info_size = sizeof(info);
        if (bpf_obj_get_info_by_fd(program_fd, &info, &info_size) < 0) {
            result = EBPF_INVALID_ARGUMENT;
        } else {
            result = _process_interface_parameter(interface_parameter, info.type, &if_index);
            if (result == EBPF_SUCCESS) {
                attach_parameters = &if_index;
                attach_parameters_size = sizeof(if_index);
            }
        }
    }

    struct bpf_link* link;
    if (result == EBPF_SUCCESS) {
        ebpf_result_t local_result =
            ebpf_program_attach_by_fd(program_fd, &attach_type, attach_parameters, attach_parameters_size, &link);
        if (local_result == EBPF_SUCCESS) {
            ebpf_link_close(link);
        }
    }

    Platform::_close(program_fd);
    return result;
}

int // errno value
_ebpf_program_detach_by_id(ebpf_id_t program_id)
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

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
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
        {TOKEN_PINPATH, NS_REQ_ZERO, FALSE},
        {TOKEN_INTERFACE, NS_REQ_ZERO, FALSE}};
    const int ID_INDEX = 0;
    const int ATTACHED_INDEX = 1;
    const int PINPATH_INDEX = 2;
    const int INTERFACE_INDEX = 3;

    unsigned long tag_type[_countof(tags)] = {0};
    wchar_t* interface_parameter = nullptr;

    unsigned long status = PreprocessCommand(
        nullptr,
        argv,
        current_index,
        argc,
        tags,
        _countof(tags),
        0,
        3, // Two required tags plus at least one optional tag.
        tag_type);

    uint32_t id = 0;
    std::string pinpath;
    ebpf_attach_type_t attach_type = EBPF_ATTACH_TYPE_UNSPECIFIED;
    for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
        switch (tag_type[i]) {
        case ID_INDEX: {
            id = (uint32_t)_wtoi(argv[current_index + i]);
            break;
        }
        case ATTACHED_INDEX: {
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
        case INTERFACE_INDEX: {
            interface_parameter = argv[current_index + i];
            break;
        }
        case PINPATH_INDEX:
            pinpath = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        default:
            status = ERROR_INVALID_SYNTAX;
            break;
        }
    }
    if (status != NO_ERROR) {
        return status;
    }

    if (tags[ATTACHED_INDEX].bPresent) {
        if (memcmp(&attach_type, &EBPF_ATTACH_TYPE_UNSPECIFIED, sizeof(ebpf_attach_type_t)) != 0) {
            ebpf_result_t result = _ebpf_program_attach_by_id(id, attach_type, interface_parameter);
            if (result != NO_ERROR) {
                std::cerr << "error " << result << ": could not attach program" << std::endl;
                return ERROR_SUPPRESS_OUTPUT;
            }
        } else {
            int error = _ebpf_program_detach_by_id(id);
            if (error != NO_ERROR) {
                std::cerr << "error " << error << ": could not detach program" << std::endl;
                return ERROR_SUPPRESS_OUTPUT;
            }
        }
    }

    if (tags[PINPATH_INDEX].bPresent) {
        if (pinpath.empty()) {
            // Unpin a program from all names to which it is currently pinpath.
            return _unpin_program_by_id(id);
        } else {
            // Try to find the program with the specified ID.
            fd_t program_fd = bpf_prog_get_fd_by_id(id);
            if (program_fd == ebpf_fd_invalid) {
                std::cerr << "Program not found." << std::endl;
                return ERROR_SUPPRESS_OUTPUT;
            }

            status = bpf_obj_pin(program_fd, pinpath.c_str());
            if (status != EBPF_SUCCESS) {
                std::cerr << "error " << status << ": could not pin program" << std::endl;
                return ERROR_SUPPRESS_OUTPUT;
            }

            Platform::_close(program_fd);
        }
    }

    return ERROR_OKAY;
}

// The following function uses windows specific type as an input to match
// definition of "FN_HANDLE_CMD" in public file of NetSh.h
unsigned long
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
    const int TYPE_INDEX = 0;
    const int ATTACHED_INDEX = 1;
    const int PINNED_INDEX = 2;
    const int LEVEL_INDEX = 3;
    const int FILENAME_INDEX = 4;
    const int SECTION_INDEX = 5;
    const int ID_INDEX = 6;

    unsigned long tag_type[_countof(tags)] = {0};

    unsigned long status =
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
        case TYPE_INDEX: {
            std::string type_name = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            ebpf_attach_type_t expected_attach_type;
            ebpf_result_t result =
                ebpf_get_program_type_by_name(type_name.c_str(), &program_type, &expected_attach_type);
            if (result != EBPF_SUCCESS) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        }
        case ATTACHED_INDEX:
            status = MatchEnumTag(
                NULL,
                argv[current_index + i],
                _countof(_boolean_constraint_enum),
                _boolean_constraint_enum,
                (unsigned long*)&attached);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        case PINNED_INDEX:
            status = MatchEnumTag(
                NULL,
                argv[current_index + i],
                _countof(_boolean_constraint_enum),
                _boolean_constraint_enum,
                (unsigned long*)&pinned);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        case LEVEL_INDEX:
            status =
                MatchEnumTag(NULL, argv[current_index + i], _countof(g_LevelEnum), g_LevelEnum, (unsigned long*)&level);
            if (status != NO_ERROR) {
                status = ERROR_INVALID_PARAMETER;
            }
            break;
        case FILENAME_INDEX: {
            filename = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case SECTION_INDEX: {
            section = down_cast_from_wstring(std::wstring(argv[current_index + i]));
            break;
        }
        case ID_INDEX: {
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

    // If the user specified an ID and no level, default to verbose.
    if (tags[ID_INDEX].bPresent && !tags[LEVEL_INDEX].bPresent) {
        level = VL_VERBOSE;
    }

    if (level == VL_NORMAL) {
        std::cout << "\n";
        std::cout << "    ID  Pins  Links  Mode       Type           Name\n";
        std::cout << "======  ====  =====  =========  =============  ====================\n";
    }

    uint32_t program_id = 0;
    fd_t program_fd = ebpf_fd_invalid;
    for (;;) {
        const char* program_file_name;
        const char* program_section_name;
        const char* execution_type_name;
        ebpf_execution_type_t program_execution_type;
        uint32_t next_program_id;
        if (bpf_prog_get_next_id(program_id, &next_program_id) < 0) {
            break;
        }
        program_id = next_program_id;

        if (program_fd != ebpf_fd_invalid) {
            Platform::_close(program_fd);
        }
        program_fd = bpf_prog_get_fd_by_id(program_id);

        struct bpf_prog_info info = {};
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

        // Filter by attached if desired.
        if (attached == BC_NO && info.link_count > 0) {
            continue;
        }
        if (attached == BC_YES && info.link_count == 0) {
            continue;
        }

        // Filter by pinpath if desired.
        if (pinned == BC_NO && info.pinned_path_count > 0) {
            continue;
        }
        if (pinned == BC_YES && info.pinned_path_count == 0) {
            continue;
        }

        status =
            ebpf_program_query_info(program_fd, &program_execution_type, &program_file_name, &program_section_name);
        if (status != ERROR_SUCCESS) {
            break;
        }

        if (filename.empty() || strcmp(program_file_name, filename.c_str()) == 0) {
            if (section.empty() || strcmp(program_section_name, section.c_str()) == 0) {
                switch (program_execution_type) {
                case EBPF_EXECUTION_JIT:
                    execution_type_name = "JIT";
                    break;
                case EBPF_EXECUTION_INTERPRET:
                    execution_type_name = "INTERPRET";
                    break;
                default:
                    execution_type_name = "NATIVE";
                    break;
                }
                const char* program_type_name = ebpf_get_program_type_name(&info.type_uuid);

                if (level == VL_NORMAL) {
                    printf(
                        "%6u  %4u  %5u  %-9s  %-13s  %s\n",
                        info.id,
                        info.pinned_path_count,
                        info.link_count,
                        execution_type_name,
                        program_type_name,
                        info.name);
                } else {
                    std::cout << "\n";
                    std::cout << "ID             : " << info.id << "\n";
                    std::cout << "File name      : " << program_file_name << "\n";
                    std::cout << "Section        : " << program_section_name << "\n";
                    std::cout << "Name           : " << info.name << "\n";
                    std::cout << "Program type   : " << program_type_name << "\n";
                    std::cout << "Mode           : " << execution_type_name << "\n";
                    std::cout << "# map IDs      : " << info.nr_map_ids << "\n";

                    if (info.nr_map_ids > 0) {
                        std::vector<ebpf_id_t> map_ids(info.nr_map_ids);
                        info.map_ids = (uintptr_t)map_ids.data();
                        error = bpf_obj_get_info_by_fd(program_fd, &info, &info_size);
                        if (error < 0) {
                            break;
                        }
                        std::cout << "map IDs        : " << map_ids[0] << "\n";
                        for (uint32_t i = 1; i < info.nr_map_ids; i++) {
                            std::cout << "                 " << map_ids[i] << "\n";
                        }
                    }

                    std::cout << "# pinned paths : " << info.pinned_path_count << "\n";
                    std::cout << "# links        : " << info.link_count << "\n";
                }
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
