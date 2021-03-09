// Copyright (C) Microsoft.
// SPDX-License-Identifier: MIT
#include <string>
#define WIN32_LEAN_AND_MEAN
#include "ebpf_windows.h"
#include "programs.h"
#include "tokens.h"
#include <netsh.h>
#include <windows.h>

#include "api.h"
#include <iostream>

static ebpf_handle_t _program_handle = INVALID_HANDLE_VALUE;
static ebpf_handle_t _map_handles[10];

typedef enum {
  PINNED_ANY = 0,
  PINNED_YES = 1,
  PINNED_NO = 2,
} PINNED_CONSTRAINT;

static TOKEN_VALUE _pinned_enum[] = {
    {L"any", PINNED_ANY},
    {L"yes", PINNED_YES},
    {L"no", PINNED_NO},
};

static TOKEN_VALUE _ebpf_program_type_enum[] = {
    {L"unknown", EBPF_PROGRAM_TYPE_UNSPECIFIED},
    {L"xdp", EBPF_PROGRAM_TYPE_XDP},
    {L"bind", EBPF_PROGRAM_TYPE_BIND},

};

static TOKEN_VALUE _ebpf_execution_type_enum[] = {
    {L"jit", EBPF_EXECUTION_JIT},
    {L"interpret", EBPF_EXECUTION_INTERPRET},

};

std::string down_cast_from_wstring(const std::wstring &wide_string);

unsigned long handle_ebpf_add_program(LPCWSTR machine, LPWSTR *argv,
                                      DWORD current_index, DWORD argc,
                                      DWORD flags, LPCVOID data, BOOL *done) {
  UNREFERENCED_PARAMETER(machine);
  UNREFERENCED_PARAMETER(flags);
  UNREFERENCED_PARAMETER(data);
  UNREFERENCED_PARAMETER(done);

  TAG_TYPE tags[] = {{TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
                     {TOKEN_SECTION, NS_REQ_ZERO, FALSE},
                     {TOKEN_TYPE, NS_REQ_ZERO, FALSE},
                     {TOKEN_PINNED, NS_REQ_ZERO, FALSE},
                     {TOKEN_EXECUTION, NS_REQ_ZERO, FALSE}};
  ULONG tag_type[_countof(tags)] = {0};

  ULONG status = PreprocessCommand(nullptr, argv, current_index, argc, tags,
                                   _countof(tags), 0, _countof(tags), tag_type);

  std::string filename;
  std::string section = ""; // Use the first code section by default.
  ebpf_program_type_t type = EBPF_PROGRAM_TYPE_XDP;
  PINNED_CONSTRAINT pinned = PINNED_ANY;
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
      status = MatchEnumTag(NULL, argv[current_index + i],
                            _countof(_ebpf_program_type_enum),
                            _ebpf_program_type_enum, (PULONG)&type);
      if (status != NO_ERROR) {
        status = ERROR_INVALID_PARAMETER;
      }
      break;
    case 3: // PINNED
      status =
          MatchEnumTag(NULL, argv[current_index + i], _countof(_pinned_enum),
                       _pinned_enum, (PULONG)&pinned);
      if (status != NO_ERROR) {
        status = ERROR_INVALID_PARAMETER;
      }
      break;
    case 4: // EXECUTION
      status = MatchEnumTag(NULL, argv[current_index + i],
                            _countof(_ebpf_execution_type_enum),
                            _ebpf_execution_type_enum, (PULONG)&execution);
      break;
    default:
      status = ERROR_INVALID_SYNTAX;
      break;
    }
  }
  if (status != NO_ERROR) {
    return status;
  }

  if (_program_handle != INVALID_HANDLE_VALUE) {
    ebpf_api_detach_program(_program_handle, type);
    ebpf_api_unload_program(_program_handle);
    _program_handle = INVALID_HANDLE_VALUE;
  }

  const char *error_message = nullptr;
  uint32_t count_of_map_handles = sizeof(_map_handles);
  status = ebpf_api_load_program(filename.c_str(), section.c_str(), execution,
                                 &_program_handle, &count_of_map_handles,
                                 _map_handles, &error_message);
  if (status != ERROR_SUCCESS) {
    if (error_message != nullptr) {
      std::cerr << error_message << std::endl;
    } else {
      std::cerr << "error " << status << ": could not load program"
                << std::endl;
    }
    ebpf_api_free_error_message(error_message);
    return ERROR_SUPPRESS_OUTPUT;
  }

  status = ebpf_api_attach_program(_program_handle, type);
  if (status != ERROR_SUCCESS) {
    std::cerr << "error " << status << ": could not attach program"
              << std::endl;
    return ERROR_SUPPRESS_OUTPUT;
  }
  return ERROR_SUCCESS;
}

DWORD handle_ebpf_delete_program(LPCWSTR machine, LPWSTR *argv,
                                 DWORD current_index, DWORD argc, DWORD flags,
                                 LPCVOID data, BOOL *done) {
  UNREFERENCED_PARAMETER(machine);
  UNREFERENCED_PARAMETER(flags);
  UNREFERENCED_PARAMETER(data);
  UNREFERENCED_PARAMETER(done);

  TAG_TYPE tags[] = {
      {TOKEN_FILENAME, NS_REQ_PRESENT, FALSE},
      {TOKEN_SECTION, NS_REQ_ZERO, FALSE},
  };
  ULONG tag_type[_countof(tags)] = {0};

  ULONG status = PreprocessCommand(nullptr, argv, current_index, argc, tags,
                                   _countof(tags), 0, _countof(tags), tag_type);

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

  if (_program_handle != INVALID_HANDLE_VALUE) {
    ebpf_api_detach_program(_program_handle, EBPF_PROGRAM_TYPE_XDP);
    ebpf_api_unload_program(_program_handle);
    _program_handle = INVALID_HANDLE_VALUE;
  }

  // TODO: delete program
  return ERROR_SUCCESS;
}

DWORD handle_ebpf_set_program(LPCWSTR machine, LPWSTR *argv,
                              DWORD current_index, DWORD argc, DWORD flags,
                              LPCVOID data, BOOL *done) {
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
      nullptr, argv, current_index, argc, tags, _countof(tags), 0,
      3, // Two required tags plus at least one optional tag.
      tag_type);

  std::string filename;
  std::string section = ""; // Use the first code section by default.
  PINNED_CONSTRAINT pinned = PINNED_ANY;
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
      status =
          MatchEnumTag(NULL, argv[current_index + i], _countof(_pinned_enum),
                       _pinned_enum, (PULONG)&pinned);
      if ((status != NO_ERROR) || (pinned == PINNED_ANY)) {
        status = ERROR_INVALID_PARAMETER;
      }
      break;
    default:
      status = ERROR_INVALID_SYNTAX;
      break;
    }
  }
  if (status != NO_ERROR) {
    return status;
  }

  // TODO: update program
  return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD handle_ebpf_show_programs(LPCWSTR machine, LPWSTR *argv,
                                DWORD current_index, DWORD argc, DWORD flags,
                                LPCVOID data, BOOL *done) {
  UNREFERENCED_PARAMETER(machine);
  UNREFERENCED_PARAMETER(flags);
  UNREFERENCED_PARAMETER(data);
  UNREFERENCED_PARAMETER(done);

  TAG_TYPE tags[] = {
      {TOKEN_TYPE, NS_REQ_ZERO, FALSE},    {TOKEN_PINNED, NS_REQ_ZERO, FALSE},
      {TOKEN_LEVEL, NS_REQ_ZERO, FALSE},   {TOKEN_FILENAME, NS_REQ_ZERO, FALSE},
      {TOKEN_SECTION, NS_REQ_ZERO, FALSE},
  };
  ULONG tag_type[_countof(tags)] = {0};

  ULONG status = PreprocessCommand(nullptr, argv, current_index, argc, tags,
                                   _countof(tags), 0, _countof(tags), tag_type);

  ebpf_program_type_t type = EBPF_PROGRAM_TYPE_XDP;
  PINNED_CONSTRAINT pinned = PINNED_ANY;
  VERBOSITY_LEVEL level = VL_NORMAL;
  std::string filename;
  std::string section = ".text";
  for (int i = 0; (status == NO_ERROR) && ((i + current_index) < argc); i++) {
    switch (tag_type[i]) {
    case 0: // TYPE
      status = MatchEnumTag(NULL, argv[current_index + i],
                            _countof(_ebpf_program_type_enum),
                            _ebpf_program_type_enum, (PULONG)&type);
      if (status != NO_ERROR) {
        status = ERROR_INVALID_PARAMETER;
      }
      break;
    case 1: // PINNED
      status =
          MatchEnumTag(NULL, argv[current_index + i], _countof(_pinned_enum),
                       _pinned_enum, (PULONG)&pinned);
      if (status != NO_ERROR) {
        status = ERROR_INVALID_PARAMETER;
      }
      break;
    case 2: // LEVEL
      status = MatchEnumTag(NULL, argv[current_index + i],
                            _countof(g_LevelEnum), g_LevelEnum, (PULONG)&level);
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

  // TODO: enumerate programs using specified constraints
  return ERROR_CALL_NOT_IMPLEMENTED;
}
