// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_api.h"
#include "ebpf_execution_context.h"
#include "ebpf_utilities.h"

#pragma warning(push)
#pragma warning(disable : 26439) // This kind of function should not throw. Declare it 'noexcept'.
#pragma warning(disable : 26451) // Arithmetic overflow: Using operator '+' on a 4 byte value and then casting the
                                 // result to a 8 byte value.
#undef min                       // don't interfere with C++ min/max definitions required inside platform.hpp.
#undef max
#include "platform.hpp"
#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))
#pragma warning(pop)

#include "windows_platform_common.hpp"

#include <errno.h>
#include <map>
#include <stdexcept>

// The map file descriptors that appear in eBPF bytecode start at 1,
// in the order the maps appear in the maps sections.
const int ORIGINAL_FD_OFFSET = 1;

inline fd_t
map_idx_to_original_fd(uint32_t idx)
{
    return idx + ORIGINAL_FD_OFFSET;
}

inline uint32_t
original_fd_to_map_idx(fd_t fd)
{
    return fd - ORIGINAL_FD_OFFSET;
}

typedef struct _map_cache
{
    ebpf_handle_t handle;
    uint32_t id;
    size_t section_offset;
    EbpfMapDescriptor verifier_map_descriptor;
    ebpf_pin_type_t pinning;
    uint32_t inner_id;

    _map_cache()
        : handle(0), id(EBPF_ID_NONE), section_offset(0), verifier_map_descriptor(), pinning(LIBBPF_PIN_NONE),
          inner_id(EBPF_ID_NONE)
    {
    }

    _map_cache(ebpf_handle_t handle, size_t section_offset, EbpfMapDescriptor descriptor, ebpf_pin_type_t pinning)
        : handle(handle), id(EBPF_ID_NONE), section_offset(section_offset), verifier_map_descriptor(descriptor),
          pinning(pinning), inner_id(EBPF_ID_NONE)
    {
    }

    _map_cache(
        ebpf_handle_t handle,
        uint32_t _id,
        int original_fd, // fd as it appears in raw bytecode
        uint32_t type,
        unsigned int key_size,
        unsigned int value_size,
        unsigned int max_entries,
        fd_t inner_map_original_fd,
        unsigned int _inner_id,
        size_t section_offset,
        ebpf_pin_type_t pinning)
        : handle(handle), section_offset(section_offset), pinning(pinning)
    {
        verifier_map_descriptor.original_fd = original_fd;
        verifier_map_descriptor.type = type;
        verifier_map_descriptor.key_size = key_size;
        verifier_map_descriptor.value_size = value_size;
        verifier_map_descriptor.max_entries = max_entries;
        id = _id;
        inner_id = _inner_id;
        verifier_map_descriptor.inner_map_fd = inner_map_original_fd;
    }
} map_cache_t;

const char*
allocate_string(const std::string& string, uint32_t* length = nullptr) noexcept;

std::vector<uint8_t>
convert_ebpf_program_to_bytes(const std::vector<ebpf_inst>& instructions);

int
get_file_size(const char* filename, size_t* byte_code_size) noexcept;

void
cache_map_handle(
    ebpf_handle_t handle,
    uint32_t original_fd,
    uint32_t id,
    uint32_t type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    uint32_t inner_map_original_fd,
    uint32_t inner_id,
    size_t section_offset,
    ebpf_pin_type_t pinning);

size_t
get_map_descriptor_size(void);

ebpf_handle_t
get_map_handle(int map_fd);

std::vector<ebpf_handle_t>
get_all_map_handles(void);

std::vector<map_cache_t>&
get_all_map_descriptors();

__forceinline int
ebpf_result_to_errno(ebpf_result_t result)
{
    int error;

    switch (result) {
    case EBPF_SUCCESS:
        error = 0;
        break;

    case EBPF_NO_MEMORY:
        error = ENOMEM;
        break;

    case EBPF_ALREADY_INITIALIZED:
    case EBPF_INVALID_ARGUMENT:
    case EBPF_EXTENSION_FAILED_TO_LOAD:
    case EBPF_INVALID_OBJECT:
        error = EINVAL;
        break;

    case EBPF_INVALID_FD:
        error = EBADF;
        break;

    case EBPF_OPERATION_NOT_SUPPORTED:
        error = ENOTSUP;
        break;

    case EBPF_INSUFFICIENT_BUFFER:
        error = ENOBUFS;
        break;

    case EBPF_FILE_NOT_FOUND:
    case EBPF_KEY_NOT_FOUND:
    case EBPF_NO_MORE_KEYS:
    case EBPF_OBJECT_NOT_FOUND:
        error = ENOENT;
        break;

    case EBPF_OBJECT_ALREADY_EXISTS:
        error = EEXIST;
        break;

    case EBPF_VERIFICATION_FAILED:
        error = EACCES;
        break;

    case EBPF_INVALID_POINTER:
        error = EFAULT;
        break;

    case EBPF_OUT_OF_SPACE:
        error = ENOSPC;
        break;

    case EBPF_ACCESS_DENIED:
        error = EPERM;
        break;

    default:
        error = EOTHER;
        break;
    }

    return error;
}

_Must_inspect_result_ ebpf_result_t
ebpf_object_get_info(
    ebpf_handle_t handle,
    _Inout_updates_bytes_to_(*info_size, *info_size) void* info,
    _Inout_ uint32_t* info_size,
    _Out_opt_ ebpf_object_type_t* type) noexcept;

_Must_inspect_result_ ebpf_result_t
query_map_definition(
    ebpf_handle_t handle,
    _Out_ uint32_t* id,
    _Out_ uint32_t* type,
    _Out_ uint32_t* key_size,
    _Out_ uint32_t* value_size,
    _Out_ uint32_t* max_entries,
    _Out_ ebpf_id_t* inner_map_id) noexcept;

void
set_global_program_and_attach_type(const ebpf_program_type_t* program_type, const ebpf_attach_type_t* attach_type);

const ebpf_program_type_t*
get_global_program_type();

const ebpf_attach_type_t*
get_global_attach_type();

void
set_verification_in_progress(bool value);

bool
get_verification_in_progress();

struct _verification_in_progress_helper
{
    _verification_in_progress_helper() { set_verification_in_progress(true); }
    ~_verification_in_progress_helper() { set_verification_in_progress(false); }
};

/**
 * @brief Save handle to program being verified in thread-local storage.
 *
 * @param[in] program Handle to program being verified.
 */
void
set_program_under_verification(ebpf_handle_t program);

/**
 * @brief Clear thread-local storage used for storing data needed for program verification.
 */
void
ebpf_clear_thread_local_storage() noexcept;

bool
ebpf_verify_program(
    std::ostream& os,
    _In_ const InstructionSeq& prog,
    _In_ const program_info& info,
    _In_ const ebpf_verifier_options_t& options,
    _Out_ ebpf_api_verifier_stats_t* stats);