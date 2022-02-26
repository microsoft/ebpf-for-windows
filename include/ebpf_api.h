// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "ebpf_core_structs.h"
#include "ebpf_execution_type.h"
#include "ebpf_program_attach_type_guids.h"
#include "ebpf_result.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef int32_t fd_t;
    extern __declspec(selectany) const fd_t ebpf_fd_invalid = -1;
    typedef intptr_t ebpf_handle_t;
    typedef struct _tlv_type_length_value tlv_type_length_value_t;

    struct bpf_object;
    struct bpf_program;
    struct bpf_map;
    struct bpf_link;

    /**
     * @brief Create an eBPF map with input parameters.
     *
     * @param[in] map_type Map type.
     * @param[in] key_size Key size.
     * @param[in] value_size Value size.
     * @param[in] max_entries Maximum number of entries in the map.
     * @param[in] map_flags This is reserved and should be 0.
     * @param[out] map_fd File descriptor for the created map. The caller needs to
     *  call _close() on the returned fd when done.
     *
     * @retval EBPF_SUCCESS Map created successfully.
     * @retval EBPF_ERROR_NOT_SUPPORTED Unsupported map type.
     * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
     */
    ebpf_result_t
    ebpf_create_map(
        ebpf_map_type_t map_type,
        uint32_t key_size,
        uint32_t value_size,
        uint32_t max_entries,
        uint32_t map_flags,
        _Out_ fd_t* map_fd);

    /**
     * @brief Create an eBPF map with input parameters.
     *
     * @param[in] type Map type.
     * @param[in] name Optionally, the map name.
     * @param[in] key_size Key size.
     * @param[in] value_size Value size.
     * @param[in] max_entries Maximum number of entries in the map.
     * @param[in] map_flags This is reserved and should be 0.
     * @param[out] map_fd File descriptor for the created map. The caller needs to
     *  call _close() on the returned fd when done.
     *
     * @retval EBPF_SUCCESS Map created successfully.
     * @retval EBPF_ERROR_NOT_SUPPORTED Unsupported map type.
     * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
     */
    ebpf_result_t
    ebpf_create_map_name(
        ebpf_map_type_t type,
        _In_opt_z_ const char* name,
        uint32_t key_size,
        uint32_t value_size,
        uint32_t max_entries,
        uint32_t map_flags,
        _Out_ fd_t* map_fd);

    /**
     * @brief Get file descriptor to the next eBPF map.
     * @param[in] previous_fd FD to previous eBPF map or ebpf_fd_invalid to
     *  start enumeration.
     * @param[out] next_fd FD to the next eBPF map or ebpf_fd_invalid if this
     *  is the last map.
     * @retval EBPF_SUCCESS The operation was successful.
     */
    ebpf_result_t
    ebpf_get_next_map(fd_t previous_fd, _Out_ fd_t* next_fd);

    /**
     * @brief Get file descriptor to the next eBPF program.
     * @param[in] previous_fd File descriptor of the previous eBPF program or ebpf_fd_invalid to
     *  start enumeration.
     * @param[out] next_fd File descriptor of the next eBPF program or ebpf_fd_invalid if
     *  this is the last program.
     * @retval EBPF_SUCCESS The operation was successful.
     */
    ebpf_result_t
    ebpf_get_next_program(fd_t previous_fd, _Out_ fd_t* next_fd);

    /**
     * @brief Query info about an eBPF program.
     * @param[in] fd File descriptor of an eBPF program.
     * @param[out] execution_type On success, contains the execution type.
     * @param[out] file_name On success, contains the file name.
     * @param[out] section_name On success, contains the section name.
     * @retval EBPF_SUCCESS The operation was successful.
     */
    ebpf_result_t
    ebpf_program_query_info(
        fd_t fd,
        _Out_ ebpf_execution_type_t* execution_type,
        _Outptr_result_z_ const char** file_name,
        _Outptr_result_z_ const char** section_name);

    /**
     * @brief Get list of programs and stats in an ELF eBPF file.
     * @param[in] file Name of ELF file containing eBPF program.
     * @param[in] section Optionally, the name of the section to query.
     * @param[in] verbose Obtain additional info about the programs.
     * @param[out] data On success points to a list of eBPF programs.
     * @param[out] error_message On failure points to a text description of
     *  the error.
     *
     * The list of eBPF programs from this function is TLV formatted as follows:\n
     *
     *   sections ::= SEQUENCE {\n
     *      section    SEQUENCE of section\n
     *    }\n
     * \n
     *   section ::= SEQUENCE {\n
     *      name       STRING\n
     *      platform_specific_data INTEGER\n
     *      count_of_maps INTEGER\n
     *      byte_code   BLOB\n
     *      statistic SEQUENCE of statistic\n
     *   }\n
     * \n
     *   statistic ::= SEQUENCE {\n
     *      name      STRING\n
     *      value     INTEGER\n
     *   }\n
     */
    uint32_t
    ebpf_api_elf_enumerate_sections(
        const char* file,
        const char* section,
        bool verbose,
        const tlv_type_length_value_t** data,
        const char** error_message);

    /**
     * @brief Convert an eBPF program to human readable byte code.
     * @param[in] file Name of ELF file containing eBPF program.
     * @param[in] section The name of the section to query.
     * @param[out] disassembly On success points text version of the program.
     * @param[out] error_message On failure points to a text description of
     *  the error.
     */
    uint32_t
    ebpf_api_elf_disassemble_section(
        const char* file, const char* section, const char** disassembly, const char** error_message);

    typedef struct
    {
        int total_unreachable;
        int total_warnings;
        int max_instruction_count;
    } ebpf_api_verifier_stats_t;

    /**
     * @brief Convert an eBPF program to human readable byte code.
     * @param[in] file Name of ELF file containing eBPF program.
     * @param[in] section The name of the section to query.
     * @param[in] verbose Obtain additional info about the programs.
     * @param[out] report Points to a text section describing why the program
     *  failed verification.
     * @param[out] error_message On failure points to a text description of
     *  the error.
     * @param[out] stats If non-NULL, returns verification statistics.
     */
    uint32_t
    ebpf_api_elf_verify_section(
        const char* file,
        const char* section,
        bool verbose,
        const char** report,
        const char** error_message,
        ebpf_api_verifier_stats_t* stats);

    /**
     * @brief Free a TLV returned from \ref ebpf_api_elf_enumerate_sections
     * @param[in] data Memory to free.
     */
    void
    ebpf_api_elf_free(const tlv_type_length_value_t* data);

    /**
     * @brief Free memory for a string returned from an eBPF API.
     * @param[in] string Memory to free.
     */
    void
    ebpf_free_string(_In_opt_ _Post_invalid_ const char* string);

    /**
     * @brief Dissociate a name with an object handle.
     * @param[in] name Name to dissociate.
     * @param[in] name_length Length in bytes of the name.
     */
    uint32_t
    ebpf_api_unpin_object(const uint8_t* name, uint32_t name_length);

    /**
     * @brief Unpin the object from the specified path.
     * @param[in] path Path from which to unpin.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     */
    ebpf_result_t
    ebpf_object_unpin(_In_z_ const char* path);

    /**
     * @brief Find a map given its associated name.
     * @param[in] name Name to find.
     * @param[in] name_length Length in bytes of name to find.
     * @param[out] handle Pointer to memory that contains the map handle on success.
     */
    uint32_t
    ebpf_api_get_pinned_map(const uint8_t* name, uint32_t name_length, ebpf_handle_t* handle);

    /**
     * @brief Bind a program to an attach point and return a handle representing
     *  the link.
     *
     * @param[in] program_handle Handle to program to attach.
     * @param[in] attach_type Attach point to attach program to.
     * @param[out] link_handle Pointer to memory that contains the link handle
     * on success.
     * @retval ERROR_SUCCESS The operations succeeded.
     * @retval ERROR_INVALID_PARAMETER One or more parameters are incorrect.
     */
    uint32_t
    ebpf_api_link_program(ebpf_handle_t program_handle, ebpf_attach_type_t attach_type, ebpf_handle_t* link_handle);

    /**
     * @brief Detach the eBPF program from the link.
     *
     * @param[in] link_handle Handle to the link.
     *
     * @retval ERROR_SUCCESS The operations succeeded.
     * @retval ERROR_INVALID_PARAMETER The link handle is invalid.
     */
    uint32_t
    ebpf_api_unlink_program(ebpf_handle_t link_handle);

    /**
     * @brief Close an eBPF handle.
     *
     * @param[in] handle Handle to close.
     * @retval EBPF_SUCCESS Handle was closed.
     * @retval EBPF_INVALID_OBJECT Handle is not valid.
     */
    ebpf_result_t
    ebpf_api_close_handle(ebpf_handle_t handle);

    /**
     * @brief Returns an array of \ref ebpf_map_info_t for all pinned maps.
     *
     * @param[out] map_count Number of pinned maps.
     * @param[out] map_info Array of ebpf_map_info_t for pinned maps.
     *
     * @retval EBPF_SUCCESS The API suceeded.
     * @retval EBPF_NO_MEMORY Out of memory.
     * @retval EBPF_INVALID_ARGUMENT One or more parameters are wrong.
     */
    ebpf_result_t
    ebpf_api_get_pinned_map_info(
        _Out_ uint16_t* map_count, _Outptr_result_buffer_maybenull_(*map_count) ebpf_map_info_t** map_info);

    /**
     * @brief Helper Function to free array of \ref ebpf_map_info_t allocated by
     * \ref ebpf_api_get_pinned_map_info function.
     *
     * @param[in] map_count Length of array to be freed.
     * @param[in] map_info Map to be freed.
     */
    void
    ebpf_api_map_info_free(
        uint16_t map_count, _In_opt_count_(map_count) _Post_ptr_invalid_ const ebpf_map_info_t* map_info);

    /**
     * @brief Load eBPF programs from an ELF file based on default load
     * attributes. This API does the following:
     * 1. Read the ELF file.
     * 2. Create maps.
     * 3. Load all programs.
     * 4. Return fd to the first program.
     *
     * If the caller supplies a program type and/or attach type, that
     * supplied value takes precedence over the derived program/attach type.
     *
     * @param[in] file_name ELF file name with full path.
     * @param[in] program_type Optionally, the program type to use when loading
     *  the eBPF program. If program type is not supplied, it is derived from
     *  the section prefix in the ELF file.
     * @param[in] attach_type Optionally, the attach type to use for the loaded
     *  eBPF program. If attach type is not supplied, it is derived from the
     *  section prefix in the ELF file.
     * @param[in] execution_type The execution type to use for this program. If
     *  EBPF_EXECUTION_ANY is specified, execution type will be decided by a
     *  system-wide policy.
     * @param[out] object Returns pointer to ebpf_object object. The caller
     *  is expected to call bpf_object__close() at the end.
     * @param[out] program_fd Returns a file descriptor for the first program.
     *  The caller should not call _close() on the fd, but should instead use
     *  bpf_object__close() to close this (and other) file descriptors.
     * @param[out] log_buffer Returns a pointer to a null-terminated log buffer.
     *  The caller is responsible for freeing the returned log_buffer pointer
     *  by calling ebpf_free_string().
     *
     * @retval EBPF_SUCCESS The programs are loaded and maps are created successfully.
     * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
     * @retval EBPF_NO_MEMORY Out of memory.
     * @retval EBPF_ELF_PARSING_FAILED Failure in parsing ELF file.
     * @retval EBPF_FAILED Some other error occured.
     */
    ebpf_result_t
    ebpf_program_load(
        _In_z_ const char* file_name,
        _In_opt_ const ebpf_program_type_t* program_type,
        _In_opt_ const ebpf_attach_type_t* attach_type,
        _In_ ebpf_execution_type_t execution_type,
        _Outptr_ struct bpf_object** object,
        _Out_ fd_t* program_fd,
        _Outptr_result_maybenull_z_ const char** log_buffer);

    /**
     * @brief Load an eBPF programs from raw instructions.
     *
     * @param[in] program_type The eBPF program type.
     * @param[in] execution_type The execution type to use for this program. If
     *  EBPF_EXECUTION_ANY is specified, execution type will be decided by a
     *  system-wide policy.
     * @param[in] byte_code The eBPF program byte code.
     * @param[in] byte_code_size Size in bytes (not instruction count) of the
     *  eBPF program byte code.
     * @param[out] log_buf The buffer in which to write log messages.
     * @param[in] log_buf_sz Size in bytes of the caller's log buffer.
     * @param[out] program_fd Returns a file descriptor for the program.
     *  The caller should call _close() on the fd to close this when done.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
     * @retval EBPF_NO_MEMORY Out of memory.
     * @retval EBPF_VERIFICATION_FAILED The program failed verification.
     * @retval EBPF_FAILED Some other error occured.
     */
    ebpf_result_t
    ebpf_program_load_bytes(
        _In_ const ebpf_program_type_t* program_type,
        ebpf_execution_type_t execution_type,
        _In_reads_(byte_code_size) const uint8_t* byte_code,
        uint32_t byte_code_size,
        _Out_writes_opt_(log_buf_sz) char* log_buf,
        size_t log_buf_sz,
        _Out_ fd_t* program_fd);

    /**
     * @brief Attach an eBPF program.
     *
     * @param[in] program Pointer to the eBPF program.
     * @param[in] attach_type Optionally, the attach type for attaching the program.
     *  If attach type is not specified, then the earlier provided attach type
     *  or attach type derived from section prefix will be used to attach the
     *  program.
     * @param[in] attach_params_size Size of the attach parameters.
     * @param[in] attach_parameters Optionally, attach parameters. This is an
     *  opaque flat buffer containing the attach parameters which is interpreted
     *  by the extension provider.
     * @param[out] link Pointer to ebpf_link structure.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     */
    ebpf_result_t
    ebpf_program_attach(
        _In_ const struct bpf_program* program,
        _In_opt_ const ebpf_attach_type_t* attach_type,
        _In_reads_bytes_opt_(attach_params_size) void* attach_parameters,
        _In_ size_t attach_params_size,
        _Outptr_ struct bpf_link** link);

    /**
     * @brief Attach an eBPF program by program file descriptor.
     *
     * @param[in] program_fd An eBPF program file descriptor.
     * @param[in] attach_type Optionally, the attach type for attaching the program.
     *  If attach type is not specified, then the earlier provided attach type
     *  or attach type derived from section prefix will be used to attach the
     *  program.
     * @param[in] attach_parameters_size Size of the attach parameters.
     * @param[in] attach_parameters Optionally, attach parameters. This is an
     *  opaque flat buffer containing the attach parameters which is interpreted
     *  by the extension provider.
     * @param[out] link Pointer to ebpf_link structure.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     */
    ebpf_result_t
    ebpf_program_attach_by_fd(
        fd_t program_fd,
        _In_opt_ const ebpf_attach_type_t* attach_type,
        _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
        _In_ size_t attach_parameters_size,
        _Outptr_ struct bpf_link** link);

    /**
     * @brief Detach an eBPF program from an attach point represented by
     *  the bpf_link structure.
     *
     * @param[in] link Pointer to bpf_link structure.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_OBJECT Invalid object was passed.
     */
    ebpf_result_t
    ebpf_link_detach(_In_ struct bpf_link* link);

    /**
     * Clean up and free bpf_link structure. Also close the
     * underlying link fd.
     *
     * @param[in] link Pointer to the bpf_link structure.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_ARGUMENT Invalid argument was provided.
     *
     * @sa bpf_link__destroy
     * @sa bpf_link_detach
     */
    ebpf_result_t
    ebpf_link_close(_In_ struct bpf_link* link);

    /**
     * @brief Close a file descriptor. Also close the underlying handle.
     * @param [in] fd File descriptor to be closed.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_INVALID_FD Invalid fd was provided.
     */
    ebpf_result_t
    ebpf_close_fd(fd_t fd);

    /**
     * @brief Get a program type and expected attach type by name.
     *
     * @param[in] name Name, as if it were a section name in an ELF file.
     * @param[out] program_type Program type.
     * @param[out] expected_attach_type Expected attach type.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_KEY_NOT_FOUND No program type was found.
     */
    ebpf_result_t
    ebpf_get_program_type_by_name(
        _In_z_ const char* name,
        _Out_ ebpf_program_type_t* program_type,
        _Out_ ebpf_attach_type_t* expected_attach_type);

    /**
     * @brief Get the name of a given program type.
     *
     * @param[in] program_type Program type.
     *
     * @returns Name of the program type, or NULL if not found.
     */
    _Ret_maybenull_z_ const char*
    ebpf_get_program_type_name(_In_ const ebpf_program_type_t* program_type);

    /**
     * @brief Get the name of a given attach type.
     *
     * @param[in] attach_type Attach type.
     *
     * @returns Name of the attach type, or NULL if not found.
     */
    _Ret_maybenull_z_ const char*
    ebpf_get_attach_type_name(_In_ const ebpf_attach_type_t* attach_type);

    /**
     * @brief Gets the next pinned program after a given path.
     *
     * @param[in] start_path Path to look for an entry greater than.
     * @param[out] next_path Returns the next path, if one exists.
     *
     * @retval EBPF_SUCCESS The operation was successful.
     * @retval EBPF_NO_MORE_KEYS No more entries found.
     */
    ebpf_result_t
    ebpf_get_next_pinned_program_path(
        _In_z_ const char* start_path, _Out_writes_z_(EBPF_MAX_PIN_PATH_LENGTH) char* next_path);

#ifdef __cplusplus
}
#endif
