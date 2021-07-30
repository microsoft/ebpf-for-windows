/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "ebpf_execution_type.h"
#include "ebpf_result.h"
#include "ebpf_core_structs.h"
#include "ebpf_result.h"
#include "ebpf_windows.h"

#ifdef __cplusplus
extern "C"
{
#endif

    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_UNSPECIFIED = {0};

    /** @brief Attach type for handling incoming packets as early as possible.
     *
     * Program type: \ref EBPF_PROGRAM_TYPE_XDP
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_XDP = {
        0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};

    /** @brief Attach type for handling socket bind() requests.
     *
     * Program type: \ref EBPF_PROGRAM_TYPE_BIND
     */
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_BIND = {
        0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};

    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_TEST = {
        0xf788ef4b, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};

    __declspec(selectany) ebpf_attach_type_t EBPF_PROGRAM_TYPE_UNSPECIFIED = {0};

    /** @brief Program type for handling incoming packets as early as possible.
     *
     * eBPF program prototype: \ref xdp_hook_t
     *
     * Attach type(s): \ref EBPF_ATTACH_TYPE_XDP
     *
     * Helpers available: see ebpf_helpers.h
     */
    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_XDP = {
        0xf1832a85, 0x85d5, 0x45b0, {0x98, 0xa0, 0x70, 0x69, 0xd6, 0x30, 0x13, 0xb0}};

    /** @brief Program type for handling socket bind() requests.
     *
     * eBPF program prototype: \ref bind_hook_t
     *
     * Attach type(s): \ref EBPF_ATTACH_TYPE_BIND
     *
     * Helpers available: see ebpf_helpers.h
     */
    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_BIND = {
        0x608c517c, 0x6c52, 0x4a26, {0xb6, 0x77, 0xbb, 0x1c, 0x34, 0x42, 0x5a, 0xdf}};

    __declspec(selectany) ebpf_program_type_t EBPF_PROGRAM_TYPE_TEST = {
        0xf788ef4a, 0x207d, 0x4dc3, {0x85, 0xcf, 0x0f, 0x2e, 0xa1, 0x07, 0x21, 0x3c}};

    typedef int32_t fd_t;
    const fd_t ebpf_fd_invalid = -1;
    typedef void* ebpf_handle_t;
    const ebpf_handle_t ebpf_handle_invalid = (ebpf_handle_t)-1;
    typedef struct _tlv_type_length_value tlv_type_length_value_t;

    struct _ebpf_object;
    struct _ebpf_program;
    struct _ebpf_map;

    /**
     *  @brief Initialize the eBPF user mode library.
     */
    uint32_t
    ebpf_api_initiate();

    /**
     *  @brief Terminate the eBPF user mode library.
     */
    void
    ebpf_api_terminate();

    /**
     * @brief Load an eBFP program into the kernel execution context.
     * @param[in] file An ELF file containing one or more eBPF programs.
     * @param[in] section_name Name of the section in the ELF file to load.
     * @param[in] execution_type How this program should be run in the execution
     * context.
     * @param[out] handle Handle to eBPF program.
     * @param[in,out] count_of_map_handles On input, contains the maximum number of map_handles to return.
     * On output, contains the actual number of map_handles returned.
     * @param[out] map_handles Array of map handles to be filled in.
     * @param[out] error_message Error message describing what failed.
     */
    ebpf_result_t
    ebpf_api_load_program(
        const char* file,
        const char* section_name,
        ebpf_execution_type_t execution_type,
        ebpf_handle_t* handle,
        uint32_t* count_of_map_handles,
        ebpf_handle_t* map_handles,
        const char** error_message);

    /**
     * @brief Create an eBPF map with input parameters.
     * @param[in] type Map type.
     * @param[in] key_size Key size.
     * @param[in] value_size Value size.
     * @param[in] max_entries Maximum number of entries in the map.
     * @param[in] map_flags Map flags.
     * @param[out] handle Pointer to map handle.
     *
     * @retval EBPF_SUCCESS Map created successfully.
     * @retval EBPF_ERROR_NOT_SUPPORTED Unsupported map type.
     * @retval EBPF_INVALID_ARGUMENT One or more parameters are incorrect.
     */
    ebpf_result_t
    ebpf_api_create_map(
        ebpf_map_type_t type,
        uint32_t key_size,
        uint32_t value_size,
        uint32_t max_entries,
        uint32_t map_flags,
        _Out_ ebpf_handle_t* handle);

    /**
     * @brief Find an element in an eBPF map.
     * @param[in] handle Handle to eBPF map.
     * @param[in] key_size Size of the key buffer.
     * @param[in] key Pointer to buffer containing key.
     * @param[in] value_size Size of the value buffer.
     * @param[out] value Pointer to buffer that contains value on success.
     */
    uint32_t
    ebpf_api_map_find_element(
        ebpf_handle_t handle, uint32_t key_size, const uint8_t* key, uint32_t value_size, uint8_t* value);

    /**
     * @brief Update an element in an eBPF map.
     * @param[in] handle Handle to eBPF map.
     * @param[in] key_size Size of the key buffer.
     * @param[in] key Pointer to buffer containing key.
     * @param[in] value_size Size of the value buffer.
     * @param[out] value Pointer to buffer containing value.
     */
    uint32_t
    ebpf_api_map_update_element(
        ebpf_handle_t handle, uint32_t key_size, const uint8_t* key, uint32_t value_size, const uint8_t* value);

    /**
     * @brief Delete an element in an eBPF map.
     * @param[in] handle Handle to eBPF map.
     * @param[in] key_size Size of the key buffer.
     * @param[in] key Pointer to buffer containing key.
     */
    uint32_t
    ebpf_api_map_delete_element(ebpf_handle_t handle, uint32_t key_size, const uint8_t* key);

    /**
     * @brief Return the next key in an eBPF map.
     * @param[in] handle Handle to eBPF map.
     * @param[in] key_size Size of the key buffer.
     * @param[in] previous_key Pointer to buffer containing
     previous key or NULL to restart enumeration.
     * @param[out] next_key Pointer to buffer that contains next
     * key on success.
     * @retval ERROR_NO_MORE_ITEMS previous_key was the last key.
     */
    uint32_t
    ebpf_api_get_next_map_key(ebpf_handle_t handle, uint32_t key_size, const uint8_t* previous_key, uint8_t* next_key);

    /**
     * @brief Get the next eBPF map.
     * @param[in] previous_handle Handle to previous eBPF map or
     *  ebpf_handle_invalid to start enumeration.
     * @param[out] next_handle The next eBPF map or ebpf_handle_invalid if this
     *  is the last map.
     */
    uint32_t
    ebpf_api_get_next_map(ebpf_handle_t previous_handle, ebpf_handle_t* next_handle);

    /**
     * @brief Get the next eBPF program.
     * @param[in] previous_handle Handle to previous eBPF program or
     *  ebpf_handle_invalid to start enumeration.
     * @param[out] next_handle The next eBPF program or ebpf_handle_invalid if this
     *  is the last map.
     */
    uint32_t
    ebpf_api_get_next_program(ebpf_handle_t previous_handle, ebpf_handle_t* next_handle);

    /**
     * @brief Query properties of an eBPF map.
     * @param[in] handle Handle to an eBPF map.
     * @param[out] size Size of the eBPF map definition.
     * @param[out] type Type of the eBPF map.
     * @param[out] key_size Size of keys in the eBPF map.
     * @param[out] value_size Size of values in the eBPF map.
     * @param[out] max_entries Maximum number of entries in the map.
     */
    ebpf_result_t
    ebpf_api_map_query_definition(
        ebpf_handle_t handle,
        uint32_t* size,
        uint32_t* type,
        uint32_t* key_size,
        uint32_t* value_size,
        uint32_t* max_entries);

    /**
     * @brief Query info about an eBPF program.
     * @param[in] handle Handle to an eBPF program.
     * @param[out] execution_type On success, contains the execution type.
     * @param[out] file_name On success, contains the file name.
     * @param[out] section_name On success, contains the section name.
     */
    uint32_t
    ebpf_api_program_query_info(
        ebpf_handle_t handle, ebpf_execution_type_t* execution_type, const char** file_name, const char** section_name);

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
     * @brief Associate a name with an object handle.
     * @param[in] handle Handle to object.
     * @param[in] name Name to associate with handle.
     * @param[in] name_length Length in bytes of the name.
     */
    uint32_t
    ebpf_api_pin_object(ebpf_handle_t handle, const uint8_t* name, uint32_t name_length);

    /**
     * @brief Dissociate a name with an object handle.
     * @param[in] name Name to dissociate.
     * @param[in] name_length Length in bytes of the name.
     */
    uint32_t
    ebpf_api_unpin_object(const uint8_t* name, uint32_t name_length);

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
     * @retval ERROR_INVALID_PARAMETER One or more parameters are incorrect.
     */
    uint32_t
    ebpf_api_unlink_program(ebpf_handle_t link_handle);

    /**
     * @brief Close an eBPF handle.
     *
     * @param[in] handle Handle to close.
     * @retval ERROR_SUCCESS Handle was closed.
     * @retval ERROR_INVALID_HANDLE Handle is not valid.
     */
    uint32_t
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
        is expected to call ebpf_object_close() at the end.
     * @param[out] program_fd Returns a file descriptor for the first program.
     *  The caller should not call _close() on the fd, but should instead use
     *  ebpf_object_close() to close this (and other) file descriptors.
     * @param[out] log_buffer Returns a pointer to a null-terminated log buffer.
     *  The caller is responsible for freeing the returned log_buffer pointer
     *  by calling ebpf_api_free_string().
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
        _Outptr_ struct _ebpf_object** object,
        _Out_ fd_t* program_fd,
        _Outptr_result_maybenull_z_ const char** log_buffer);

    /**
     * @brief Get next program in ebpf_object object.
     *
     * @param[in] previous Pointer to previous eBPF program, or NULL to get the first one.
     * @param[in] object Pointer to eBPF object.
     * @return Pointer to the next program, or NULL if none.
     */
    _Ret_maybenull_ struct _ebpf_program*
    ebpf_program_next(_In_opt_ const struct _ebpf_program* previous, _In_ const struct _ebpf_object* object);

    /**
     * @brief Get previous program in ebpf_object object.
     *
     * @param[in] next Pointer to next eBPF program, or NULL to get the last one.
     * @param[in] object Pointer to eBPF object.
     * @return Pointer to the previous program, or NULL if none.
     */
    _Ret_maybenull_ struct _ebpf_program*
    ebpf_program_previous(_In_opt_ const struct _ebpf_program* next, _In_ const struct _ebpf_object* object);

    /**
     * @brief Get next map in ebpf_object object.
     *
     * @param[in] previous Pointer to previous eBPF map, or NULL to get the first one.
     * @param[in] object Pointer to eBPF object.
     * @return Pointer to the next map, or NULL if none.
     */
    _Ret_maybenull_ struct _ebpf_map*
    ebpf_map_next(_In_opt_ const struct _ebpf_map* previous, _In_ const struct _ebpf_object* object);

    /**
     * @brief Get previous map in ebpf_object object.
     *
     * @param[in] next Pointer to next eBPF map, or NULL to get the last one.
     * @param[in] object Pointer to eBPF object.
     * @return Pointer to the previous map, or NULL if none.
     */
    _Ret_maybenull_ struct _ebpf_map*
    ebpf_map_previous(_In_opt_ const struct _ebpf_map* next, _In_ const struct _ebpf_object* object);

    /**
     * @brief Fetch fd for a program object.
     *
     * @param[in] program Pointer to eBPF program.
     * @return fd for the program on success, ebpf_fd_invalid on failure.
     */
    fd_t
    ebpf_program_get_fd(_In_ const struct _ebpf_program* program);

    /**
     * @brief Fetch fd for a map object.
     *
     * @param[in] map Pointer to eBPF map.
     * @return fd for the map on success, ebpf_fd_invalid on failure.
     */
    fd_t
    ebpf_map_get_fd(_In_ const struct _ebpf_map* map);

    /**
     * @brief Clean up ebpf_object. Also delete all the sub objects
     * (maps, programs) and close the related file descriptors.
     *
     * @param[in] object Pointer to ebpf_object.
     */
    void
    ebpf_object_close(_In_ _Post_invalid_ struct _ebpf_object* object);

#ifdef __cplusplus
}
#endif
