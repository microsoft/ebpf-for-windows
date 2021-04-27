/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once
#include "ebpf_protocol.h"
#include "ebpf_windows.h"

#ifdef __cplusplus
extern "C"
{
#endif

    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_XDP = {
        0x85e0d8ef, 0x579e, 0x4931, {0xb0, 0x72, 0x8e, 0xe2, 0x26, 0xbb, 0x2e, 0x9d}};
    __declspec(selectany) ebpf_attach_type_t EBPF_ATTACH_TYPE_BIND = {
        0xb9707e04, 0x8127, 0x4c72, {0x83, 0x3e, 0x05, 0xb1, 0xfb, 0x43, 0x94, 0x96}};

    typedef void* ebpf_handle_t;
    const ebpf_handle_t ebpf_handle_invalid = (ebpf_handle_t)-1;
    typedef struct _tlv_type_length_value tlv_type_length_value_t;

    typedef enum _ebpf_execution_type
    {
        EBPF_EXECUTION_JIT,
        EBPF_EXECUTION_INTERPRET
    } ebpf_execution_type_t;

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
     * @param[out] error_message Error message describing what failed.
     */
    uint32_t
    ebpf_api_load_program(
        const char* file,
        const char* section_name,
        ebpf_execution_type_t execution_type,
        ebpf_handle_t* handle,
        uint32_t* count_of_map_handles,
        ebpf_handle_t* map_handles,
        const char** error_message);

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
    uint32_t
    ebpf_api_map_query_definition(
        ebpf_handle_t handle,
        uint32_t* size,
        uint32_t* type,
        uint32_t* key_size,
        uint32_t* value_size,
        uint32_t* max_entries);

    /**
     * @brief Query information about an eBPF program.
     * @param[in] handle Handle to an eBPF program.
     */
    uint32_t
    ebpf_api_program_query_information(
        ebpf_handle_t handle, ebpf_execution_type_t* program_type, const char** file_name, const char** section_name);

    /**
     * @brief Get list of programs and stats in an ELF eBPF file.
     * @param[in] file Name of ELF file containing eBPF program.
     * @param[in] section Optionally, the name of the section to query.
     * @param[in] verbose Obtain additional information about the programs.
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

    /**
     * @brief Convert an eBPF program to human readable byte code.
     * @param[in] file Name of ELF file containing eBPF program.
     * @param[in] section The name of the section to query.
     * @param[in] verbose Obtain additional information about the programs.
     * @param[out] report Points to a text section describing why the program
     *  failed verification.
     * @param[out] error_message On failure points to a text description of
     *  the error.
     */
    uint32_t
    ebpf_api_elf_verify_section(
        const char* file, const char* section, bool verbose, const char** report, const char** error_message);

    /**
     * @brief Free a TLV returned from ebpf_api_elf_enumerate_sections
     * @param[in] data Memory to free.
     */
    void
    ebpf_api_elf_free(const tlv_type_length_value_t* data);

    /**
     * @brief Free memory for a string returned from eBPF API.
     * @param[in] string Memory to free.
     */
    void
    ebpf_api_free_string(const char* string);

    /**
     * @brief Associate a name with a map handle.
     * @param[in] handle Handle to map.
     * @param[in] name Name to associate with handle.
     */
    uint32_t
    ebpf_api_pin_map(ebpf_handle_t handle, const uint8_t* name, uint32_t name_length);

    /**
     * @brief Dissociate a name with a map handle.
     * @param[in] name Name to dissociate.
     */
    uint32_t
    ebpf_api_unpin_map(const uint8_t* name, uint32_t name_length);

    /**
     * @brief Find a map given its associated name.
     * @param[in] name Name to find.
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
     * @brief Close an ebpf handle.
     *
     * @param handle Handle to close.
     * @return ERROR_SUCCESS Handle was closed.
     * @retval ERROR_INVALID_HANDLE Handle is not valid.
     */
    uint32_t
    ebpf_api_close_handle(ebpf_handle_t handle);

#ifdef __cplusplus
}
#endif
