/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#pragma once
#include "ebpf_windows.h"

#ifdef __cplusplus
extern "C"
{
#endif

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
     * @param[in] execution_type How this program should be run in the exeuction
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
     * @brief Close a handle to an eBPF program.
     * @param[in] handle Handle to eBPF program.
     */
    void
    ebpf_api_unload_program(ebpf_handle_t handle);

    /**
     * @brief Attach an eBPF program to a hook point.
     * @param[in] handle Handle to eBPF program.
     * @param[in] hook_point Which hook point to attach to.
     */
    uint32_t
    ebpf_api_attach_program(ebpf_handle_t handle, ebpf_program_type_t hook_point);

    /**
     * @brief Detach an eBPF program from a hook point.
     * @param[in] handle Handle to eBPF program.
     * @param[in] hook_point Which hook point to detach from.
     */
    uint32_t
    ebpf_api_detach_program(ebpf_handle_t handle, ebpf_program_type_t hook_point);

    /**
     * @brief Lookup an element in an eBPF map.
     * @param[in] handle Handle to eBPF map.
     * @param[in] key_size Size of the key buffer.
     * @param[in] key Pointer to buffer containing key.
     * @param[in] value_size Size of the value buffer.
     * @param[out] value Pointer to buffer that contains value on success.
     */
    uint32_t
    ebpf_api_map_lookup_element(
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
    ebpf_api_map_next_key(ebpf_handle_t handle, uint32_t key_size, const uint8_t* previous_key, uint8_t* next_key);

    /**
     * @brief Enumerate through eBPF maps.
     * @param[in] previous_handle Handle to previous eBPF map or
     *  ebpf_handle_invalid to start enumeration.
     * @param[out] next_handle The next eBPF map or ebpf_handle_invalid if this
     *  is the last map.
     */
    uint32_t
    ebpf_api_map_enumerate(ebpf_handle_t previous_handle, ebpf_handle_t* next_handle);

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
     * @brief Close a handle to an eBPF map.
     * @param[in] handle Handle to eBPF map.
     */
    void
    ebpf_api_delete_map(ebpf_handle_t handle);

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
     * @param[out] dissassembly On success points text version of the program.
     * @param[out] error_message On failure points to a text description of
     *  the error.
     */
    uint32_t
    ebpf_api_elf_disassemble_section(
        const char* file, const char* section, const char** dissassembly, const char** error_message);

    /**
     * @brief Convert an eBPF program to human readable byte code.
     * @param[in] file Name of ELF file containing eBPF program.
     * @param[in] section The name of the section to query.
     * @param[out] report Points to a text section describing why the program
     *  failed verification.
     * @param[out] error_message On failure points to a text description of
     *  the error.
     */
    uint32_t
    ebpf_api_elf_verify_section(const char* file, const char* section, const char** report, const char** error_message);

    /**
     * @brief Free a TLV returned from ebpf_api_elf_enumerate_sections
     * @param[in] data Memory to free.
     */
    void
    ebpf_api_elf_free(const tlv_type_length_value_t* data);

    /**
     * @brief Free memory for a string returned from eBPF API.
     * @param[in] error_message Memory to free.
     */
    void
    ebpf_api_free_error_message(const char* error_message);

    /**
     * @brief Associate a name with a map handle.
     * @param[in] handle Handle to map.
     * @param[in] name Name to associate with handle.
     */
    uint32_t
    ebpf_api_pin_map(ebpf_handle_t handle, const uint8_t* name, uint32_t name_length);

    /**
     * @brief Desasociate a name with a map handle.
     * @param[in] name Name to deassociate.
     */
    uint32_t
    ebpf_api_unpin_map(const uint8_t* name, uint32_t name_length);

    /**
     * @brief Find a map given it's associated name.
     * @param[in] name Name to find.
     */
    uint32_t
    ebpf_api_lookup_map(const uint8_t* name, uint32_t name_length, ebpf_handle_t* handle);

#ifdef __cplusplus
}
#endif
