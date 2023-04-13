// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// This file contains function implementations for serializing and de-serializing
// various eBPF structures to/from ebpf_operation_*_request/reply_t structures.
#include "ebpf_program_types.h"
#include "ebpf_serialize.h"

/**
 * @brief Serialized program type descriptor.
 */
typedef struct _ebpf_serialized_program_type_descriptor
{
    size_t size;
    ebpf_context_descriptor_t context_descriptor;
    GUID program_type;
    unsigned char is_privileged;
    size_t name_length;
    uint8_t name[1];
} ebpf_serialized_program_type_descriptor_t;

/**
 * @brief Serialized helper function prototype.
 */
typedef struct _ebpf_serialized_helper_function_prototype
{
    size_t size;
    uint32_t helper_id;
    ebpf_return_type_t return_type;
    ebpf_argument_type_t arguments[5];
    size_t name_length;
    uint8_t name[1];
} ebpf_serialized_helper_function_prototype_t;

/**
 * @brief Serialized helper function prototypes array.
 */
typedef struct _ebpf_serialized_helper_function_prototype_array
{
    size_t size;
    uint32_t helper_function_count;
    uint8_t prototypes[1];
} ebpf_serialized_helper_function_prototype_array_t;

void
ebpf_map_info_array_free(uint16_t map_count, _In_opt_count_(map_count) _Post_ptr_invalid_ ebpf_map_info_t* map_info)
{
    EBPF_LOG_ENTRY();
    uint16_t map_index;

    if (map_info != NULL) {
        for (map_index = 0; map_index < map_count; map_index++) {
            ebpf_free(map_info[map_index].pin_path);
            map_info[map_index].pin_path = NULL;
        }
        ebpf_free(map_info);
    }
    EBPF_RETURN_VOID();
}

_Must_inspect_result_ ebpf_result_t
ebpf_serialize_internal_map_info_array(
    uint16_t map_count,
    _In_count_(map_count) const ebpf_map_info_internal_t* map_info,
    _Out_writes_bytes_to_(output_buffer_length, *serialized_data_length) uint8_t* output_buffer,
    size_t output_buffer_length,
    _Out_ size_t* serialized_data_length,
    _Out_ size_t* required_length)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    uint16_t map_index;
    uint8_t* current = NULL;

    *serialized_data_length = 0;

    // Compute required length for serialized array of map info objects.
    *required_length = 0;
    for (map_index = 0; map_index < map_count; map_index++) {
        // Increment required_length by EBPF_OFFSET_OF(ebpf_serialized_map_info_t, pin_path).
        result = ebpf_safe_size_t_add(
            *required_length, EBPF_OFFSET_OF(ebpf_serialized_map_info_t, pin_path), required_length);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // Increment required_length by map_info[map_index].pin_path.length.
        result = ebpf_safe_size_t_add(*required_length, map_info[map_index].pin_path.length, required_length);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
    }

    // Output buffer too small.
    if (output_buffer_length < *required_length) {
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_WARNING,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Output buffer is too small",
            output_buffer_length,
            *required_length);
        result = EBPF_INSUFFICIENT_BUFFER;
        goto Exit;
    }

    *serialized_data_length = *required_length;
    current = output_buffer;

    for (map_index = 0; map_index < map_count; map_index++) {
        size_t serialized_map_info_length;
        const ebpf_map_info_internal_t* source = &map_info[map_index];
        ebpf_serialized_map_info_t* destination = (ebpf_serialized_map_info_t*)current;

        // Compute required length for serialized map info.
        result = ebpf_safe_size_t_add(
            EBPF_OFFSET_OF(ebpf_serialized_map_info_t, pin_path), source->pin_path.length, &serialized_map_info_length);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // Copy the map definition fields.
        destination->definition = source->definition;

        // Set the length of the pin path.
        destination->pin_path_length = (uint16_t)source->pin_path.length;

        // Copy the pin path buffer.
        memcpy(destination->pin_path, source->pin_path.value, source->pin_path.length);

        // Move the output buffer current pointer.
        current += serialized_map_info_length;
    }

Exit:
    EBPF_RETURN_RESULT(result);
}

#pragma warning(push)
#pragma warning(disable : 6101) // ebpf_map_info_array_free at exit label
_Must_inspect_result_ ebpf_result_t
ebpf_deserialize_map_info_array(
    size_t input_buffer_length,
    _In_reads_bytes_(input_buffer_length) const uint8_t* input_buffer,
    uint16_t map_count,
    _Outptr_result_buffer_maybenull_(map_count) ebpf_map_info_t** map_info)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    uint16_t map_index;
    size_t out_map_size;
    ebpf_map_info_t* out_map_info = NULL;
    uint8_t* current;
    size_t buffer_left;

    if (map_count == 0) {
        *map_info = NULL;
        goto Exit;
    }

    // Allocate the output maps.
    result = ebpf_safe_size_t_multiply(sizeof(ebpf_map_info_t), (size_t)map_count, &out_map_size);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    out_map_info = (ebpf_map_info_t*)ebpf_allocate(out_map_size);
    if (out_map_info == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    current = (uint8_t*)input_buffer;
    buffer_left = input_buffer_length;
    for (map_index = 0; map_index < map_count; map_index++) {
        ebpf_serialized_map_info_t* source;
        ebpf_map_info_t* destination;
        size_t destination_pin_path_length;

        // Check if sufficient input buffer remaining.
        if (buffer_left < sizeof(ebpf_serialized_map_info_t)) {
            EBPF_LOG_MESSAGE_UINT64_UINT64(
                EBPF_TRACELOG_LEVEL_WARNING,
                EBPF_TRACELOG_KEYWORD_BASE,
                "Insufficient input buffer remaining",
                buffer_left,
                sizeof(ebpf_serialized_map_info_t));
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        source = (ebpf_serialized_map_info_t*)current;
        destination = &out_map_info[map_index];

        // Copy the map definition part.
        destination->definition = source->definition;

        // Advance the input buffer current pointer.
        current += EBPF_OFFSET_OF(ebpf_serialized_map_info_t, pin_path);

        // Adjust remaining input buffer length.
        result =
            ebpf_safe_size_t_subtract(buffer_left, EBPF_OFFSET_OF(ebpf_serialized_map_info_t, pin_path), &buffer_left);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // Check if sufficient input buffer remaining.
        if (buffer_left < source->pin_path_length) {
            EBPF_LOG_MESSAGE_UINT64_UINT64(
                EBPF_TRACELOG_LEVEL_WARNING,
                EBPF_TRACELOG_KEYWORD_BASE,
                "Insufficient input buffer remaining",
                buffer_left,
                source->pin_path_length);
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        if (source->pin_path_length > 0) {
            // Allocate the buffer to hold the pin path in destination map info structure.
            destination_pin_path_length = ((size_t)source->pin_path_length) + 1;
            destination->pin_path = ebpf_allocate(destination_pin_path_length);
            if (destination->pin_path == NULL) {
                result = EBPF_NO_MEMORY;
                goto Exit;
            }

            // Copy the pin path.
            memcpy(destination->pin_path, source->pin_path, source->pin_path_length);

            // Advance the input buffer current pointer.
            current += source->pin_path_length;

            // Adjust remaining input buffer length.
            result = ebpf_safe_size_t_subtract(buffer_left, source->pin_path_length, &buffer_left);
            if (result != EBPF_SUCCESS) {
                goto Exit;
            }
        }
    }

    *map_info = out_map_info;
    out_map_info = NULL;

Exit:
    ebpf_map_info_array_free(map_count, out_map_info);

    EBPF_RETURN_RESULT(result);
}
#pragma warning(pop)

void
ebpf_program_info_free(_In_opt_ _Post_invalid_ ebpf_program_info_t* program_info)
{
    EBPF_LOG_ENTRY();
    if (program_info != NULL) {
        ebpf_free((void*)program_info->program_type_descriptor.context_descriptor);
        ebpf_free((void*)program_info->program_type_descriptor.name);
        if (program_info->program_type_specific_helper_prototype != NULL) {
            for (uint32_t i = 0; i < program_info->count_of_program_type_specific_helpers; i++) {
                const ebpf_helper_function_prototype_t* helper_prototype =
                    &program_info->program_type_specific_helper_prototype[i];
                void* name = (void*)helper_prototype->name;
                ebpf_free(name);
            }
        }
        if (program_info->global_helper_prototype != NULL) {
            for (uint32_t i = 0; i < program_info->count_of_global_helpers; i++) {
                const ebpf_helper_function_prototype_t* helper_prototype = &program_info->global_helper_prototype[i];
                void* name = (void*)helper_prototype->name;
                ebpf_free(name);
            }
        }

        ebpf_free((void*)program_info->program_type_specific_helper_prototype);
        ebpf_free((void*)program_info->global_helper_prototype);
        ebpf_free(program_info);
    }
    EBPF_RETURN_VOID();
}

_Must_inspect_result_ ebpf_result_t
ebpf_serialize_program_info(
    _In_ const ebpf_program_info_t* program_info,
    _Out_writes_bytes_to_(output_buffer_length, *serialized_data_length) uint8_t* output_buffer,
    size_t output_buffer_length,
    _Out_ size_t* serialized_data_length,
    _Out_ size_t* required_length)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    uint8_t* current = NULL;
    const ebpf_program_type_descriptor_t* program_type_descriptor;
    const ebpf_helper_function_prototype_t* helper_prototype_array;
    uint32_t helper_prototype_index;
    size_t serialized_program_type_descriptor_length;
    size_t program_type_descriptor_name_length;
    size_t serialized_helper_prototype_array_length;
    ebpf_serialized_program_type_descriptor_t* serialized_program_type_descriptor;

    *serialized_data_length = 0;

    // Perform sanity check on input program info.
    program_type_descriptor = &program_info->program_type_descriptor;

    if (program_type_descriptor->name == NULL) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_WARNING, EBPF_TRACELOG_KEYWORD_BASE, "program_type_descriptor->name is NULL");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    helper_prototype_array = program_info->program_type_specific_helper_prototype;
    if (helper_prototype_array != NULL) {
        if (program_info->count_of_program_type_specific_helpers == 0) {
            EBPF_LOG_MESSAGE(
                EBPF_TRACELOG_LEVEL_WARNING,
                EBPF_TRACELOG_KEYWORD_BASE,
                "program_info->count_of_program_type_specific_helpers 0");
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
        for (helper_prototype_index = 0; helper_prototype_index < program_info->count_of_program_type_specific_helpers;
             helper_prototype_index++) {
            if (helper_prototype_array[helper_prototype_index].name == NULL) {
                EBPF_LOG_MESSAGE_UINT64(
                    EBPF_TRACELOG_LEVEL_WARNING,
                    EBPF_TRACELOG_KEYWORD_BASE,
                    "helper_prototype_array[helper_prototype_index].name is null",
                    helper_prototype_index);
                result = EBPF_INVALID_ARGUMENT;
                goto Exit;
            }
        }
    }

    // Compute required length for serialized program info object.
    *required_length = 0;

    // Compute length for serialized program type descriptor.
    serialized_program_type_descriptor_length = 0;
    result = ebpf_safe_size_t_add(
        serialized_program_type_descriptor_length,
        EBPF_OFFSET_OF(ebpf_serialized_program_type_descriptor_t, name),
        &serialized_program_type_descriptor_length);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    program_type_descriptor_name_length =
        strnlen_s(program_type_descriptor->name, EBPF_MAX_PROGRAM_DESCRIPTOR_NAME_LENGTH);
    result = ebpf_safe_size_t_add(
        serialized_program_type_descriptor_length,
        program_type_descriptor_name_length,
        &serialized_program_type_descriptor_length);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // Increment required_length by length of serialized program type descriptor.
    result = ebpf_safe_size_t_add(*required_length, serialized_program_type_descriptor_length, required_length);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // Compute required length for serialized helper function prototypes array.
    serialized_helper_prototype_array_length = 0;
    if (helper_prototype_array != NULL) {
        result = ebpf_safe_size_t_add(
            serialized_helper_prototype_array_length,
            EBPF_OFFSET_OF(ebpf_serialized_helper_function_prototype_array_t, prototypes),
            &serialized_helper_prototype_array_length);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        for (helper_prototype_index = 0; helper_prototype_index < program_info->count_of_program_type_specific_helpers;
             helper_prototype_index++) {
            const ebpf_helper_function_prototype_t* helper_prototype = &helper_prototype_array[helper_prototype_index];

            result = ebpf_safe_size_t_add(
                serialized_helper_prototype_array_length,
                EBPF_OFFSET_OF(ebpf_serialized_helper_function_prototype_t, name),
                &serialized_helper_prototype_array_length);
            if (result != EBPF_SUCCESS) {
                goto Exit;
            }

            result = ebpf_safe_size_t_add(
                serialized_helper_prototype_array_length,
                strnlen_s(helper_prototype->name, EBPF_MAX_HELPER_FUNCTION_NAME_LENGTH),
                &serialized_helper_prototype_array_length);
            if (result != EBPF_SUCCESS) {
                goto Exit;
            }
        }

        // Increment required length by the length of serialized helper function prototype array.
        result = ebpf_safe_size_t_add(*required_length, serialized_helper_prototype_array_length, required_length);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }
    }

    if (output_buffer_length < *required_length) {
        // Output buffer too small.
        EBPF_LOG_MESSAGE_UINT64_UINT64(
            EBPF_TRACELOG_LEVEL_WARNING,
            EBPF_TRACELOG_KEYWORD_BASE,
            "Output buffer is too small",
            output_buffer_length,
            *required_length);
        result = EBPF_INSUFFICIENT_BUFFER;
        goto Exit;
    }

    *serialized_data_length = *required_length;
    current = output_buffer;

    memset(output_buffer, 0, output_buffer_length);

    // Serialize the program type descriptor.
    serialized_program_type_descriptor = (ebpf_serialized_program_type_descriptor_t*)current;
    serialized_program_type_descriptor->size = serialized_program_type_descriptor_length;
    if (program_type_descriptor->context_descriptor != NULL) {
        serialized_program_type_descriptor->context_descriptor = *program_type_descriptor->context_descriptor;
    }
    serialized_program_type_descriptor->program_type = program_type_descriptor->program_type;
    serialized_program_type_descriptor->is_privileged = program_type_descriptor->is_privileged;
    serialized_program_type_descriptor->name_length = program_type_descriptor_name_length;
    // Copy the program type descriptor name buffer.
    memcpy(
        serialized_program_type_descriptor->name, program_type_descriptor->name, program_type_descriptor_name_length);

    // Move the output buffer current pointer.
    current += serialized_program_type_descriptor_length;

    if (helper_prototype_array != NULL) {
        // Serialize the helper function prototypes array.
        ebpf_serialized_helper_function_prototype_array_t* serialized_helper_prototype_array =
            (ebpf_serialized_helper_function_prototype_array_t*)current;
        serialized_helper_prototype_array->size = serialized_helper_prototype_array_length;
        serialized_helper_prototype_array->helper_function_count = program_info->count_of_program_type_specific_helpers;

        // Move the output buffer current pointer to the beginning of serialized helper function prototypes.
        current += EBPF_OFFSET_OF(ebpf_serialized_helper_function_prototype_array_t, prototypes);

        for (helper_prototype_index = 0; helper_prototype_index < program_info->count_of_program_type_specific_helpers;
             helper_prototype_index++) {
            const ebpf_helper_function_prototype_t* helper_prototype = &helper_prototype_array[helper_prototype_index];
            size_t helper_function_name_length =
                strnlen_s(helper_prototype->name, EBPF_MAX_HELPER_FUNCTION_NAME_LENGTH);
            ebpf_serialized_helper_function_prototype_t* serialized_helper_prototype =
                (ebpf_serialized_helper_function_prototype_t*)current;

            // Serialize individual helper function prototypes.
            serialized_helper_prototype->size =
                EBPF_OFFSET_OF(ebpf_serialized_helper_function_prototype_t, name) + helper_function_name_length;
            serialized_helper_prototype->helper_id = helper_prototype->helper_id;
            serialized_helper_prototype->return_type = helper_prototype->return_type;
            for (uint16_t index = 0; index < EBPF_COUNT_OF(helper_prototype->arguments); index++) {
                serialized_helper_prototype->arguments[index] = helper_prototype->arguments[index];
            }
            serialized_helper_prototype->name_length = helper_function_name_length;
            // Copy the program type descriptor name buffer.
            memcpy(serialized_helper_prototype->name, helper_prototype->name, helper_function_name_length);

            // Move the output buffer current pointer.
            current += serialized_helper_prototype->size;
        }
    }

Exit:
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_deserialize_program_info(
    size_t input_buffer_length,
    _In_reads_bytes_(input_buffer_length) const uint8_t* input_buffer,
    _Outptr_ ebpf_program_info_t** program_info)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_program_info_t* local_program_info;
    const uint8_t* current;
    size_t buffer_left;
    ebpf_context_descriptor_t* local_context_descriptor;
    ebpf_program_type_descriptor_t* local_program_type_descriptor;
    const ebpf_serialized_program_type_descriptor_t* serialized_program_type_descriptor;
    char* local_program_type_descriptor_name;
    ebpf_serialized_helper_function_prototype_array_t* serialized_helper_prototype_array;
    uint32_t helper_function_count;
    size_t helper_prototype_array_size;
    ebpf_helper_function_prototype_t* local_helper_prototype_array;

    // Allocate output program info.
    local_program_info = (ebpf_program_info_t*)ebpf_allocate(sizeof(ebpf_program_info_t));
    if (local_program_info == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    local_program_type_descriptor = &local_program_info->program_type_descriptor;

    current = input_buffer;
    buffer_left = input_buffer_length;

    // Deserialize program type descriptor.

    // Check if sufficient input buffer remaining.
    if (buffer_left < sizeof(ebpf_serialized_program_type_descriptor_t)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    serialized_program_type_descriptor = (const ebpf_serialized_program_type_descriptor_t*)current;

    local_program_type_descriptor->program_type = serialized_program_type_descriptor->program_type;
    local_program_type_descriptor->is_privileged = serialized_program_type_descriptor->is_privileged;

    // Allocate and deserialize context_descriptor, if present.
    if (serialized_program_type_descriptor->context_descriptor.size != 0) {
        local_context_descriptor = (ebpf_context_descriptor_t*)ebpf_allocate(sizeof(ebpf_context_descriptor_t));
        if (local_context_descriptor == NULL) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        *local_context_descriptor = serialized_program_type_descriptor->context_descriptor;
        local_program_type_descriptor->context_descriptor = local_context_descriptor;
    }

    // Allocate and deserialize program type descriptor name.
    if (serialized_program_type_descriptor->name_length == 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Adjust remaining buffer length.
    result = ebpf_safe_size_t_subtract(
        buffer_left, EBPF_OFFSET_OF(ebpf_serialized_program_type_descriptor_t, name), &buffer_left);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // Check if sufficient buffer is remaining for program type descriptor name.
    if (buffer_left < sizeof(serialized_program_type_descriptor->name_length)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Allocate and deserialize program type descriptor name.
    local_program_type_descriptor_name = (char*)ebpf_allocate(serialized_program_type_descriptor->name_length + 1);
    if (local_program_type_descriptor_name == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    memcpy(
        local_program_type_descriptor_name,
        serialized_program_type_descriptor->name,
        serialized_program_type_descriptor->name_length);
    local_program_type_descriptor->name = local_program_type_descriptor_name;

    // Adjust remaining buffer length.
    result = ebpf_safe_size_t_subtract(buffer_left, serialized_program_type_descriptor->name_length, &buffer_left);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // Advance the input buffer current pointer to the end of program type descriptor section.
    current += serialized_program_type_descriptor->size;

    if (buffer_left == 0) {
        // No buffer left. This means there are no helper function prototypes in the input buffer.
        goto Exit;
    }

    // Check if sufficient buffer left for ebpf_serialized_helper_function_prototype_array_t.
    if (buffer_left < sizeof(ebpf_serialized_helper_function_prototype_array_t)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Deserialize ebpf_serialized_helper_function_prototype_array_t.
    serialized_helper_prototype_array = (ebpf_serialized_helper_function_prototype_array_t*)current;
    helper_function_count = serialized_helper_prototype_array->helper_function_count;

    if (helper_function_count == 0) {
        // Serialized buffer present for helper prototypes, but count is zero.
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    local_program_info->count_of_program_type_specific_helpers = helper_function_count;

    // Advance the input buffer current pointer to the beginning of array of helper function prototypes.
    current += EBPF_OFFSET_OF(ebpf_serialized_helper_function_prototype_array_t, prototypes);

    // Adjust remaining buffer length.
    result = ebpf_safe_size_t_subtract(
        buffer_left, EBPF_OFFSET_OF(ebpf_serialized_helper_function_prototype_array_t, prototypes), &buffer_left);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // Allocate array of helper function prototypes.
    result = ebpf_safe_size_t_multiply(
        helper_function_count, sizeof(ebpf_helper_function_prototype_t), &helper_prototype_array_size);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }
    local_helper_prototype_array = (ebpf_helper_function_prototype_t*)ebpf_allocate(helper_prototype_array_size);
    if (local_helper_prototype_array == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }
    local_program_info->program_type_specific_helper_prototype = local_helper_prototype_array;

    for (uint32_t helper_function_index = 0; helper_function_index < helper_function_count; helper_function_index++) {
        ebpf_serialized_helper_function_prototype_t* serialized_helper_prototype =
            (ebpf_serialized_helper_function_prototype_t*)current;
        ebpf_helper_function_prototype_t* helper_prototype = &local_helper_prototype_array[helper_function_index];
        char* local_helper_function_name;

        // Check if sufficient input buffer left for ebpf_serialized_helper_function_prototype_t.
        if (buffer_left < sizeof(ebpf_serialized_helper_function_prototype_t)) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        // Serialize helper prototype.
        helper_prototype->helper_id = serialized_helper_prototype->helper_id;
        helper_prototype->return_type = serialized_helper_prototype->return_type;
        for (int i = 0; i < EBPF_COUNT_OF(helper_prototype->arguments); i++) {
            helper_prototype->arguments[i] = serialized_helper_prototype->arguments[i];
        }

        // Adjust remaining buffer length.
        result = ebpf_safe_size_t_subtract(
            buffer_left, EBPF_OFFSET_OF(ebpf_serialized_helper_function_prototype_t, name), &buffer_left);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // Check if enough buffer left for helper function name.
        if (buffer_left < serialized_helper_prototype->name_length) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        // Allocate buffer and serialize helper function name.
        local_helper_function_name = (char*)ebpf_allocate(serialized_helper_prototype->name_length + 1);
        if (local_helper_function_name == NULL) {
            result = EBPF_NO_MEMORY;
            goto Exit;
        }
        memcpy(local_helper_function_name, serialized_helper_prototype->name, serialized_helper_prototype->name_length);
        helper_prototype->name = local_helper_function_name;

        // Adjust remaining buffer length.
        result = ebpf_safe_size_t_subtract(buffer_left, serialized_helper_prototype->name_length, &buffer_left);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // Advance the current pointer to the end of the helper function prototype.
        current += serialized_helper_prototype->size;
    }

Exit:
    if (result == EBPF_SUCCESS) {
        *program_info = local_program_info;
        local_program_info = NULL;
    } else {
        ebpf_program_info_free(local_program_info);
    }

    EBPF_RETURN_RESULT(result);
}
