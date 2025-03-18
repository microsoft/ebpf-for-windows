// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "ebpf_core.h"
#include "ebpf_maps.h"
#include "helpers.h"
#include "libfuzzer.h"

#include <algorithm>
#include <iterator>
#include <map>
#include <set>
#include <vector>

// For testing purposes, use up to 64-byte buffers for things like csum diff.
#define MAX_BUFFER_SIZE 64

/**
 * @brief A wrapper class used to fuzz helper functions with a specific context type from a specific helper function
 * provider.
 *
 * @tparam context_type The context type to use when calling helper functions.
 */
template <typename context_type> class fuzz_helper_function
{
  public:
    fuzz_helper_function(GUID provider_id) : provider_guid(provider_id)
    {
        // Assert that we have the same number of map definitions as the number of map type names excluding the
        // BPF_MAP_TYPE_UNSPEC.
        if (_map_definitions.size() != _countof(_ebpf_map_type_names) - 1) {
            // Find the missing map type.
            std::set<bpf_map_type> map_types_in_use;
            std::set<bpf_map_type> map_types_defined;
            for (auto& [_, m] : _map_definitions) {
                map_types_in_use.insert(m.type);
            }

            // Add the BPF_MAP_TYPE_UNSPEC to the set of map types in use as it is not defined in _map_definitions.
            map_types_in_use.insert(BPF_MAP_TYPE_UNSPEC);

            for (size_t i = 0; i < _countof(_ebpf_map_type_names); i++) {
                map_types_defined.insert((bpf_map_type)i);
            }

            // Find the missing map type.
            std::set<bpf_map_type> missing_map_types;
            std::set_difference(
                map_types_defined.begin(),
                map_types_defined.end(),
                map_types_in_use.begin(),
                map_types_in_use.end(),
                std::inserter(missing_map_types, missing_map_types.begin()));

            // Create a string of missing map type names.
            std::string missing_map_type_names;
            for (auto& map_type : missing_map_types) {
                missing_map_type_names += _ebpf_map_type_names[map_type];
                missing_map_type_names += " ";
            }

            // Throw an exception with the missing map type names.
            throw std::runtime_error("Missing map type definitions for: " + missing_map_type_names);
        }
        ebpf_result_t result = ebpf_core_initiate();
        if (result != EBPF_SUCCESS) {
            throw std::runtime_error("ebpf_core_initiate failed");
        }

        // Register as an NmrClient for the global program information NPI.
        NTSTATUS status =
            NmrRegisterClient(&_program_information_client_characteristics, this, &program_information_nmr_handle);
        if (status != STATUS_SUCCESS) {
            throw std::runtime_error("NmrRegisterClient failed");
        }
    }

    ~fuzz_helper_function()
    {
        for (auto& [_, map] : maps) {
            EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)map);
        }

        NTSTATUS status = NmrDeregisterClient(program_information_nmr_handle);
        if (status == STATUS_PENDING) {
            NmrWaitForClientDeregisterComplete(program_information_nmr_handle);
        }
        ebpf_core_terminate();
    }

    /**
     * @brief Fuzz the helper function with the supplied data.
     *
     * @param[in] data_left The data to use when fuzzing the helper function.
     * @param[in] data_left_size The size of the data to use when fuzzing the helper function.
     * @return 0 Add this to the corpus.
     * @return -1 Discard this input.
     */
    int
    fuzz(_In_reads_(data_left_size) const uint8_t* data_left, size_t data_left_size)
    {
        // Get helper index.
        uint8_t helper_index;
        if (!consume_data(&data_left, &data_left_size, &helper_index, sizeof(helper_index))) {
            return -1;
        }

        const ebpf_helper_function_prototype_t* prototype = get_helper_prototype(helper_index);
        uintptr_t helper_function_address = get_helper_function_address(helper_index);

        if (helper_function_address == 0 || prototype == nullptr) {
            // No such helper id.
            return -1;
        }

        // Declare some memory usable when calling a helper.
        context_type context;
        char writable_buffer[MAX_BUFFER_SIZE] = {0};
        int readable_buffer_index = 0;
        char readable_buffer[5][MAX_BUFFER_SIZE];
        char map_key[MAX_BUFFER_SIZE];
        char map_value[MAX_BUFFER_SIZE];
        ebpf_map_type_t map_type = BPF_MAP_TYPE_UNSPEC;

        // Fill args based on data supplied by the fuzzer.
        uint64_t argument[5] = {0};
        int arg_count = 0;
        while (arg_count < 5) {
            ebpf_argument_type_t type = prototype->arguments[arg_count];
            // The verifier marks the first unused argument as EBPF_ARGUMENT_TYPE_DONTCARE.
            if (type == EBPF_ARGUMENT_TYPE_DONTCARE) {
                break;
            }
            switch (type) {
            case EBPF_ARGUMENT_TYPE_ANYTHING: {
                // Fill the argument with supplied data.
                if (!consume_data(
                        &data_left, &data_left_size, (uint8_t*)&argument[arg_count], sizeof(argument[arg_count]))) {
                    return -1;
                }
                break;
            }
            case EBPF_ARGUMENT_TYPE_CONST_SIZE: {
                assert(arg_count > 0);
                assert(argument[arg_count - 1] != 0);
                if (arg_count == 0 || argument[arg_count - 1] == 0) {
                    // Should never happen but we need to keep analysis build happy.
                    return -1;
                }

                // Put the supplied size into the argument.
                uint8_t arg_size;
                if (!consume_data(&data_left, &data_left_size, (uint8_t*)&arg_size, sizeof(arg_size)) ||
                    (arg_size == 0) || (arg_size > MAX_BUFFER_SIZE)) {
                    return -1;
                }
                argument[arg_count] = arg_size;

                // Put the supplied data into the previous argument.
                if (!consume_data(&data_left, &data_left_size, (uint8_t*)argument[arg_count - 1], arg_size)) {
                    return -1;
                }
                break;
            }
            case EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: {
                assert(arg_count > 0);
                assert(argument[arg_count - 1] != 0);
                if (arg_count == 0 || argument[arg_count - 1] == 0) {
                    // Should never happen but we need to keep analysis build happy.
                    return -1;
                }

                // Put the supplied size into the argument.
                uint8_t arg_size;
                if (!consume_data(&data_left, &data_left_size, (uint8_t*)&arg_size, sizeof(arg_size)) ||
                    (arg_size > MAX_BUFFER_SIZE)) {
                    return -1;
                }
                argument[arg_count] = arg_size;
                if (arg_size == 0) {
                    // Set the previous argument to NULL.
                    if (prototype->arguments[arg_count - 1] == EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL) {
                        argument[arg_count - 1] = 0;
                    }
                } else {
                    // Put the supplied data into the previous argument.
                    if (!consume_data(&data_left, &data_left_size, (uint8_t*)argument[arg_count - 1], arg_size)) {
                        return -1;
                    }
                }
                break;
            }
            case EBPF_ARGUMENT_TYPE_PTR_TO_CTX:
                // Put the context into the argument (all program contexts must support header, so subtract it out).
                argument[arg_count] = (uint64_t)&context - EBPF_CONTEXT_HEADER_SIZE;
                break;
            case EBPF_ARGUMENT_TYPE_PTR_TO_MAP: {
                // Put a map pointer into the argument.
                uint8_t index;
                if (!consume_data(&data_left, &data_left_size, &index, sizeof(index))) {
                    return -1;
                }
                map_type = (ebpf_map_type_t)index;
                argument[arg_count] = (uint64_t)get_map(map_type);
                if (argument[arg_count] == 0) {
                    return -1;
                }
                break;
            }
            case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY: {
                // Put the supplied data into the argument.
                const ebpf_map_definition_in_memory_t* definition = get_map_definition(map_type);
                if ((definition == nullptr) ||
                    !consume_data(&data_left, &data_left_size, (uint8_t*)&map_key, definition->key_size)) {
                    return -1;
                }
                argument[arg_count] = (uint64_t)map_key;
                break;
            }
            case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS:
                // Put the PROG_ARRAY map pointer into the argument.
                argument[arg_count] = (uint64_t)get_map(BPF_MAP_TYPE_PROG_ARRAY);
                if (argument[arg_count] == 0) {
                    return -1;
                }
                break;
            case EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE: {
                // Put the supplied data into the argument.
                const ebpf_map_definition_in_memory_t* definition = get_map_definition(map_type);
                if ((definition == nullptr) ||
                    !consume_data(&data_left, &data_left_size, (uint8_t*)&map_value, definition->value_size)) {
                    return -1;
                }
                argument[arg_count] = (uint64_t)map_value;
                break;
            }
            case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM:
                // Put a pointer to the next readable buffer into the argument.
                argument[arg_count] = (uint64_t)readable_buffer[readable_buffer_index++];
                break;
            case EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL:
                // Put a pointer to the next readable buffer into the argument.
                argument[arg_count] = (uint64_t)readable_buffer[readable_buffer_index++];
                break;
            case EBPF_ARGUMENT_TYPE_PTR_TO_WRITABLE_MEM:
                // Put a pointer to the writable buffer into the argument.
                argument[arg_count] = (uint64_t)writable_buffer;
                break;
            default:
                throw std::runtime_error("Unsupported argument type: " + std::to_string(type));
                break;
            }
            arg_count++;
        }
        if (data_left_size > 0) {
            // Fuzzer supplied too much data.
            return -1;
        }

        // Call into the helper.
        switch (arg_count) {
        case 0:
            ((function0_t)helper_function_address)();
            break;
        case 1:
            ((function1_t)helper_function_address)(argument[0]);
            break;
        case 2:
            ((function2_t)helper_function_address)(argument[0], argument[1]);
            break;
        case 3:
            ((function3_t)helper_function_address)(argument[0], argument[1], argument[2]);
            break;
        case 4:
            ((function4_t)helper_function_address)(argument[0], argument[1], argument[2], argument[3]);
            break;
        case 5:
            ((function5_t)helper_function_address)(argument[0], argument[1], argument[2], argument[3], argument[4]);
            break;
        }
        return 0;
    }

  private:
    inline static const std::map<std::string, ebpf_map_definition_in_memory_t> _map_definitions = {
        {
            "BPF_MAP_TYPE_HASH",
            {
                BPF_MAP_TYPE_HASH,
                4,
                4,
                10,
            },
        },
        {
            "BPF_MAP_TYPE_ARRAY",
            {
                BPF_MAP_TYPE_ARRAY,
                4,
                4,
                10,
            },
        },
        {
            "BPF_MAP_TYPE_PROG_ARRAY",
            {
                BPF_MAP_TYPE_PROG_ARRAY,
                4,
                4,
                10,
            },
        },
        {
            "BPF_MAP_TYPE_PERCPU_HASH",
            {
                BPF_MAP_TYPE_PERCPU_HASH,
                4,
                4,
                10,
            },
        },
        {
            "BPF_MAP_TYPE_PERCPU_ARRAY",
            {
                BPF_MAP_TYPE_PERCPU_ARRAY,
                4,
                4,
                10,
            },
        },
        {
            "BPF_MAP_TYPE_HASH_OF_MAPS",
            {
                BPF_MAP_TYPE_HASH_OF_MAPS,
                4,
                4,
                10,
            },
        },
        {
            "BPF_MAP_TYPE_ARRAY_OF_MAPS",
            {
                BPF_MAP_TYPE_ARRAY_OF_MAPS,
                4,
                4,
                10,
            },
        },
        {
            "BPF_MAP_TYPE_LRU_HASH",
            {
                BPF_MAP_TYPE_LRU_HASH,
                4,
                4,
                10,
            },
        },
        {
            "BPF_MAP_TYPE_LPM_TRIE",
            {
                BPF_MAP_TYPE_LPM_TRIE,
                4,
                4,
                10,
            },
        },
        {
            "BPF_MAP_TYPE_QUEUE",
            {
                BPF_MAP_TYPE_QUEUE,
                0,
                4,
                10,
            },
        },
        {
            "BPF_MAP_TYPE_LRU_PERCPU_HASH",
            {
                BPF_MAP_TYPE_LRU_PERCPU_HASH,
                4,
                4,
                10,
            },
        },
        {
            "BPF_MAP_TYPE_STACK",
            {
                BPF_MAP_TYPE_STACK,
                0,
                4,
                10,
            },
        },
        {
            "BPF_MAP_TYPE_PERCPU_ARRAY",
            {
                BPF_MAP_TYPE_PERCPU_ARRAY,
                0,
                4,
                10,
            },
        },
        {
            "BPF_MAP_TYPE_RINGBUF",
            {
                BPF_MAP_TYPE_RINGBUF,
                0,
                4,
                64 * 1024,
            },
        },
    };

    uintptr_t
    get_helper_function_address(uint32_t helper_id)
    {
        if (helper_functions_addresses.contains(helper_id)) {
            return helper_functions_addresses[helper_id];
        }
        return 0;
    }

    const ebpf_helper_function_prototype_t*
    get_helper_prototype(uint32_t helper_id)
    {
        if (helper_prototypes.contains(helper_id)) {
            return helper_prototypes[helper_id];
        }
        return nullptr;
    }

    _Ret_maybenull_ ebpf_map_t*
    get_map(ebpf_map_type_t type)
    {
        return maps.contains(type) ? maps[type] : nullptr;
    }

    // Generic helper prototypes.
    typedef uint64_t (*function0_t)();
    typedef uint64_t (*function1_t)(uint64_t r1);
    typedef uint64_t (*function2_t)(uint64_t r1, uint64_t r2);
    typedef uint64_t (*function3_t)(uint64_t r1, uint64_t r2, uint64_t r3);
    typedef uint64_t (*function4_t)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4);
    typedef uint64_t (*function5_t)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);

    // Consume the next output_size bytes from the input data and save them in the supplied output buffer.
    bool
    consume_data(
        _Inout_ _At_(*input, _Pre_readable_byte_size_(output_size) _Post_readable_byte_size_(*input_size))
            const uint8_t** input,
        _Inout_ _Pre_satisfies_(*input_size >= output_size) size_t* input_size,
        _Out_writes_bytes_(output_size) uint8_t* output,
        size_t output_size)
    {
        if (*input_size < output_size) {
            return false;
        }
        memcpy(output, *input, output_size);
        *input += output_size;
        *input_size -= output_size;
        return true;
    }

    void* dispatch_table;

    static NTSTATUS
    _program_information_attach_provider(
        _In_ HANDLE nmr_binding_handle,
        _In_ void* client_context,
        _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
    {

        fuzz_helper_function* wrapper = (fuzz_helper_function*)client_context;

        if (provider_registration_instance->ModuleId->Guid != wrapper->provider_guid) {
            return STATUS_INVALID_PARAMETER;
        }

        wrapper->program_data = (const ebpf_program_data_t*)provider_registration_instance->NpiSpecificCharacteristics;

        void* provider_binding_context;
        const void* provider_dispatch;

        // Register as an NmrClient for the global program information NPI.
        NTSTATUS status = NmrClientAttachProvider(
            nmr_binding_handle,
            client_context,
            &wrapper->dispatch_table,
            &provider_binding_context,
            &provider_dispatch);

        if (status != STATUS_SUCCESS) {
            return status;
        }

        for (size_t i = 0; i < wrapper->program_data->program_info->count_of_global_helpers; i++) {
            const ebpf_helper_function_prototype_t* helper_prototype =
                &wrapper->program_data->program_info->global_helper_prototype[i];
            wrapper->helper_prototypes[helper_prototype->helper_id] = helper_prototype;
            wrapper->helper_functions_addresses[helper_prototype->helper_id] =
                wrapper->program_data->global_helper_function_addresses->helper_function_address[i];
        }

        for (size_t i = 0; i < wrapper->program_data->program_info->count_of_program_type_specific_helpers; i++) {
            const ebpf_helper_function_prototype_t* helper_prototype =
                &wrapper->program_data->program_info->program_type_specific_helper_prototype[i];
            wrapper->helper_prototypes[helper_prototype->helper_id] = helper_prototype;
            wrapper->helper_functions_addresses[helper_prototype->helper_id] =
                wrapper->program_data->program_type_specific_helper_function_addresses->helper_function_address[i];
        }

        return STATUS_SUCCESS;
    }

    static NTSTATUS
    _program_information_detach_provider(_In_ void* client_binding_context)
    {
        UNREFERENCED_PARAMETER(client_binding_context);
        return STATUS_SUCCESS;
    }

    static constexpr NPI_CLIENT_CHARACTERISTICS _program_information_client_characteristics = {
        0,
        sizeof(NPI_CLIENT_CHARACTERISTICS),
        _program_information_attach_provider,
        _program_information_detach_provider,
        NULL,
        {
            0,
            sizeof(NPI_REGISTRATION_INSTANCE),
            &EBPF_PROGRAM_INFO_EXTENSION_IID,
            NULL,
            0,
            NULL,
        },
    };

    _Ret_maybenull_ const ebpf_map_definition_in_memory_t*
    get_map_definition(ebpf_map_type_t type)
    {
        for (auto& [_, m] : _map_definitions) {
            if (m.type == type) {
                return &m;
            }
        }
        return nullptr;
    }

  private:
    GUID provider_guid;
    std::map<ebpf_map_type_t, ebpf_map_t*> maps;
    NPI_CLIENT_CHARACTERISTICS program_information_client_characteristics;
    HANDLE program_information_nmr_handle;
    const ebpf_program_data_t* program_data;
    std::map<uint32_t, uintptr_t> helper_functions_addresses;
    std::map<uint32_t, const ebpf_helper_function_prototype_t*> helper_prototypes;
};
