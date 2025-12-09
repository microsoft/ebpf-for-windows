// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#define EBPF_TEST_POOL_TAG 'tPsE'
static uint32_t map_pool_tag = EBPF_TEST_POOL_TAG;

#include "ebpf_api.h"
#include "ebpf_extension.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_nethooks.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "ebpf_structs.h"
#include "ebpf_windows.h"
#include "net_ebpf_ext_program_info.h"
#include "sample_ext_maps.h"
#include "sample_ext_program_info.h"
#include "usersim/ex.h"
#include "usersim/ke.h"

// We need the NET_BUFFER typedefs without the other NT kernel defines that
// ndis.h might pull in and conflict with user-mode headers.
#ifndef _NDIS_
typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;
#pragma warning(disable : 4324) // structure was padded due to alignment specifier
#include <ndis/nbl.h>
#endif
#include <vector>

#define CONCAT(s1, s2) s1 s2
#define DECLARE_TEST_CASE(_name, _group, _function, _suffix, _execution_type) \
    TEST_CASE(CONCAT(_name, _suffix), _group) { _function(_execution_type); }
#define DECLARE_NATIVE_TEST(_name, _group, _function) \
    DECLARE_TEST_CASE(_name, _group, _function, "-native", EBPF_EXECUTION_NATIVE)
#if !defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define DECLARE_INTERPRET_TEST(_name, _group, _function) \
    DECLARE_TEST_CASE(_name, _group, _function, "-interpret", EBPF_EXECUTION_INTERPRET)
#else
#define DECLARE_INTERPRET_TEST(_name, _group, _function)
#endif

#define DECLARE_CGROUP_SOCK_ADDR_LOAD_TEST2(file, name, attach_type, name_suffix, file_suffix, execution_type) \
    TEST_CASE("cgroup_sockaddr_load_test_" name "_" #attach_type "_" name_suffix, "[cgroup_sock_addr]")        \
    {                                                                                                          \
        cgroup_sock_addr_load_test(file file_suffix, name, attach_type, execution_type);                       \
    }

typedef struct _sample_program_context_header
{
    EBPF_CONTEXT_HEADER;
    sample_program_context_t context;
} sample_program_context_header_t;

typedef struct _bind_context_header
{
    uint64_t context_header[8];
    bind_md_t context;
} bind_context_header_t;

typedef struct _sock_addr_context_header
{
    EBPF_CONTEXT_HEADER;
    bpf_sock_addr_t context;
} sock_addr_context_header_t;

typedef struct _sock_ops_context_header
{
    EBPF_CONTEXT_HEADER;
    bpf_sock_ops_t context;
} sock_ops_context_header_t;

#define INITIALIZE_BIND_CONTEXT      \
    bind_context_header_t header{0}; \
    bind_md_t* ctx = &header.context;

#define INITIALIZE_SAMPLE_CONTEXT              \
    sample_program_context_header_t header{0}; \
    sample_program_context_t* ctx = &header.context;

bpf_attach_type_t
ebpf_get_bpf_attach_type(_In_ const ebpf_attach_type_t* ebpf_attach_type) noexcept;

typedef struct _ebpf_free_memory
{
    void
    operator()(uint8_t* memory)
    {
        ebpf_free(memory);
    }
} ebpf_free_memory_t;

typedef std::unique_ptr<uint8_t, ebpf_free_memory_t> ebpf_memory_t;

typedef class _emulate_dpc
{
  public:
    _emulate_dpc(uint32_t cpu_id)
    {
        ebpf_assert_success(ebpf_set_current_thread_cpu_affinity(cpu_id, &old_thread_affinity_mask));
        KeRaiseIrql(DISPATCH_LEVEL, &old_irql);
    }
    ~_emulate_dpc()
    {
        KeLowerIrql(old_irql);

        ebpf_restore_current_thread_cpu_affinity(&old_thread_affinity_mask);
    }

  private:
    GROUP_AFFINITY old_thread_affinity_mask;
    KIRQL old_irql;

} emulate_dpc_t;

typedef class _test_global_helper
{
  public:
    static uint64_t
    _sample_get_pid_tgid()
    {
        return 9999;
    }
} test_global_helper_t;

class _test_sample_map_provider;

#pragma region Sample Array Map Implementation
typedef struct _test_sample_array_map
{
    sample_base_array_map_t base;
    class _test_sample_map_provider* provider;
} test_sample_array_map_t;

static ebpf_result_t
_test_sample_array_map_find_entry(
    _In_ void* map_context,
    size_t key_size,
    _In_reads_(key_size) const uint8_t* key,
    _Outptr_ uint8_t** value,
    uint32_t flags)
{
    test_sample_array_map_t* map = (test_sample_array_map_t*)map_context;
    return _sample_array_map_find_entry_common(&map->base, key_size, key, value, flags);
}

static ebpf_result_t
_test_sample_array_map_update_entry(
    _In_ void* map_context,
    size_t key_size,
    _In_reads_(key_size) const uint8_t* key,
    size_t value_size,
    _In_reads_(value_size) const uint8_t* value,
    ebpf_map_option_t option,
    uint32_t flags)
{
    test_sample_array_map_t* map = (test_sample_array_map_t*)map_context;
    return _sample_array_map_update_entry_common(&map->base, key_size, key, value_size, value, option, flags);
}

static ebpf_result_t
_test_sample_array_map_delete_entry(
    _In_ void* map_context, size_t key_size, _In_reads_(key_size) const uint8_t* key, uint32_t flags)
{
    test_sample_array_map_t* map = (test_sample_array_map_t*)map_context;
    return _sample_array_map_delete_entry_common(&map->base, key_size, key, flags);
}

static ebpf_result_t
_test_sample_array_map_get_next_key_and_value(
    _In_ void* map_context,
    size_t key_size,
    _In_opt_ const uint8_t* previous_key,
    _Out_writes_(key_size) uint8_t* next_key,
    _Outptr_opt_ uint8_t** next_value)
{
    test_sample_array_map_t* map = (test_sample_array_map_t*)map_context;
    return _sample_array_map_get_next_key_and_value_common(&map->base, key_size, previous_key, next_key, next_value);
}

static ebpf_result_t
_test_sample_map_associate_program(_In_ void* map_context, _In_ const ebpf_program_type_t* program_type)
{
    UNREFERENCED_PARAMETER(map_context);

    // Check that the program type is supported.
    if (*program_type != EBPF_PROGRAM_TYPE_SAMPLE) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }
    return EBPF_SUCCESS;
}
#pragma endregion

#pragma region Sample Hash Map Implementation
typedef struct _test_sample_hash_map
{
    sample_base_hash_map_t base;
    class _test_sample_map_provider* provider;
} test_sample_hash_map_t;

static ebpf_result_t
_test_sample_hash_map_get_next_key_and_value(
    _In_ void* map,
    size_t key_size,
    _In_ const uint8_t* previous_key,
    _Out_writes_(key_size) uint8_t* next_key,
    _Outptr_opt_ uint8_t** next_value)
{
    test_sample_hash_map_t* sample_map = (test_sample_hash_map_t*)map;
    return _sample_hash_map_get_next_key_and_value_common(
        &sample_map->base, key_size, previous_key, next_key, next_value);
}
#pragma endregion

static ebpf_result_t
_test_sample_array_map_create(
    _In_ void* binding_context,
    uint32_t map_type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    _Outptr_ void** map_context);

static void
_test_sample_array_map_delete(_In_ _Post_invalid_ void* map_context);

static ebpf_map_provider_dispatch_table_t _test_sample_array_map_dispatch_table = {
    .header = EBPF_MAP_PROVIDER_DISPATCH_TABLE_HEADER,
    .create_map_function = _test_sample_array_map_create,
    .delete_map_function = _test_sample_array_map_delete,
    .associate_program_function = _test_sample_map_associate_program,
    .find_element_function = _test_sample_array_map_find_entry,
    .update_element_function = _test_sample_array_map_update_entry,
    .delete_element_function = _test_sample_array_map_delete_entry,
    .get_next_key_and_value_function = _test_sample_array_map_get_next_key_and_value};

static ebpf_result_t
_test_sample_hash_map_create(
    _In_ void* binding_context,
    uint32_t map_type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    _Outptr_ void** map_context);

static void
_test_sample_hash_map_delete(_In_ _Post_invalid_ void* map);

static ebpf_result_t
_test_sample_hash_map_delete_entry(_In_ void* map, size_t key_size, _In_ const uint8_t* key, uint32_t flags);

static ebpf_result_t
_test_sample_hash_map_find_entry(
    _In_ void* map, size_t key_size, _In_reads_(key_size) const uint8_t* key, _Outptr_ uint8_t** value, uint32_t flags);

static ebpf_result_t
_test_sample_hash_map_update_entry(
    _In_ void* map,
    size_t key_size,
    _In_ const uint8_t* key,
    size_t value_size,
    _In_ const uint8_t* value,
    ebpf_map_option_t option,
    uint32_t flags);

static ebpf_result_t
_test_sample_hash_map_get_next_key_and_value(
    _In_ void* map,
    size_t key_size,
    _In_ const uint8_t* previous_key,
    _Out_writes_(key_size) uint8_t* next_key,
    _Outptr_opt_ uint8_t** next_value);

static ebpf_map_provider_dispatch_table_t _test_sample_hash_map_dispatch_table = {
    .header = EBPF_MAP_PROVIDER_DISPATCH_TABLE_HEADER,
    .create_map_function = _test_sample_hash_map_create,
    .delete_map_function = _test_sample_hash_map_delete,
    .associate_program_function = _test_sample_map_associate_program,
    .find_element_function = _test_sample_hash_map_find_entry,
    .update_element_function = _test_sample_hash_map_update_entry,
    .delete_element_function = _test_sample_hash_map_delete_entry,
    .get_next_key_and_value_function = _test_sample_hash_map_get_next_key_and_value};

static ebpf_map_provider_data_t _test_sample_array_map_provider_data = {
    EBPF_MAP_PROVIDER_DATA_HEADER, BPF_MAP_TYPE_SAMPLE_ARRAY_MAP, &_test_sample_array_map_dispatch_table};

static ebpf_map_provider_data_t _test_sample_hash_map_provider_data = {
    EBPF_MAP_PROVIDER_DATA_HEADER, BPF_MAP_TYPE_SAMPLE_HASH_MAP, &_test_sample_hash_map_dispatch_table};

typedef class _test_sample_map_provider
{
    // Map provider implementation
  public:
    ~_test_sample_map_provider()
    {
        if (_map_provider_handle != INVALID_HANDLE_VALUE) {
            NTSTATUS status = NmrDeregisterProvider(_map_provider_handle);
            if (status == STATUS_PENDING) {
                NmrWaitForProviderDeregisterComplete(_map_provider_handle);
            } else {
                ebpf_assert(status == STATUS_SUCCESS);
            }

            _map_provider_handle = INVALID_HANDLE_VALUE;
        }
    }

    ebpf_result_t
    initialize(ebpf_map_type_t map_type)
    {
        if (map_type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) {
            _map_provider_characteristics.ProviderRegistrationInstance.NpiSpecificCharacteristics =
                &_test_sample_array_map_provider_data;
        } else if (map_type == BPF_MAP_TYPE_SAMPLE_HASH_MAP) {
            _map_provider_characteristics.ProviderRegistrationInstance.NpiSpecificCharacteristics =
                &_test_sample_hash_map_provider_data;
        } else {
            return EBPF_OPERATION_NOT_SUPPORTED;
        }
        // Register as NMR provider
        NTSTATUS status = NmrRegisterProvider(&_map_provider_characteristics, this, &_map_provider_handle);
        return NT_SUCCESS(status) ? EBPF_SUCCESS : EBPF_FAILED;
    }

    static NTSTATUS
    _map_provider_attach_client(
        _In_ HANDLE nmr_binding_handle,
        _Inout_ void* provider_context,
        _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
        _In_ const void* client_binding_context,
        _In_ const void* client_dispatch,
        _Outptr_ void** provider_binding_context,
        _Outptr_result_maybenull_ const void** provider_dispatch)
    {
        UNREFERENCED_PARAMETER(nmr_binding_handle);
        UNREFERENCED_PARAMETER(client_registration_instance);
        UNREFERENCED_PARAMETER(client_binding_context);
        UNREFERENCED_PARAMETER(client_dispatch);

        test_sample_map_provider_t* map_provider = (test_sample_map_provider_t*)provider_context;
        ebpf_map_client_data_t* client_data =
            (ebpf_map_client_data_t*)client_registration_instance->NpiSpecificCharacteristics;
        ebpf_map_client_dispatch_table_t* client_dispatch_table = client_data->dispatch_table;

        map_provider->set_dispatch_table(client_dispatch_table);
        map_provider->set_map_context_offset(client_data->map_context_offset);

        *provider_binding_context = provider_context;
        *provider_dispatch = nullptr;
        return STATUS_SUCCESS;
    }

    static NTSTATUS
    _map_provider_detach_client(_In_ const void* provider_binding_context)
    {
        UNREFERENCED_PARAMETER(provider_binding_context);
        return STATUS_SUCCESS;
    }

    static void
    _map_provider_cleanup_binding_context(_Frees_ptr_ void* provider_binding_context)
    {
        UNREFERENCED_PARAMETER(provider_binding_context);
    }

    void
    set_dispatch_table(_In_ ebpf_map_client_dispatch_table_t* client_dispatch_table)
    {
        memcpy(&_client_dispatch_table, client_dispatch_table, sizeof(ebpf_map_client_dispatch_table_t));
    }

    ebpf_map_client_dispatch_table_t*
    dispatch_table()
    {
        return &_client_dispatch_table;
    }

    static void
    set_map_context_offset(uint64_t offset)
    {
        _map_context_offset = offset;
    }

    static uint64_t
    get_map_context_offset()
    {
        return _map_context_offset;
    }

    // NMR Provider infrastructure
  private:
    HANDLE _map_provider_handle = INVALID_HANDLE_VALUE;
    NPI_MODULEID _map_module_id = {sizeof(NPI_MODULEID), MIT_GUID, EBPF_SAMPLE_MAP_PROVIDER_GUID};
    NPI_PROVIDER_CHARACTERISTICS _map_provider_characteristics = {
        0,
        sizeof(NPI_PROVIDER_CHARACTERISTICS),
        (NPI_PROVIDER_ATTACH_CLIENT_FN*)_map_provider_attach_client,
        (NPI_PROVIDER_DETACH_CLIENT_FN*)_map_provider_detach_client,
        (PNPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN)_map_provider_cleanup_binding_context,
        {0, sizeof(NPI_REGISTRATION_INSTANCE), &EBPF_MAP_INFO_EXTENSION_IID, &_map_module_id, 0, NULL}};

    ebpf_map_client_dispatch_table_t _client_dispatch_table = {};

    static uint64_t _map_context_offset;
} test_sample_map_provider_t;

// Definition of the static member variable - inline to avoid multiple definition errors
inline uint64_t _test_sample_map_provider::_map_context_offset = 0;

static ebpf_result_t
_test_sample_array_map_create(
    _In_ void* binding_context,
    uint32_t map_type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    _Outptr_ void** map_context)
{
    UNREFERENCED_PARAMETER(map_type);

    if (key_size == 0 || value_size == 0 || max_entries == 0) {
        return EBPF_INVALID_ARGUMENT;
    }

    test_sample_map_provider_t* provider = (test_sample_map_provider_t*)binding_context;

    test_sample_array_map_t* sample_map =
        (test_sample_array_map_t*)provider->dispatch_table()->epoch_allocate_cache_aligned_with_tag(
            sizeof(test_sample_array_map_t), EBPF_TEST_POOL_TAG);
    if (sample_map == nullptr) {
        return EBPF_NO_MEMORY;
    }
    memset(sample_map, 0, sizeof(test_sample_array_map_t));
    sample_map->base.core.map_type = map_type;
    sample_map->base.core.key_size = key_size;
    sample_map->base.core.value_size = value_size;
    sample_map->base.core.max_entries = max_entries;
    sample_map->provider = provider;

    sample_map->base.data = (uint8_t*)provider->dispatch_table()->epoch_allocate_cache_aligned_with_tag(
        (size_t)value_size * (size_t)max_entries, EBPF_TEST_POOL_TAG);
    if (sample_map->base.data == nullptr) {
        provider->dispatch_table()->epoch_free_cache_aligned(sample_map);
        return EBPF_NO_MEMORY;
    }

    *map_context = (void*)sample_map;
    return EBPF_SUCCESS;
}

static void
_test_sample_array_map_delete(_In_ _Post_invalid_ void* map_context)
{
    if (map_context == nullptr) {
        return;
    }

    test_sample_array_map_t* map = (test_sample_array_map_t*)map_context;

    if (map->base.data != nullptr) {
        map->provider->dispatch_table()->epoch_free_cache_aligned(map->base.data);
    }

    // Free map structure
    map->provider->dispatch_table()->epoch_free_cache_aligned(map);
}

static ebpf_result_t
_test_sample_hash_map_create(
    _In_ void* binding_context,
    uint32_t map_type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    _Outptr_ void** map_context)
{
    ebpf_result_t result = EBPF_SUCCESS;
    UNREFERENCED_PARAMETER(map_type);

    if (key_size == 0 || value_size == 0 || max_entries == 0) {
        return EBPF_INVALID_ARGUMENT;
    }

    test_sample_map_provider_t* provider = (test_sample_map_provider_t*)binding_context;

    test_sample_hash_map_t* sample_map =
        (test_sample_hash_map_t*)provider->dispatch_table()->epoch_allocate_cache_aligned_with_tag(
            sizeof(test_sample_hash_map_t), EBPF_TEST_POOL_TAG);
    if (sample_map == nullptr) {
        return EBPF_NO_MEMORY;
    }

    memset(sample_map, 0, sizeof(test_sample_hash_map_t));
    sample_map->base.core.map_type = map_type;
    sample_map->base.core.key_size = key_size;
    sample_map->base.core.value_size = value_size;
    sample_map->base.core.max_entries = max_entries;
    sample_map->provider = provider;
    sample_map->base.bucket_count = max_entries;

    // Allocate array of hash buckets
    sample_map->base.buckets = (sample_hash_bucket_t*)provider->dispatch_table()->epoch_allocate_cache_aligned_with_tag(
        sizeof(sample_hash_bucket_t) * sample_map->base.bucket_count, EBPF_TEST_POOL_TAG);
    if (sample_map->base.buckets == NULL) {
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    *map_context = (void*)sample_map;

Exit:
    if (result != EBPF_SUCCESS && sample_map != NULL) {
        if (sample_map->base.buckets != NULL) {
            provider->dispatch_table()->epoch_free_cache_aligned(sample_map->base.buckets);
        }
        provider->dispatch_table()->epoch_free_cache_aligned(sample_map);
    }
    return result;
}

static void
_test_sample_hash_map_delete(_In_ _Post_invalid_ void* map)
{
    test_sample_hash_map_t* sample_map = (test_sample_hash_map_t*)map;
    if (sample_map == NULL) {
        return;
    }

    test_sample_map_provider_t* provider = sample_map->provider;
    ebpf_map_client_dispatch_table_t* client_dispatch_table = provider->dispatch_table();

    // Free all bucket arrays
    for (uint32_t i = 0; i < sample_map->base.bucket_count; i++) {
        sample_hash_bucket_t* bucket = &sample_map->base.buckets[i];
        if (bucket->entries != NULL) {
            // Free each entry's key-value data
            for (uint32_t j = 0; j < bucket->count; j++) {
                if (bucket->entries[j].key_value_data != NULL) {
                    client_dispatch_table->epoch_free(bucket->entries[j].key_value_data);
                }
            }
            // Free the entries array
            client_dispatch_table->epoch_free_cache_aligned(bucket->entries);
        }
    }

    if (sample_map->base.buckets != NULL) {
        client_dispatch_table->epoch_free_cache_aligned(sample_map->base.buckets);
    }
    client_dispatch_table->epoch_free_cache_aligned(sample_map);
}

static ebpf_result_t
_test_sample_hash_map_delete_entry(_In_ void* map, size_t key_size, _In_ const uint8_t* key, uint32_t flags)
{
    test_sample_hash_map_t* sample_map = (test_sample_hash_map_t*)map;
    ebpf_map_client_dispatch_table_t* client_dispatch_table = sample_map->provider->dispatch_table();
    return _sample_hash_map_delete_entry_common(client_dispatch_table, &sample_map->base, key_size, key, flags);
}

static ebpf_result_t
_test_sample_hash_map_find_entry(
    _In_ void* map, size_t key_size, _In_reads_(key_size) const uint8_t* key, _Outptr_ uint8_t** value, uint32_t flags)
{
    test_sample_hash_map_t* sample_map = (test_sample_hash_map_t*)map;
    ebpf_map_client_dispatch_table_t* client_dispatch_table = sample_map->provider->dispatch_table();
    return _sample_hash_map_find_entry_common(client_dispatch_table, &sample_map->base, key_size, key, value, flags);
}

static ebpf_result_t
_test_sample_hash_map_update_entry(
    _In_ void* map,
    size_t key_size,
    _In_ const uint8_t* key,
    size_t value_size,
    _In_ const uint8_t* value,
    ebpf_map_option_t option,
    uint32_t flags)
{
    test_sample_hash_map_t* sample_map = (test_sample_hash_map_t*)map;
    ebpf_map_client_dispatch_table_t* client_dispatch_table = sample_map->provider->dispatch_table();
    return _sample_hash_map_update_entry_common(
        client_dispatch_table, &sample_map->base, key_size, key, value_size, value, option, flags);
}

typedef class _test_sample_helper
{
  public:
    static int64_t
    _sample_ebpf_extension_helper_function1(_In_ const sample_program_context_t* context)
    {
        UNREFERENCED_PARAMETER(context);
        return 0;
    }

    static int64_t
    _sample_ebpf_extension_find(_In_ const void* buffer, uint32_t size, _In_ const void* find, uint32_t arg_size)
    {
        UNREFERENCED_PARAMETER(size);
        UNREFERENCED_PARAMETER(arg_size);
        return strstr((char*)buffer, (char*)find) - (char*)buffer;
    }

    static int64_t
    _sample_ebpf_extension_replace(
        _In_ const void* buffer, uint32_t size, int64_t position, _In_ const void* replace, uint32_t arg_size)
    {
        int64_t result = 0;
        char* dest;
        char* end = (char*)buffer + size - 1;
        char* source = (char*)replace;
        UNREFERENCED_PARAMETER(arg_size);

        if (position < 0) {
            result = -1;
            goto Exit;
        }

        if (position >= size) {
            result = -1;
            goto Exit;
        }

        dest = (char*)buffer + position;
        while (dest != end) {
            if (*source == '\0') {
                break;
            }
            *dest++ = *source++;
        }

    Exit:
        return result;
    }

    static int64_t
    _sample_ebpf_extension_helper_implicit_1(
        uint64_t dummy_param1,
        uint64_t dummy_param2,
        uint64_t dummy_param3,
        uint64_t dummy_param4,
        uint64_t dummy_param5,
        _In_ const sample_program_context_t* context)
    {
        UNREFERENCED_PARAMETER(dummy_param1);
        UNREFERENCED_PARAMETER(dummy_param2);
        UNREFERENCED_PARAMETER(dummy_param3);
        UNREFERENCED_PARAMETER(dummy_param4);
        UNREFERENCED_PARAMETER(dummy_param5);
        sample_program_context_t* sample_context = (sample_program_context_t*)context;
        return sample_context->helper_data_1;
    }

    static int64_t
    _sample_ebpf_extension_helper_implicit_2(
        uint32_t arg,
        uint64_t dummy_param1,
        uint64_t dummy_param2,
        uint64_t dummy_param3,
        uint64_t dummy_param4,
        _In_ const sample_program_context_t* context)
    {
        UNREFERENCED_PARAMETER(dummy_param1);
        UNREFERENCED_PARAMETER(dummy_param2);
        UNREFERENCED_PARAMETER(dummy_param3);
        UNREFERENCED_PARAMETER(dummy_param4);
        sample_program_context_t* sample_context = (sample_program_context_t*)context;
        return ((uint64_t)sample_context->helper_data_2 + arg);
    }

    static void*
    _sample_helper_map_lookup_element(
        _In_ const void* map,
        _In_ const uint8_t* key,
        uint64_t dummy_param1,
        uint64_t dummy_param2,
        uint64_t dummy_param3)
    {
        UNREFERENCED_PARAMETER(dummy_param1);
        UNREFERENCED_PARAMETER(dummy_param2);
        UNREFERENCED_PARAMETER(dummy_param3);

        sample_core_map_t** sample_map =
            (sample_core_map_t**)MAP_CONTEXT(map, test_sample_map_provider_t::get_map_context_offset());
        if (*sample_map == NULL) {
            return NULL;
        }
        uint8_t* value = NULL;

        if ((*sample_map)->map_type == BPF_MAP_TYPE_SAMPLE_ARRAY_MAP) {
            ebpf_result_t result =
                _test_sample_array_map_find_entry(*sample_map, (*sample_map)->key_size, key, &value, 0);
            if (result != EBPF_SUCCESS) {
                return NULL;
            }
        } else if ((*sample_map)->map_type == BPF_MAP_TYPE_SAMPLE_HASH_MAP) {
            ebpf_result_t result =
                _test_sample_hash_map_find_entry(*sample_map, (*sample_map)->key_size, key, &value, 0);
            if (result != EBPF_SUCCESS) {
                return NULL;
            }
        } else {
            return NULL;
        }

        return value;
    }
} test_sample_helper_t;

// These are test sample context creation functions.
static ebpf_result_t
_sample_test_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    _In_ size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    _In_ size_t context_size_in,
    _Outptr_ void** context)
{
    ebpf_result_t retval = EBPF_FAILED;
    sample_program_context_header_t* context_header = nullptr;
    sample_program_context_t* sample_context = nullptr;
    *context = nullptr;

    // Context is required.
    if (!context_in || context_size_in < sizeof(sample_program_context_t)) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    context_header =
        reinterpret_cast<sample_program_context_header_t*>(malloc(sizeof(sample_program_context_header_t)));
    if (!context_header) {
        goto Done;
    }
    sample_context = &context_header->context;

    memcpy(sample_context, context_in, sizeof(sample_program_context_t));

    if (data_in) {
        sample_context->data_start = (uint8_t*)data_in;
        sample_context->data_end = (uint8_t*)data_in + data_size_in;
    } else {
        sample_context->data_start = nullptr;
        sample_context->data_end = nullptr;
    }

    *context = sample_context;
    sample_context = nullptr;
    context_header = nullptr;
    retval = EBPF_SUCCESS;

Done:
    free(context_header);
    context_header = nullptr;
    return retval;
}

static void
_sample_test_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    UNREFERENCED_PARAMETER(data_out);
    if (!context) {
        return;
    }
    sample_program_context_header_t* context_header =
        CONTAINING_RECORD(context, sample_program_context_header_t, context);

    // Data is not supported.
    *data_size_out = 0;

    if (context_out && *context_size_out >= sizeof(sample_program_context_t)) {
        memcpy(context_out, context, sizeof(sample_program_context_t));
        *context_size_out = sizeof(sample_program_context_t);
    } else {
        *context_size_out = 0;
    }

    free(context_header);
}

#define TEST_NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION 0

// program info provider data for various program types.

// Bind.
static ebpf_result_t
_ebpf_bind_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    ebpf_result_t retval;
    *context = nullptr;
    bind_md_t* bind_context = nullptr;
    bind_context_header_t* bind_context_header = reinterpret_cast<bind_context_header_t*>(
        ebpf_allocate_with_tag(sizeof(bind_context_header_t), EBPF_POOL_TAG_DEFAULT));
    if (bind_context_header == nullptr) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }
    bind_context = &bind_context_header->context;

    if (context_in) {
        if (context_size_in < sizeof(bind_md_t)) {
            retval = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        bind_md_t* provided_context = (bind_md_t*)context_in;
        *bind_context = *provided_context;
    }

    bind_context->app_id_start = 0;
    bind_context->app_id_end = 0;

    if (data_in) {
        bind_context->app_id_start = (uint8_t*)data_in;
        bind_context->app_id_end = (uint8_t*)data_in + data_size_in;
    }

    *context = bind_context;
    bind_context = nullptr;
    bind_context_header = nullptr;
    retval = EBPF_SUCCESS;
Done:
    ebpf_free(bind_context_header);
    bind_context_header = nullptr;
    return retval;
}

static void
_ebpf_bind_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    UNREFERENCED_PARAMETER(data_out);
    if (!context) {
        return;
    }

    bind_md_t* bind_context = reinterpret_cast<bind_md_t*>(context);
    bind_context_header_t* bind_context_header = CONTAINING_RECORD(bind_context, bind_context_header_t, context);
    if (context_out && *context_size_out >= sizeof(bind_md_t)) {
        bind_md_t* provided_context = (bind_md_t*)context_out;
        *provided_context = *bind_context;
        *context_size_out = sizeof(bind_md_t);
    }

    ebpf_free(bind_context_header);
    bind_context_header = nullptr;

    *data_size_out = 0;
    return;
}

static ebpf_program_data_t _ebpf_bind_program_data = {
    .header = EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_ebpf_bind_program_info,
    .context_create = _ebpf_bind_context_create,
    .context_destroy = _ebpf_bind_context_destroy,
    .capabilities = {0},
};

// SOCK_ADDR.
static int
_ebpf_sock_addr_set_redirect_context(_In_ const bpf_sock_addr_t* ctx, _In_ void* data, _In_ uint32_t data_size)
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(data_size);
    return -ENOTSUP;
}

static uint64_t
_ebpf_sock_addr_get_current_pid_tgid_implicit(
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    uint64_t dummy_param5,
    _In_ const bpf_sock_addr_t* ctx)
{
    UNREFERENCED_PARAMETER(dummy_param1);
    UNREFERENCED_PARAMETER(dummy_param2);
    UNREFERENCED_PARAMETER(dummy_param3);
    UNREFERENCED_PARAMETER(dummy_param4);
    UNREFERENCED_PARAMETER(dummy_param5);
    UNREFERENCED_PARAMETER(ctx);
    return 0;
}

static int
_ebpf_sock_addr_get_current_logon_id(_In_ const bpf_sock_addr_t* ctx)
{
    UNREFERENCED_PARAMETER(ctx);
    return -ENOTSUP;
}

static int
_ebpf_sock_addr_is_current_admin(_In_ const bpf_sock_addr_t* ctx)
{
    UNREFERENCED_PARAMETER(ctx);
    return -ENOTSUP;
}

static uint64_t
_ebpf_sock_addr_get_socket_cookie(_In_ const bpf_sock_addr_t* ctx)
{
    UNREFERENCED_PARAMETER(ctx);
    return 0;
}

static ebpf_result_t
_ebpf_sock_addr_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    UNREFERENCED_PARAMETER(data_in);
    UNREFERENCED_PARAMETER(data_size_in);

    ebpf_result_t retval;
    *context = nullptr;

    bpf_sock_addr_t* sock_addr_context = nullptr;
    sock_addr_context_header_t* sock_addr_context_header = reinterpret_cast<sock_addr_context_header_t*>(
        ebpf_allocate_with_tag(sizeof(sock_addr_context_header_t), EBPF_POOL_TAG_DEFAULT));
    if (sock_addr_context_header == nullptr) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }
    sock_addr_context = &sock_addr_context_header->context;

    if (context_in) {
        if (context_size_in < sizeof(bpf_sock_addr_t)) {
            retval = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        bpf_sock_addr_t* provided_context = (bpf_sock_addr_t*)context_in;
        *sock_addr_context = *provided_context;
    }

    *context = sock_addr_context;
    sock_addr_context = nullptr;
    sock_addr_context_header = nullptr;
    retval = EBPF_SUCCESS;
Done:
    ebpf_free(sock_addr_context_header);
    sock_addr_context = nullptr;
    return retval;
}

static void
_ebpf_sock_addr_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    UNREFERENCED_PARAMETER(data_out);
    if (!context) {
        return;
    }

    bpf_sock_addr_t* sock_addr_context = reinterpret_cast<bpf_sock_addr_t*>(context);
    sock_addr_context_header_t* sock_addr_context_header =
        CONTAINING_RECORD(sock_addr_context, sock_addr_context_header_t, context);
    if (context_out && *context_size_out >= sizeof(bpf_sock_addr_t)) {
        bpf_sock_addr_t* provided_context = (bpf_sock_addr_t*)context_out;
        *provided_context = *sock_addr_context;
        *context_size_out = sizeof(bpf_sock_addr_t);
    }

    ebpf_free(sock_addr_context_header);
    sock_addr_context_header = nullptr;

    *data_size_out = 0;
    return;
}

static const void* _ebpf_sock_addr_specific_helper_functions[] = {(void*)_ebpf_sock_addr_set_redirect_context};

static ebpf_helper_function_addresses_t _ebpf_sock_addr_specific_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_ebpf_sock_addr_specific_helper_functions),
    (uint64_t*)_ebpf_sock_addr_specific_helper_functions};

static const void* _ebpf_sock_addr_global_helper_functions[] = {
    (void*)_ebpf_sock_addr_get_current_pid_tgid_implicit,
    (void*)_ebpf_sock_addr_get_current_logon_id,
    (void*)_ebpf_sock_addr_is_current_admin,
    (void*)_ebpf_sock_addr_get_socket_cookie};

static ebpf_helper_function_addresses_t _ebpf_sock_addr_global_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_ebpf_sock_addr_global_helper_functions),
    (uint64_t*)_ebpf_sock_addr_global_helper_functions};

static ebpf_program_data_t _ebpf_sock_addr_program_data = {
    .header = EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_ebpf_sock_addr_program_info,
    .program_type_specific_helper_function_addresses = &_ebpf_sock_addr_specific_helper_function_address_table,
    .global_helper_function_addresses = &_ebpf_sock_addr_global_helper_function_address_table,
    .context_create = &_ebpf_sock_addr_context_create,
    .context_destroy = &_ebpf_sock_addr_context_destroy,
    .required_irql = DISPATCH_LEVEL,
    .capabilities = {0},
};

// SOCK_OPS.
static uint64_t
_ebpf_sock_ops_get_current_pid_tgid(
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    uint64_t dummy_param5,
    _In_ const bpf_sock_addr_t* ctx)
{
    UNREFERENCED_PARAMETER(dummy_param1);
    UNREFERENCED_PARAMETER(dummy_param2);
    UNREFERENCED_PARAMETER(dummy_param3);
    UNREFERENCED_PARAMETER(dummy_param4);
    UNREFERENCED_PARAMETER(dummy_param5);
    UNREFERENCED_PARAMETER(ctx);
    return 0;
}

static const void* _ebpf_sock_ops_global_helper_functions[] = {(void*)_ebpf_sock_ops_get_current_pid_tgid};

static ebpf_helper_function_addresses_t _ebpf_sock_ops_global_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_ebpf_sock_ops_global_helper_functions),
    (uint64_t*)_ebpf_sock_ops_global_helper_functions};

static ebpf_result_t
_ebpf_sock_ops_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    UNREFERENCED_PARAMETER(data_in);
    UNREFERENCED_PARAMETER(data_size_in);
    ebpf_result_t retval;
    *context = nullptr;

    bpf_sock_ops_t* sock_ops_context = nullptr;
    sock_ops_context_header_t* sock_ops_context_header = reinterpret_cast<sock_ops_context_header_t*>(
        ebpf_allocate_with_tag(sizeof(sock_ops_context_header_t), EBPF_POOL_TAG_DEFAULT));
    if (sock_ops_context_header == nullptr) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }
    sock_ops_context = &sock_ops_context_header->context;

    if (context_in) {
        if (context_size_in < sizeof(bpf_sock_ops_t)) {
            retval = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        bpf_sock_ops_t* provided_context = (bpf_sock_ops_t*)context_in;
        *sock_ops_context = *provided_context;
    }

    *context = sock_ops_context;
    sock_ops_context = nullptr;
    sock_ops_context_header = nullptr;
    retval = EBPF_SUCCESS;
Done:
    ebpf_free(sock_ops_context_header);
    sock_ops_context = nullptr;
    return retval;
}

static void
_ebpf_sock_ops_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    UNREFERENCED_PARAMETER(data_out);
    if (!context) {
        return;
    }

    bpf_sock_ops_t* sock_ops_context = reinterpret_cast<bpf_sock_ops_t*>(context);
    sock_ops_context_header_t* sock_ops_context_header =
        CONTAINING_RECORD(sock_ops_context, sock_ops_context_header_t, context);
    if (context_out && *context_size_out >= sizeof(bpf_sock_ops_t)) {
        bpf_sock_ops_t* provided_context = (bpf_sock_ops_t*)context_out;
        *provided_context = *sock_ops_context;
        *context_size_out = sizeof(bpf_sock_ops_t);
    }

    ebpf_free(sock_ops_context_header);
    sock_ops_context_header = nullptr;

    *data_size_out = 0;
    return;
}

static ebpf_program_data_t _ebpf_sock_ops_program_data = {
    .header = EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_ebpf_sock_ops_program_info,
    .global_helper_function_addresses = &_ebpf_sock_ops_global_helper_function_address_table,
    .context_create = &_ebpf_sock_ops_context_create,
    .context_destroy = &_ebpf_sock_ops_context_destroy,
    .required_irql = DISPATCH_LEVEL,
    .capabilities = {0},
};

// Sample extension.
static const void* _sample_ebpf_ext_helper_functions[] = {
    test_sample_helper_t::_sample_ebpf_extension_helper_function1,
    test_sample_helper_t::_sample_ebpf_extension_find,
    test_sample_helper_t::_sample_ebpf_extension_replace,
    test_sample_helper_t::_sample_ebpf_extension_helper_implicit_1,
    test_sample_helper_t::_sample_ebpf_extension_helper_implicit_2,
    test_sample_helper_t::_sample_helper_map_lookup_element};

static ebpf_helper_function_addresses_t _sample_ebpf_ext_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_sample_ebpf_ext_helper_functions),
    (uint64_t*)_sample_ebpf_ext_helper_functions};

static const void* _test_global_helper_functions[] = {test_global_helper_t::_sample_get_pid_tgid};

static ebpf_helper_function_addresses_t _test_global_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_test_global_helper_functions),
    (uint64_t*)_test_global_helper_functions};

static ebpf_program_data_t _test_ebpf_sample_extension_program_data = {
    EBPF_PROGRAM_DATA_HEADER,
    &_sample_ebpf_extension_program_info,
    &_sample_ebpf_ext_helper_function_address_table,
    &_test_global_helper_function_address_table,
    _sample_test_context_create,
    _sample_test_context_destroy,
    0,
    {0},
};

#define TEST_EBPF_SAMPLE_EXTENSION_NPI_PROVIDER_VERSION 0

typedef class _program_info_provider
{
  public:
    _program_info_provider() : program_data(nullptr), nmr_provider_handle(INVALID_HANDLE_VALUE)
    {
        memset(&_program_type, 0, sizeof(_program_type));
    }

    ebpf_result_t
    initialize(ebpf_program_type_t program_type, ebpf_program_data_t* custom_program_data = nullptr)
    {
        this->_program_type = program_type;

        if (custom_program_data != nullptr) {
            program_data = custom_program_data;
        } else if (program_type == EBPF_PROGRAM_TYPE_BIND) {
            program_data = &_ebpf_bind_program_data;
        } else if (program_type == EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR) {
            program_data = &_ebpf_sock_addr_program_data;
        } else if (program_type == EBPF_PROGRAM_TYPE_SOCK_OPS) {
            program_data = &_ebpf_sock_ops_program_data;
        } else if (program_type == EBPF_PROGRAM_TYPE_SAMPLE) {
            program_data = &_test_ebpf_sample_extension_program_data;
        } else {
            // Unsupported program type.
            return EBPF_INVALID_ARGUMENT;
        }

        module_id.Guid = program_data->program_info->program_type_descriptor->program_type;
        provider_characteristics.ProviderRegistrationInstance.NpiSpecificCharacteristics = program_data;

        NTSTATUS status = NmrRegisterProvider(&provider_characteristics, this, &nmr_provider_handle);
        return (NT_SUCCESS(status)) ? EBPF_SUCCESS : EBPF_FAILED;
    }
    ~_program_info_provider()
    {
        if (nmr_provider_handle != INVALID_HANDLE_VALUE) {
            NTSTATUS status = NmrDeregisterProvider(nmr_provider_handle);
            if (status == STATUS_PENDING) {
                NmrWaitForProviderDeregisterComplete(nmr_provider_handle);
            } else {
                ebpf_assert(status == STATUS_SUCCESS);
            }
        }
    }

  private:
    static NTSTATUS
    provider_attach_client_callback(
        HANDLE nmr_binding_handle,
        _Inout_ void* provider_context,
        _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
        _In_ const void* client_binding_context,
        _In_ const void* client_dispatch,
        _Out_ void** provider_binding_context,
        _Out_ const void** provider_dispatch)
    {
        auto hook = reinterpret_cast<_program_info_provider*>(provider_context);
        UNREFERENCED_PARAMETER(nmr_binding_handle);
        UNREFERENCED_PARAMETER(client_dispatch);
        UNREFERENCED_PARAMETER(client_binding_context);
        UNREFERENCED_PARAMETER(client_registration_instance);
        UNREFERENCED_PARAMETER(hook);
        *provider_binding_context = provider_context;
        *provider_dispatch = NULL;
        return STATUS_SUCCESS;
    };

    static NTSTATUS
    provider_detach_client_callback(_Inout_ void* provider_binding_context)
    {
        auto hook = reinterpret_cast<_program_info_provider*>(provider_binding_context);
        UNREFERENCED_PARAMETER(hook);

        // There should be no in-progress calls to any client functions,
        // we we can return success rather than pending.
        return EBPF_SUCCESS;
    };

    ebpf_program_type_t _program_type;
    const ebpf_program_data_t* program_data;

    NPI_MODULEID module_id = {
        sizeof(NPI_MODULEID),
        MIT_GUID,
    };

    NPI_PROVIDER_CHARACTERISTICS provider_characteristics{
        0,
        sizeof(NPI_PROVIDER_CHARACTERISTICS),
        (NPI_PROVIDER_ATTACH_CLIENT_FN*)provider_attach_client_callback,
        (NPI_PROVIDER_DETACH_CLIENT_FN*)provider_detach_client_callback,
        NULL,
        {
            0,
            sizeof(NPI_REGISTRATION_INSTANCE),
            &EBPF_PROGRAM_INFO_EXTENSION_IID,
            &module_id,
            0,
            NULL,
        },
    };
    HANDLE nmr_provider_handle;
} program_info_provider_t;

#define ETHERNET_TYPE_IPV4 0x0800
std::vector<uint8_t>
prepare_udp_packet(uint16_t udp_length, uint16_t ethertype);

class _wait_event
{
  public:
    ebpf_handle_t
    handle()
    {
        initialize();
        // ObReferenceObjectByHandle in usersim simply reinterprets the handle as a pointer.
        return reinterpret_cast<ebpf_handle_t>(&_event);
    }

    KEVENT*
    operator&()
    {
        initialize();
        return &_event;
    }

  private:
    bool _initialized = false;
    KEVENT _event = {0};

    void
    initialize()
    {
        if (_initialized) {
            return;
        }

        KeInitializeEvent(&_event, SynchronizationEvent, FALSE);

        // Take a refcount on the event, without ever dropping it. This avoids
        // a call to CloseHandle in the ObfDereferenceObject implementation in
        // usersim.
        ObfReferenceObject(&_event);

        _initialized = true;
    }
};
