// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#define EBPF_FILE_ID EBPF_FILE_ID_NATIVE

#include "ebpf_core.h"
#include "ebpf_handle.h"
#include "ebpf_hash_table.h"
#include "ebpf_native.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "ebpf_protocol.h"
#include "ebpf_tracelog.h"

#include <intrin.h>

#define DEFAULT_PIN_ROOT_PATH "/ebpf/global"
#define EBPF_MAX_PIN_PATH_LENGTH 256

static const uint32_t _ebpf_native_marker = 'entv';

// Set this value if there is a need to block older version of the native driver.
static bpf2c_version_t _ebpf_minimum_version = {0, 0, 0};

#ifndef __CGUID_H__
static const GUID GUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
#endif

typedef uint64_t (*helper_function_address)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5);

typedef struct _ebpf_native_map
{
    map_entry_t* entry;
    struct _ebpf_native_map* inner_map;
    ebpf_handle_t handle;
    ebpf_handle_t inner_map_handle;
    int32_t original_id;
    int32_t inner_map_original_id;
    cxplat_utf8_string_t pin_path;
    bool reused;
    bool pinned;
} ebpf_native_map_t;

typedef struct _ebpf_native_program
{
    struct _ebpf_native_module* module;
    program_entry_t* entry;
    ebpf_handle_t handle;
    struct _ebpf_native_helper_address_changed_context* addresses_changed_callback_context;
    // uintptr_t* map_addresses;
    program_runtime_context_t runtime_context;
} ebpf_native_program_t;

typedef enum _ebpf_native_module_state
{
    MODULE_STATE_UNINITIALIZED = 0,
    MODULE_STATE_INITIALIZING,
    MODULE_STATE_INITIALIZED,
    // MODULE_STATE_LOADING,
    // MODULE_STATE_LOADED,
    MODULE_STATE_UNLOADING,
} ebpf_native_module_state_t;

// typedef enum _ebpf_native_module_instance_state
// {
//     INSTANCE_STATE_UNINITIALIZED = 0,
//     INSTANCE_STATE_INITIALIZING,
//     INSTANCE_STATE_INITIALIZED,
// } ebpf_native_module_instance_state_t;

typedef struct _ebpf_native_handle_cleanup_information
{
    intptr_t process_handle;
    ebpf_process_state_t* process_state;
    size_t count_of_program_handles;
    ebpf_handle_t* program_handles;
    size_t count_of_map_handles;
    ebpf_handle_t* map_handles;
} ebpf_native_handle_cleanup_info_t;

typedef struct _ebpf_native_handle_cleanup_context
{
    ebpf_native_handle_cleanup_info_t* handle_information;
    cxplat_preemptible_work_item_t* handle_cleanup_work_item;
} ebpf_native_handle_cleanup_context_t;

typedef struct _ebpf_native_module
{
    ebpf_base_object_t base;
    GUID client_module_id;
    metadata_table_t table;
    ebpf_native_module_state_t state;
    bool detaching;
    _Field_z_ wchar_t* service_name; // This will be used to pass to the unload module workitem.
    ebpf_lock_t lock;
    // _Guarded_by_(lock) ebpf_hash_table_t* instance_table = NULL;
    // ebpf_native_map_t* maps;
    // size_t map_count;
    // ebpf_native_program_t* programs;
    // size_t program_count;
    HANDLE nmr_binding_handle;
    // ebpf_list_entry_t list_entry;
    cxplat_preemptible_work_item_t* cleanup_work_item;
    // ebpf_native_handle_cleanup_context_t handle_cleanup_context;
    KEVENT event;
    bool unload_driver_on_cleanup;
} ebpf_native_module_t;

typedef struct _ebpf_native_module_instance
{
    ebpf_native_module_t* module;
    // ebpf_base_object_t base;
    GUID instance_id;
    // metadata_table_t table;
    // ebpf_native_module_instance_state_t state;
    // bool detaching;
    // _Field_z_ wchar_t* service_name; // This will be used to pass to the unload module workitem.
    // ebpf_lock_t lock;
    ebpf_native_map_t* maps;
    size_t map_count;
    ebpf_native_program_t** programs;
    size_t program_count;
    // HANDLE nmr_binding_handle;
    // ebpf_list_entry_t list_entry;
    // cxplat_preemptible_work_item_t* cleanup_work_item;
    ebpf_native_handle_cleanup_context_t handle_cleanup_context;
} ebpf_native_module_instance_t;

static const GUID _ebpf_native_npi_id = {/* c847aac8-a6f2-4b53-aea3-f4a94b9a80cb */
                                         0xc847aac8,
                                         0xa6f2,
                                         0x4b53,
                                         {0xae, 0xa3, 0xf4, 0xa9, 0x4b, 0x9a, 0x80, 0xcb}};

static const NPI_MODULEID _ebpf_native_provider_module_id = {
    sizeof(NPI_MODULEID),
    MIT_GUID,
    {
        /* 5e24d2f5-f799-42c3-a945-87feefd930a7 */
        0x5e24d2f5,
        0xf799,
        0x42c3,
        {0xa9, 0x45, 0x87, 0xfe, 0xef, 0xd9, 0x30, 0xa7},
    },
};

static NPI_PROVIDER_ATTACH_CLIENT_FN _ebpf_native_provider_attach_client_callback;
static NPI_PROVIDER_DETACH_CLIENT_FN _ebpf_native_provider_detach_client_callback;

static const NPI_PROVIDER_CHARACTERISTICS _ebpf_native_provider_characteristics = {
    0,
    sizeof(_ebpf_native_provider_characteristics),
    _ebpf_native_provider_attach_client_callback,
    _ebpf_native_provider_detach_client_callback,
    NULL,
    {
        0,
        sizeof(NPI_REGISTRATION_INSTANCE),
        &_ebpf_native_npi_id,
        &_ebpf_native_provider_module_id,
        0,
        NULL,
    },
};

static HANDLE _ebpf_native_nmr_provider_handle = NULL;

// #define EBPF_CLIENT_TABLE_BUCKET_COUNT 64
static ebpf_lock_t _ebpf_native_client_table_lock = {0};
static _Guarded_by_(_ebpf_native_client_table_lock) ebpf_hash_table_t* _ebpf_native_client_table = NULL;

_Must_inspect_result_ ebpf_result_t
ebpf_native_load_driver(_In_z_ const wchar_t* service_name);
void
ebpf_native_unload_driver(_In_z_ const wchar_t* service_name);

static int
_ebpf_compare_versions(bpf2c_version_t* lhs, bpf2c_version_t* rhs)
{
    if (lhs->major < rhs->major) {
        return -1;
    }
    if (lhs->major > rhs->major) {
        return 1;
    }
    ebpf_assert(lhs->major == rhs->major);
    if (lhs->minor < rhs->major) {
        return -1;
    }
    if (lhs->minor > rhs->major) {
        return 1;
    }
    ebpf_assert(lhs->minor == rhs->minor);
    if (lhs->revision < rhs->revision) {
        return -1;
    }
    if (lhs->revision > rhs->revision) {
        return 1;
    }
    return 0;
}

typedef struct _ebpf_native_helper_address_changed_context
{
    const ebpf_native_module_t* module;
    ebpf_native_program_t* native_program;
} ebpf_native_helper_address_changed_context_t;

static ebpf_result_t
_ebpf_native_helper_address_changed(
    size_t address_count, _In_reads_opt_(address_count) uintptr_t* addresses, _In_opt_ void* context);

static void
_ebpf_native_unload_work_item(_In_ cxplat_preemptible_work_item_t* work_item, _In_opt_ const void* service)
{
    // We do not need epoch awareness here. Specifically:
    // 1. We're not touching any epoch managed objects in this code path.
    // 2. Far more importantly, in the case where ebpfcore is shutting down, this work item will get executed _after_
    //    the 'epoch' functionality has already been shut down.
    if (service != NULL) {
        ebpf_native_unload_driver((const wchar_t*)service);
        ebpf_free((void*)service);
    }
    cxplat_free_preemptible_work_item(work_item);
}

static inline bool
_ebpf_native_is_map_in_map(_In_ const ebpf_native_map_t* map)
{
    if (map->entry->definition.type == BPF_MAP_TYPE_HASH_OF_MAPS ||
        map->entry->definition.type == BPF_MAP_TYPE_ARRAY_OF_MAPS) {
        return true;
    }

    return false;
}

static void
_ebpf_native_clean_up_maps(
    _In_reads_(map_count) _Frees_ptr_ ebpf_native_map_t* maps, size_t map_count, bool unpin, bool close_handles)
{
    for (uint32_t count = 0; count < map_count; count++) {
        ebpf_native_map_t* map = &maps[count];

        if (unpin) {
            // Map should only be unpinned if this is a failure case, and the map
            // was created and pinned while loading the native module.
            if (map->pin_path.value && map->pinned && !map->reused) {
                ebpf_assert_success(ebpf_core_update_pinning(UINT64_MAX, &map->pin_path));
            }
        }
        if (map->pin_path.value) {
#pragma warning(push)
#pragma warning(disable : 6001) // Using uninitialized memory '*maps.pin_path.value'
            ebpf_free(map->pin_path.value);
#pragma warning(pop)
        }
        if (close_handles && map->handle != ebpf_handle_invalid) {
            ebpf_assert_success(ebpf_handle_close(map->handle));
            map->handle = ebpf_handle_invalid;
        }
    }

    ebpf_free(maps);
}

static void
_ebpf_native_clean_up_program(_In_opt_ _Post_invalid_ ebpf_native_program_t* program, bool close_handle)
{
    if (program != NULL) {
        if (program->handle != ebpf_handle_invalid) {
            ebpf_program_t* program_object = NULL;
            ebpf_assert_success(EBPF_OBJECT_REFERENCE_BY_HANDLE(
                program->handle, EBPF_OBJECT_PROGRAM, (ebpf_core_object_t**)&program_object));
            ebpf_assert_success(ebpf_program_register_for_helper_changes(program_object, NULL, NULL));
            EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)program_object);
            if (close_handle) {
                ebpf_assert_success(ebpf_handle_close(program->handle));
                program->handle = ebpf_handle_invalid;
            }
        }
        ebpf_free(program->addresses_changed_callback_context);
        program->addresses_changed_callback_context = NULL;
        ebpf_free(program->runtime_context.helper_data);
        ebpf_free(program->runtime_context.map_data);
        ebpf_free(program);
    }
}

static void
_ebpf_native_clean_up_programs(
    _In_reads_(count_of_programs) ebpf_native_program_t** programs, size_t count_of_programs, bool close_handles)
{
    for (uint32_t i = 0; i < count_of_programs; i++) {
        _ebpf_native_clean_up_program(programs[i], close_handles);
    }

    ebpf_free(programs);
}

/**
 * @brief Free all state for a given module.
 * @param[in] module The module to free.
 */
static void
_ebpf_native_clean_up_module(_In_ _Post_invalid_ ebpf_native_module_t* module)
{
    // _ebpf_native_clean_up_maps(module->maps, module->map_count, false, true);
    // _ebpf_native_clean_up_programs(module->programs, module->program_count, true);

    // module->maps = NULL;
    // module->map_count = 0;
    // module->programs = NULL;
    // module->program_count = 0;

    // ebpf_free(module->map_addresses);

    cxplat_free_preemptible_work_item(module->cleanup_work_item);
    ebpf_free(module->service_name);

    ebpf_lock_destroy(&module->lock);

    ebpf_free(module);
}

/**
 * @brief Free all state for a given module.
 * @param[in] module The module to free.
 */
static void
_ebpf_native_clean_up_module_instance(_In_ ebpf_native_module_instance_t* instance)
{
    _ebpf_native_clean_up_maps(instance->maps, instance->map_count, false, true);
    _ebpf_native_clean_up_programs(instance->programs, instance->program_count, true);

    instance->maps = NULL;
    instance->map_count = 0;
    instance->programs = NULL;
    instance->program_count = 0;

    // ebpf_free(module->map_addresses);

    // cxplat_free_preemptible_work_item(instance->cleanup_work_item);
    // ebpf_free(instance->service_name);

    // ebpf_lock_destroy(&instance->lock);

    // ebpf_free(instance);
}

_Requires_lock_held_(module->lock) static ebpf_result_t _ebpf_native_unload(_Inout_ ebpf_native_module_t* module)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    cxplat_preemptible_work_item_t* work_item = NULL;

    if (module->state == MODULE_STATE_UNLOADING) {
        // If module is already unloading, skip unloading it again.
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "_ebpf_native_unload: module already unloading",
            &module->client_module_id);
        result = EBPF_SUCCESS;
        goto Done;
    }
    module->state = MODULE_STATE_UNLOADING;

    // Queue pre-allocated work item to unload the driver.
    work_item = module->cleanup_work_item;
    module->cleanup_work_item = NULL;
    module->service_name = NULL;

    cxplat_queue_preemptible_work_item(work_item);

Done:
    EBPF_RETURN_RESULT(result);
}

_Requires_exclusive_lock_held_(module->lock) static void _ebpf_native_acquire_reference_under_lock(
    _Inout_ ebpf_native_module_t* module)
{
    ebpf_assert(module->base.marker == _ebpf_native_marker);

    if (module->base.reference_count != 0) {
        module->base.reference_count++;
    } else {
        __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }
}

void
_ebpf_native_acquire_reference(_Inout_ ebpf_native_module_t* module)
{
    ebpf_lock_state_t state = 0;

    state = ebpf_lock_lock(&module->lock);
    _ebpf_native_acquire_reference_under_lock(module);
    ebpf_lock_unlock(&module->lock, state);
}

void
ebpf_native_acquire_reference(_Inout_ ebpf_native_program_t* binding_context)
{
    _ebpf_native_acquire_reference((ebpf_native_module_t*)binding_context->module);
}

static void
_ebpf_native_release_reference(_In_opt_ _Post_invalid_ ebpf_native_module_t* module)
{
    int64_t new_ref_count;
    ebpf_lock_state_t module_lock_state = 0;
    bool lock_acquired = false;

    EBPF_LOG_ENTRY();

    if (!module) {
        EBPF_RETURN_VOID();
    }

    ebpf_assert(module->base.marker == _ebpf_native_marker);

    module_lock_state = ebpf_lock_lock(&module->lock);
    lock_acquired = true;

    new_ref_count = --module->base.reference_count;
    if (new_ref_count < 0) {
        __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }

    if (new_ref_count == 1) {
        // Check if all the program references have been released. If that
        // is the case, explicitly unload the driver, if it is safe to do so.
        if (!module->detaching) {
            // If the module is not yet marked as detaching, and reference
            // count is 1, it means all the program and module references have been
            // released.
            if (module->unload_driver_on_cleanup) {
                EBPF_LOG_MESSAGE_GUID(
                    EBPF_TRACELOG_LEVEL_INFO,
                    EBPF_TRACELOG_KEYWORD_NATIVE,
                    "_ebpf_native_release_reference: all program references released. Unloading module",
                    &module->client_module_id);

                ebpf_assert_success(_ebpf_native_unload(module));
            } else {
                EBPF_LOG_MESSAGE_GUID(
                    EBPF_TRACELOG_LEVEL_INFO,
                    EBPF_TRACELOG_KEYWORD_NATIVE,
                    "_ebpf_native_release_reference: unload_driver_on_cleanup is false. Skip unloading module",
                    &module->client_module_id);
            }
        }
        ebpf_lock_unlock(&module->lock, module_lock_state);
        lock_acquired = false;
    } else if (new_ref_count == 0) {
        ebpf_lock_unlock(&module->lock, module_lock_state);
        lock_acquired = false;

        ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
        // Delete entry from hash table.
        ebpf_assert_success(
            ebpf_hash_table_delete(_ebpf_native_client_table, (const uint8_t*)&module->client_module_id));
        ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);

        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "_ebpf_native_release_reference: ref is 0, complete detach callback",
            &module->client_module_id);

        // All references to the module have been released. Safe to complete the detach callback.
        NmrProviderDetachClientComplete(module->nmr_binding_handle);

        // Clean up the native module.
        _ebpf_native_clean_up_module(module);
    }

    if (lock_acquired) {
        ebpf_lock_unlock(&module->lock, module_lock_state);
    }

    EBPF_RETURN_VOID();
}

void
ebpf_native_release_reference(_In_opt_ _Post_invalid_ ebpf_native_program_t* binding_context)
{
    if (binding_context) {
        ebpf_native_module_t* module = binding_context->module;
        _ebpf_native_release_reference(module);
        _ebpf_native_clean_up_program(binding_context, true);
    }
}

void
ebpf_native_terminate()
{
    EBPF_LOG_ENTRY();

    // ebpf_provider_unload is blocking call until all the
    // native modules have been detached.
    if (_ebpf_native_nmr_provider_handle) {
        NTSTATUS status = NmrDeregisterProvider(_ebpf_native_nmr_provider_handle);
        if (status == STATUS_PENDING) {
            NmrWaitForProviderDeregisterComplete(_ebpf_native_nmr_provider_handle);
        } else {
            ebpf_assert(status == STATUS_SUCCESS);
        }
        _ebpf_native_nmr_provider_handle = NULL;
    }

    // All native modules should be cleaned up by now.
    ebpf_assert(!_ebpf_native_client_table || ebpf_hash_table_key_count(_ebpf_native_client_table) == 0);

    ebpf_hash_table_destroy(_ebpf_native_client_table);
    _ebpf_native_client_table = NULL;
    ebpf_lock_destroy(&_ebpf_native_client_table_lock);

    EBPF_RETURN_VOID();
}

void
ebpf_object_update_reference_history(void* object, bool acquire, uint32_t file_id, uint32_t line);

static void
_ebpf_native_acquire_reference_internal(void* base_object, ebpf_file_id_t file_id, uint32_t line)
{
    ebpf_object_update_reference_history(base_object, true, file_id, line);
    _ebpf_native_acquire_reference(base_object);
}

static void
_ebpf_native_release_reference_internal(void* base_object, ebpf_file_id_t file_id, uint32_t line)
{
    ebpf_object_update_reference_history(base_object, false, file_id, line);
    _ebpf_native_release_reference(base_object);
}

static void
_ebpf_native_map_initial_values_fallback(
    _Outptr_result_buffer_maybenull_(*count) map_initial_values_t** map_initial_values, _Out_ size_t* count)
{
    map_initial_values = NULL;
    *count = 0;
}

static NTSTATUS
_ebpf_native_provider_attach_client_callback(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ void* client_binding_context,
    _In_ const void* client_dispatch,
    _Out_ void** provider_binding_context,
    _Out_ const void** provider_dispatch)
{
    UNREFERENCED_PARAMETER(provider_context);
    UNREFERENCED_PARAMETER(client_binding_context);
    UNREFERENCED_PARAMETER(client_dispatch);

    *provider_dispatch = NULL;
    *provider_binding_context = NULL;

    const GUID* client_module_id = &client_registration_instance->ModuleId->Guid;
    EBPF_LOG_MESSAGE_GUID(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_NATIVE,
        "_ebpf_native_client_attach_callback: Called for",
        client_module_id);
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_lock_state_t state = 0;
    ebpf_native_module_t** module = NULL;
    bool lock_acquired = false;
    metadata_table_t* table = NULL;
    ebpf_native_module_t* client_context = ebpf_allocate_with_tag(sizeof(ebpf_native_module_t), EBPF_POOL_TAG_NATIVE);

    if (!client_context) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }
    table = (metadata_table_t*)client_registration_instance->NpiSpecificCharacteristics;
    if (!table || !table->programs || !table->maps) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // Check if the client module is compatible with the runtime.
    if (table->size < EBPF_OFFSET_OF(metadata_table_t, version)) {
        result = EBPF_INVALID_ARGUMENT;
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "The metadata table size is wrong for client module. The version of bpf2c used to generate this module "
            "may be too old.",
            client_module_id);
        goto Done;
    }

    bpf2c_version_t client_version = {0, 0, 0};
    table->version(&client_version);
    if (_ebpf_compare_versions(&client_version, &_ebpf_minimum_version) < 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // Copy the metadata table.
    memcpy(&client_context->table, table, min(table->size, sizeof(metadata_table_t)));

    // Initialize the map initial values function pointer if it is not present.
    if (!client_context->table.map_initial_values) {
        client_context->table.map_initial_values = _ebpf_native_map_initial_values_fallback;
    }

    ebpf_lock_create(&client_context->lock);
    client_context->base.marker = _ebpf_native_marker;
    client_context->base.acquire_reference = _ebpf_native_acquire_reference_internal;
    client_context->base.release_reference = _ebpf_native_release_reference_internal;
    // Acquire "attach" reference. Released when detach is called for this module.
    client_context->base.reference_count = 1;
    client_context->client_module_id = *client_module_id;
    client_context->state = MODULE_STATE_UNINITIALIZED;
    client_context->nmr_binding_handle = nmr_binding_handle;
    KeInitializeEvent(&client_context->event, NotificationEvent, false);

    // Insert the new client context in the hash table.
    state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
    lock_acquired = true;
    result = ebpf_hash_table_find(_ebpf_native_client_table, (const uint8_t*)client_module_id, (uint8_t**)&module);
    if (result == EBPF_SUCCESS) {
        result = EBPF_OBJECT_ALREADY_EXISTS;
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "_ebpf_native_client_attach_callback: Module already exists",
            client_module_id);
        goto Done;
    }
    result = ebpf_hash_table_update(
        _ebpf_native_client_table,
        (const uint8_t*)client_module_id,
        (const uint8_t*)&client_context,
        EBPF_HASH_TABLE_OPERATION_INSERT);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

Done:
    if (lock_acquired) {
        ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
        lock_acquired = false;
    }
    if (result != EBPF_SUCCESS) {
        ebpf_free(client_context);
    } else {
        *provider_dispatch = NULL;
        *provider_binding_context = client_context;
    }
    EBPF_RETURN_NTSTATUS(ebpf_result_to_ntstatus(result));
}

static NTSTATUS
_ebpf_native_provider_detach_client_callback(_In_ void* provider_binding_context)
{
    ebpf_native_module_t* context = (ebpf_native_module_t*)provider_binding_context;

    EBPF_LOG_MESSAGE_GUID(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_NATIVE,
        "_ebpf_native_client_detach_callback: Called for",
        &context->client_module_id);
    // 1. Find the entry in the hash table using "client_id"
    // 2. Release the "attach" reference on the native module.
    // 3. Return EBPF_PENDING
    ebpf_result_t result = EBPF_PENDING;
    ebpf_native_module_t** existing_module = NULL;
    ebpf_native_module_t* module = NULL;
    ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
    bool lock_acquired = true;
    if (ebpf_hash_table_find(
            _ebpf_native_client_table, (const uint8_t*)&context->client_module_id, (uint8_t**)&existing_module) !=
        EBPF_SUCCESS) {
        result = EBPF_SUCCESS;
        goto Done;
    }
    ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
    lock_acquired = false;
    module = *existing_module;
    state = ebpf_lock_lock(&module->lock);
    ebpf_assert(module->detaching == false);
    module->detaching = true;
    ebpf_lock_unlock(&module->lock, state);
    _ebpf_native_release_reference(module);

Done:
    if (lock_acquired) {
        ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
    }
    EBPF_RETURN_NTSTATUS(ebpf_result_to_ntstatus(result));
}

_Must_inspect_result_ ebpf_result_t
ebpf_native_initiate()
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    bool hash_table_created = false;

    ebpf_lock_create(&_ebpf_native_client_table_lock);

    const ebpf_hash_table_creation_options_t options = {
        .key_size = sizeof(GUID),
        .value_size = sizeof(ebpf_native_module_t*),
        .allocate = ebpf_allocate,
        .free = ebpf_free,
    };

    return_value = ebpf_hash_table_create(&_ebpf_native_client_table, &options);
    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }
    hash_table_created = true;

    NTSTATUS status =
        NmrRegisterProvider(&_ebpf_native_provider_characteristics, NULL, &_ebpf_native_nmr_provider_handle);
    if (!NT_SUCCESS(status)) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

Done:
    if (return_value != EBPF_SUCCESS) {
        if (hash_table_created) {
            ebpf_hash_table_destroy(_ebpf_native_client_table);
            _ebpf_native_client_table = NULL;
        }
        ebpf_lock_destroy(&_ebpf_native_client_table_lock);
    }

    EBPF_RETURN_RESULT(return_value);
}

static ebpf_native_map_t*
_ebpf_native_get_next_map_to_create(_In_reads_(map_count) ebpf_native_map_t* maps, size_t map_count)
{
    for (uint32_t i = 0; i < map_count; i++) {
        ebpf_native_map_t* map = &maps[i];
        if (map->handle != ebpf_handle_invalid) {
            // Already created.
            continue;
        }
        if (!_ebpf_native_is_map_in_map(map)) {
            return map;
        }
        if (map->inner_map == NULL) {
            // This map requires an inner map template, look up which one.
            for (uint32_t j = 0; j < map_count; j++) {
                ebpf_native_map_t* inner_map = &maps[j];
                if (inner_map->original_id == map->inner_map_original_id) {
                    map->inner_map = inner_map;
                    break;
                }
            }
            if (map->inner_map == NULL) {
                // We can't create this map because there is no inner template.
                continue;
            }
        }
        if (map->inner_map->handle == ebpf_handle_invalid) {
            // We need to create the inner map template first.
            continue;
        }

        return map;
    }

    // There are no maps left that we can create.
    return NULL;
}

static ebpf_result_t
_ebpf_native_initialize_maps(
    _In_ const GUID* module_id,
    _Out_writes_(map_count) ebpf_native_map_t* native_maps,
    _Inout_updates_(map_count) map_entry_t* maps,
    size_t map_count)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    const int ORIGINAL_ID_OFFSET = 1;

    // First set all handle value to invalid.
    // This is needed because initializing negative tests can cause initialization
    // of native_maps to fail early, leaving some of the handle values uninitialized.
    for (uint32_t i = 0; i < map_count; i++) {
        native_maps[i].handle = ebpf_handle_invalid;
    }

    for (uint32_t i = 0; i < map_count; i++) {
        if (maps[i].definition.pinning != LIBBPF_PIN_NONE && maps[i].definition.pinning != LIBBPF_PIN_BY_NAME) {
            EBPF_LOG_MESSAGE_UINT64(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_NATIVE,
                "_ebpf_native_initialize_maps: Unsupported pinning type",
                maps[i].definition.pinning);
            result = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        native_maps[i].entry = &maps[i];
        native_maps[i].original_id = i + ORIGINAL_ID_OFFSET;
        // maps[i].address = NULL;

        if (maps[i].definition.pinning == LIBBPF_PIN_BY_NAME) {
            // Construct the pin path.
            size_t prefix_length = strnlen(DEFAULT_PIN_ROOT_PATH, EBPF_MAX_PIN_PATH_LENGTH);
            size_t name_length = strnlen_s(maps[i].name, BPF_OBJ_NAME_LEN);
            if (name_length == 0 || name_length >= BPF_OBJ_NAME_LEN ||
                prefix_length + name_length + 1 >= EBPF_MAX_PIN_PATH_LENGTH) {
                EBPF_LOG_MESSAGE_GUID(
                    EBPF_TRACELOG_LEVEL_ERROR,
                    EBPF_TRACELOG_KEYWORD_NATIVE,
                    "_ebpf_native_initialize_maps: map pin path too long",
                    module_id);
                result = EBPF_INVALID_ARGUMENT;
                goto Done;
            }

            native_maps[i].pin_path.value =
                ebpf_allocate_with_tag(prefix_length + name_length + 1, EBPF_POOL_TAG_NATIVE);
            if (native_maps[i].pin_path.value == NULL) {
                result = EBPF_NO_MEMORY;
                goto Done;
            }
            native_maps[i].pin_path.length = prefix_length + name_length + 1;
            memcpy(native_maps[i].pin_path.value, DEFAULT_PIN_ROOT_PATH, prefix_length);
            memcpy(native_maps[i].pin_path.value + prefix_length, "/", 1);
            memcpy(native_maps[i].pin_path.value + prefix_length + 1, maps[i].name, name_length);
        } else {
            native_maps[i].pin_path.value = NULL;
            native_maps[i].pin_path.length = 0;
        }
    }

    // Populate inner map fd.
    for (uint32_t i = 0; i < map_count; i++) {
        ebpf_map_definition_in_file_t* definition = &(native_maps[i].entry->definition);
        int32_t inner_map_original_id = -1;
        if (_ebpf_native_is_map_in_map(&native_maps[i])) {
            if (definition->inner_map_idx != 0) {
                inner_map_original_id = definition->inner_map_idx + ORIGINAL_ID_OFFSET;
            } else if (definition->inner_id != 0) {
                for (uint32_t j = 0; j < map_count; j++) {
                    ebpf_map_definition_in_file_t* inner_definition = &(native_maps[j].entry->definition);
                    if (inner_definition->id == definition->inner_id && i != j) {
                        inner_map_original_id = j + ORIGINAL_ID_OFFSET;
                        break;
                    }
                }
            }
        }
        native_maps[i].inner_map_original_id = inner_map_original_id;
    }

Done:
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_native_validate_map(_In_ const ebpf_native_map_t* map, ebpf_handle_t original_map_handle)
{
    EBPF_LOG_ENTRY();
    // Validate that the existing map definition matches with this new map.
    struct bpf_map_info info;
    ebpf_core_object_t* object;
    ebpf_handle_t inner_map_handle = ebpf_handle_invalid;
    uint16_t info_size = (uint16_t)sizeof(info);
    ebpf_result_t result = EBPF_OBJECT_REFERENCE_BY_HANDLE(original_map_handle, EBPF_OBJECT_MAP, &object);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    result = ebpf_map_get_info((ebpf_map_t*)object, (uint8_t*)&info, &info_size);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    if (info.type != map->entry->definition.type || info.key_size != map->entry->definition.key_size ||
        info.value_size != map->entry->definition.value_size ||
        info.max_entries != map->entry->definition.max_entries) {
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    // Extra checks for map-in-map.
    if (_ebpf_native_is_map_in_map(map)) {
        ebpf_native_map_t* inner_map = map->inner_map;
        ebpf_assert(inner_map != NULL);
        // Code analysis doesn't understand that inner_map is not NULL if _ebpf_native_is_map_in_map() returns true.
        _Analysis_assume_(inner_map != NULL);

        if (info.inner_map_id == EBPF_ID_NONE) {
            // The original map is pinned but its template is not initialized yet.
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }

        // For map-in-map, validate the inner map template also.
        result = ebpf_core_get_handle_by_id(EBPF_OBJECT_MAP, info.inner_map_id, &inner_map_handle);
        if (result != EBPF_SUCCESS) {
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        }
        result = _ebpf_native_validate_map(inner_map, inner_map_handle);
        ebpf_assert_success(ebpf_handle_close(inner_map_handle));
    }

Exit:
    EBPF_OBJECT_RELEASE_REFERENCE(object);
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_native_reuse_map(_Inout_ ebpf_native_map_t* map)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_handle_t handle = ebpf_handle_invalid;
    // Check if a map is already present with this pin path.
    result = ebpf_core_get_pinned_object(&map->pin_path, &handle);
    if (result != EBPF_SUCCESS) {
        // Treat EBPF_KEY_NOT_FOUND as success.
        if (result == EBPF_KEY_NOT_FOUND) {
            ebpf_assert(handle == ebpf_handle_invalid);
            result = EBPF_SUCCESS;
        }
        goto Exit;
    }

    // Recursively validate that the map definition matches with the existing
    // map.
    result = _ebpf_native_validate_map(map, handle);
    if (result != EBPF_SUCCESS) {
        goto Exit;
    }

    // The map can be reused. Populate map handle.
    map->handle = handle;
    map->reused = true;
    map->pinned = true;

Exit:
    if (result != EBPF_SUCCESS) {
        ebpf_assert_success(ebpf_handle_close(handle));
    }
    EBPF_RETURN_RESULT(result);
}

/**
 * @brief Find the map with the given name in the module.
 *
 * @param[in] module Module to search.
 * @param[in] name Map name to search for.
 * @return Pointer to the map if found, NULL otherwise.
 */
static ebpf_native_map_t*
_ebpf_native_find_map_by_name(_In_ const ebpf_native_module_instance_t* instance, _In_ const char* name)
{
    ebpf_native_map_t* map = NULL;
    for (uint32_t i = 0; i < instance->map_count; i++) {
        if (strcmp(instance->maps[i].entry->name, name) == 0) {
            map = &instance->maps[i];
            break;
        }
    }
    return map;
}

static ebpf_native_program_t*
_ebpf_native_find_program_by_name(_In_ const ebpf_native_module_instance_t* instance, _In_ const char* name)
{
    ebpf_native_program_t* program = NULL;
    for (uint32_t i = 0; i < instance->program_count; i++) {
        if (strcmp(instance->programs[i]->entry->program_name, name) == 0) {
            program = instance->programs[i];
            break;
        }
    }
    return program;
}

static ebpf_result_t
_ebpf_native_set_initial_map_values(_Inout_ ebpf_native_module_instance_t* instance)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    map_initial_values_t* map_initial_values = NULL;
    size_t map_initial_values_count = 0;

    // Get initial value for maps.
    instance->module->table.map_initial_values(&map_initial_values, &map_initial_values_count);

    // For each map, update the initial values.
    for (size_t i = 0; i < map_initial_values_count; i++) {
        ebpf_native_map_t* native_map_to_update = _ebpf_native_find_map_by_name(instance, map_initial_values[i].name);
        if (native_map_to_update == NULL) {
            result = EBPF_INVALID_ARGUMENT;
            break;
        }

        if (native_map_to_update->reused) {
            // Map is reused. Skip updating initial values.
            continue;
        }

        // For each value in the map, find the map or program to insert.
        for (size_t j = 0; j < map_initial_values[i].count; j++) {
            // Skip empty initial values.
            if (!map_initial_values[i].values[j]) {
                continue;
            }

            ebpf_handle_t handle_to_insert = ebpf_handle_invalid;

            if (_ebpf_native_is_map_in_map(native_map_to_update)) {
                ebpf_native_map_t* native_map_to_insert =
                    _ebpf_native_find_map_by_name(instance, map_initial_values[i].values[j]);
                if (native_map_to_update == NULL) {
                    result = EBPF_INVALID_ARGUMENT;
                    break;
                }
                handle_to_insert = native_map_to_insert->handle;
            } else if (native_map_to_update->entry->definition.type == BPF_MAP_TYPE_PROG_ARRAY) {
                ebpf_native_program_t* program_to_insert =
                    _ebpf_native_find_program_by_name(instance, map_initial_values[i].values[j]);
                if (program_to_insert == NULL) {
                    result = EBPF_INVALID_ARGUMENT;
                    break;
                }
                handle_to_insert = program_to_insert->handle;
            } else {
                result = EBPF_INVALID_ARGUMENT;
                break;
            }

            uint32_t key = (uint32_t)j;
            result = ebpf_core_update_map_with_handle(
                native_map_to_update->handle,
                (uint8_t*)&key,
                native_map_to_update->entry->definition.key_size,
                handle_to_insert);
            if (result != EBPF_SUCCESS) {
                break;
            }
        }
        if (result != EBPF_SUCCESS) {
            break;
        }
    }

    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_native_create_maps(_Inout_ ebpf_native_module_instance_t* instance)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_native_map_t* native_maps = NULL;
    map_entry_t* maps = NULL;
    size_t map_count = 0;
    cxplat_utf8_string_t map_name = {0};
    ebpf_map_definition_in_memory_t map_definition = {0};
    const ebpf_native_module_t* module = instance->module;

    // Get the maps
    module->table.maps(&maps, &map_count);
    if (map_count == 0) {
        EBPF_RETURN_RESULT(EBPF_SUCCESS);
    }

    instance->maps =
        (ebpf_native_map_t*)ebpf_allocate_with_tag(map_count * sizeof(ebpf_native_map_t), EBPF_POOL_TAG_NATIVE);
    if (instance->maps == NULL) {
        EBPF_RETURN_RESULT(EBPF_NO_MEMORY);
    }

    instance->map_count = map_count;
    native_maps = instance->maps;

    result = _ebpf_native_initialize_maps(&module->client_module_id, native_maps, maps, map_count);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    for (uint32_t count = 0; count < map_count; count++) {
        ebpf_native_map_t* native_map = _ebpf_native_get_next_map_to_create(native_maps, map_count);
        if (native_map == NULL) {
            // Any remaining maps cannot be created.
            result = EBPF_INVALID_OBJECT;
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_NATIVE,
                "_ebpf_native_create_maps: Invalid map objects in module",
                &module->client_module_id);
            break;
        }

        if (native_map->entry->definition.pinning == LIBBPF_PIN_BY_NAME) {
            result = _ebpf_native_reuse_map(native_map);
            if (result != EBPF_SUCCESS) {
                break;
            }
            if (native_map->reused) {
                continue;
            }
        }

        ebpf_handle_t inner_map_handle = (native_map->inner_map) ? native_map->inner_map->handle : ebpf_handle_invalid;
        map_name.length = strlen(native_map->entry->name);
        map_name.value = (uint8_t*)ebpf_allocate_with_tag(map_name.length, EBPF_POOL_TAG_NATIVE);
        if (map_name.value == NULL) {
            result = EBPF_NO_MEMORY;
            break;
        }
        memcpy(map_name.value, native_map->entry->name, map_name.length);
        map_definition.type = native_map->entry->definition.type;
        map_definition.key_size = native_map->entry->definition.key_size;
        map_definition.value_size = native_map->entry->definition.value_size;
        map_definition.max_entries = native_map->entry->definition.max_entries;

        result = ebpf_core_create_map(&map_name, &map_definition, inner_map_handle, &native_map->handle);
        if (result != EBPF_SUCCESS) {
            break;
        }

        ebpf_free(map_name.value);
        map_name.value = NULL;

        // If pin_path is set and the map is not yet pinned, pin it now.
        if (native_map->pin_path.value != NULL && !native_map->pinned) {
            result = ebpf_core_update_pinning(native_map->handle, &native_map->pin_path);
            if (result != EBPF_SUCCESS) {
                break;
            }
            native_map->pinned = true;
        }
    }

Done:
    if (result != EBPF_SUCCESS) {
        // Copy the handles in the cleanup context.
        for (size_t i = 0; i < instance->map_count; i++) {
            instance->handle_cleanup_context.handle_information->map_handles[i] = instance->maps[i].handle;
        }
        _ebpf_native_clean_up_maps(instance->maps, instance->map_count, true, false);
        instance->maps = NULL;
        instance->map_count = 0;
    }
    if (map_name.value != NULL) {
        ebpf_free(map_name.value);
    }

    EBPF_RETURN_RESULT(result);
}

// static void
// _ebpf_native_initialize_programs(
//     _Out_writes_(program_count) ebpf_native_program_t** native_programs,
//     _In_reads_(program_count) program_entry_t* programs,
//     size_t program_count)
// {
//     for (uint32_t i = 0; i < program_count; i++) {
//         native_programs[i]->entry = &programs[i];
//         native_programs[i]->handle = ebpf_handle_invalid;
//     }
// }

static ebpf_result_t
_ebpf_native_resolve_maps_for_program(_In_ ebpf_native_module_instance_t* instance, _In_ ebpf_native_program_t* program)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    ebpf_handle_t* map_handles = NULL;
    uintptr_t* map_addresses = NULL;
    // uintptr_t* local_map_addresses = NULL;
    uint16_t* map_indices = program->entry->referenced_map_indices;
    uint16_t map_count = program->entry->referenced_map_count;
    ebpf_native_map_t* native_maps = instance->maps;

    if (map_count == 0) {
        // No maps associated with this program.
        EBPF_RETURN_RESULT(EBPF_SUCCESS);
    }

    // Validate all map indices are within range.
    for (uint32_t i = 0; i < map_count; i++) {
        if (map_indices[i] >= instance->map_count) {
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_NATIVE,
                "_ebpf_native_resolve_maps_for_program: map indices not within range",
                &instance->module->client_module_id);
            EBPF_RETURN_RESULT(EBPF_INVALID_ARGUMENT);
        }
    }

    map_handles = ebpf_allocate_with_tag(map_count * sizeof(ebpf_handle_t), EBPF_POOL_TAG_NATIVE);
    if (map_handles == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    map_addresses = ebpf_allocate_with_tag(map_count * sizeof(uintptr_t), EBPF_POOL_TAG_NATIVE);
    if (map_addresses == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    // Iterate over the map indices to get all the handles.
    for (uint16_t i = 0; i < map_count; i++) {
        map_handles[i] = native_maps[map_indices[i]].handle;
    }

    result = ebpf_core_resolve_maps(program->handle, map_count, map_handles, map_addresses);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    // Update the addresses in the map entries.
    for (uint16_t i = 0; i < map_count; i++) {
        program->runtime_context.map_data[map_indices[i]].address = map_addresses[i];
    }

Done:
    ebpf_free(map_handles);
    ebpf_free(map_addresses);
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_native_resolve_helpers_for_program(
    _In_ const ebpf_native_module_t* module, _In_ const ebpf_native_program_t* program)
{
    EBPF_LOG_ENTRY();
    UNREFERENCED_PARAMETER(module);
    ebpf_result_t result;
    uint32_t* helper_ids = NULL;
    helper_function_address* helper_addresses = NULL;
    uint16_t helper_count = program->entry->helper_count;
    helper_function_entry_t* helper_info = program->entry->helpers;
    helper_function_data_t* helper_data = program->runtime_context.helper_data;

    if (helper_count > 0) {
        helper_ids = ebpf_allocate_with_tag(helper_count * sizeof(uint32_t), EBPF_POOL_TAG_NATIVE);
        if (helper_ids == NULL) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }

        helper_addresses = ebpf_allocate_with_tag(helper_count * sizeof(helper_function_address), EBPF_POOL_TAG_NATIVE);
        if (helper_addresses == NULL) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }

        // Iterate over the helper indices to get all the helper ids.
        for (uint16_t i = 0; i < helper_count; i++) {
            helper_ids[i] = helper_info[i].helper_id;
        }
    }

    result = ebpf_core_resolve_helper(program->handle, helper_count, helper_ids, (uint64_t*)helper_addresses);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_core_resolve_helper failed",
            &module->client_module_id);
        goto Done;
    }

    // Update the addresses in the helper entries.
    for (uint16_t i = 0; i < helper_count; i++) {
        helper_data[i].address = helper_addresses[i];
    }

Done:
    ebpf_free(helper_ids);
    ebpf_free(helper_addresses);
    EBPF_RETURN_RESULT(result);
}

static void
_ebpf_native_initialize_helpers_for_program(_Inout_ ebpf_native_program_t* program)
{
    size_t helper_count = program->entry->helper_count;
    helper_function_entry_t* helpers = program->entry->helpers;
    // Initialize the helper entries.
    for (size_t i = 0; i < helper_count; i++) {
        if (helpers[i].helper_id == BPF_FUNC_tail_call) {
            program->runtime_context.helper_data[i].tail_call = true;
        }
    }
}

static ebpf_result_t
_ebpf_native_load_programs(_Inout_ ebpf_native_module_instance_t* instance)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_native_program_t** native_programs = NULL;
    program_entry_t* programs = NULL;
    size_t program_count = 0;
    size_t program_name_length = 0;
    size_t section_name_length = 0;
    size_t hash_type_length = 0;
    uint8_t* program_name = NULL;
    uint8_t* section_name = NULL;
    uint8_t* hash_type_name = NULL;
    ebpf_native_module_t* module = instance->module;

    // Get the programs.
    module->table.programs(&programs, &program_count);
    if (program_count == 0 || programs == NULL) {
        return EBPF_INVALID_OBJECT;
    }

    instance->programs = (ebpf_native_program_t**)ebpf_allocate_with_tag(
        program_count * sizeof(ebpf_native_program_t*), EBPF_POOL_TAG_NATIVE);
    if (instance->programs == NULL) {
        return EBPF_NO_MEMORY;
    }
    for (size_t i = 0; i < program_count; i++) {
        instance->programs[i] =
            (ebpf_native_program_t*)ebpf_allocate_with_tag(sizeof(ebpf_native_program_t), EBPF_POOL_TAG_NATIVE);
        if (instance->programs[i] == NULL) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }
    }
    instance->program_count = program_count;
    native_programs = instance->programs;

    // _ebpf_native_initialize_programs(native_programs, programs, program_count);
    for (uint32_t i = 0; i < program_count; i++) {
        native_programs[i]->entry = &programs[i];
        native_programs[i]->handle = ebpf_handle_invalid;
    }

    for (uint32_t count = 0; count < program_count; count++) {
        ebpf_native_program_t* native_program = native_programs[count];
        program_entry_t* program = native_program->entry;
        ebpf_program_parameters_t parameters = {0};
        size_t helper_count = program->helper_count;
        size_t helper_data_size = 0;
        size_t map_data_size = 0;

        // Initialize runtime context for the program.
        if (helper_count > 0) {
            result = ebpf_safe_size_t_multiply(sizeof(helper_function_data_t), helper_count, &helper_data_size);
            if (result != EBPF_SUCCESS) {
                EBPF_LOG_MESSAGE_GUID(
                    EBPF_TRACELOG_LEVEL_ERROR,
                    EBPF_TRACELOG_KEYWORD_NATIVE,
                    "_ebpf_native_load_programs: helper_data size overflow",
                    &module->client_module_id);
                goto Done;
            }

            native_program->runtime_context.helper_data =
                ebpf_allocate_with_tag(helper_data_size, EBPF_POOL_TAG_NATIVE);
            if (native_program->runtime_context.helper_data == NULL) {
                result = EBPF_NO_MEMORY;
                goto Done;
            }
        }

        if (instance->map_count > 0) {
            result = ebpf_safe_size_t_multiply(sizeof(map_data_t), instance->map_count, &map_data_size);
            if (result != EBPF_SUCCESS) {
                EBPF_LOG_MESSAGE_GUID(
                    EBPF_TRACELOG_LEVEL_ERROR,
                    EBPF_TRACELOG_KEYWORD_NATIVE,
                    "_ebpf_native_load_programs: map_data size overflow",
                    &module->client_module_id);
                goto Done;
            }

            native_program->runtime_context.map_data = ebpf_allocate_with_tag(map_data_size, EBPF_POOL_TAG_NATIVE);
            if (native_program->runtime_context.map_data == NULL) {
                result = EBPF_NO_MEMORY;
                goto Done;
            }
        }

        _ebpf_native_initialize_helpers_for_program(native_program);

        program_name_length = strnlen_s(program->program_name, BPF_OBJ_NAME_LEN);
        section_name_length = strnlen_s(program->section_name, BPF_OBJ_NAME_LEN);
        hash_type_length = strnlen_s(program->program_info_hash_type, BPF_OBJ_NAME_LEN);

        if (program_name_length == 0 || program_name_length >= BPF_OBJ_NAME_LEN || section_name_length == 0 ||
            section_name_length >= BPF_OBJ_NAME_LEN || hash_type_length == 0 || hash_type_length >= BPF_OBJ_NAME_LEN) {
            result = EBPF_INVALID_ARGUMENT;
            goto Done;
        }

        program_name = ebpf_allocate_with_tag(program_name_length, EBPF_POOL_TAG_NATIVE);
        if (program_name == NULL) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }
        section_name = ebpf_allocate_with_tag(section_name_length, EBPF_POOL_TAG_NATIVE);
        if (section_name == NULL) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }

        parameters.program_type = *program->program_type;
        parameters.expected_attach_type = (program->expected_attach_type ? *program->expected_attach_type : GUID_NULL);

        memcpy(program_name, program->program_name, program_name_length);
        parameters.program_name.value = program_name;
        parameters.program_name.length = program_name_length;

        memcpy(section_name, program->section_name, section_name_length);
        parameters.section_name.value = section_name;
        parameters.section_name.length = section_name_length;

        parameters.file_name.value = NULL;
        parameters.file_name.length = 0;

        parameters.program_info_hash = program->program_info_hash;
        parameters.program_info_hash_length = program->program_info_hash_length;

        hash_type_name = ebpf_allocate_with_tag(hash_type_length, EBPF_POOL_TAG_NATIVE);
        if (hash_type_name == NULL) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }
        memcpy(hash_type_name, program->program_info_hash_type, hash_type_length);
        parameters.program_info_hash_type.value = hash_type_name;
        parameters.program_info_hash_type.length = hash_type_length;

        result = ebpf_program_create_and_initialize(&parameters, &native_program->handle);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }

        ebpf_free(program_name);
        ebpf_free(section_name);
        ebpf_free(hash_type_name);
        program_name = NULL;
        section_name = NULL;
        hash_type_name = NULL;

        // Resolve and associate maps with the program.
        result = _ebpf_native_resolve_maps_for_program(instance, native_program);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }

        ebpf_native_helper_address_changed_context_t* context = NULL;

        context = (ebpf_native_helper_address_changed_context_t*)ebpf_allocate(
            sizeof(ebpf_native_helper_address_changed_context_t));

        if (context == NULL) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }

        context->module = module;
        context->native_program = native_program;

        ebpf_program_t* program_object = NULL;
        result = EBPF_OBJECT_REFERENCE_BY_HANDLE(
            native_program->handle, EBPF_OBJECT_PROGRAM, (ebpf_core_object_t**)&program_object);
        if (result != EBPF_SUCCESS) {
            ebpf_free(context);
            goto Done;
        }

        result = ebpf_program_register_for_helper_changes(program_object, _ebpf_native_helper_address_changed, context);

        EBPF_OBJECT_RELEASE_REFERENCE((ebpf_core_object_t*)program_object);

        if (result != EBPF_SUCCESS) {
            ebpf_free(context);
            goto Done;
        }

        native_program->addresses_changed_callback_context = context;

        // Resolve helper addresses.
        result = _ebpf_native_resolve_helpers_for_program(module, native_program);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }

        // Load machine code.
        ebpf_core_code_context_t code_context = {0};
        code_context.native_code_context.runtime_context = &native_program->runtime_context;
        code_context.native_code_context.native_module_context = native_program;
        native_program->module = module;

        result = ebpf_core_load_code(
            native_program->handle, EBPF_CODE_NATIVE, &code_context, (uint8_t*)native_program->entry->function, 0);
        if (result != EBPF_SUCCESS) {
            goto Done;
        }
    }

Done:
    if (result != EBPF_SUCCESS) {
        // Copy the handles in the cleanup context.
        for (size_t i = 0; i < instance->program_count; i++) {
            instance->handle_cleanup_context.handle_information->program_handles[i] = instance->programs[i]->handle;
        }
        _ebpf_native_clean_up_programs(instance->programs, instance->program_count, false);
        instance->programs = NULL;
        instance->program_count = 0;
    }

    ebpf_free(program_name);
    ebpf_free(section_name);
    ebpf_free(hash_type_name);
    return result;
}

size_t
_ebpf_native_get_count_of_maps(_In_ const ebpf_native_module_t* module)
{
    map_entry_t* maps = NULL;
    size_t count_of_maps;
    module->table.maps(&maps, &count_of_maps);

    return count_of_maps;
}

size_t
_ebpf_native_get_count_of_programs(_In_ const ebpf_native_module_t* module)
{
    program_entry_t* programs = NULL;
    size_t count_of_programs;
    module->table.programs(&programs, &count_of_programs);

    return count_of_programs;
}

/**
 * @brief close all handles associated with a given module.
 * @param[in] context The module to free handles on.
 */
static void
_ebpf_native_close_handles_work_item(
    _In_ cxplat_preemptible_work_item_t* work_item, _In_ ebpf_native_handle_cleanup_info_t* handle_info)
{
    // NOTE: This work item does not need epoch protection as we end up calling into the OS to close a handle, which in
    // turn calls back into the ebpfcore driver and that path _is_ epoch protected.

    // Attach process to this worker thread.
    ebpf_platform_attach_process(handle_info->process_handle, handle_info->process_state);

    for (uint32_t i = 0; i < handle_info->count_of_program_handles; i++) {
        if (handle_info->program_handles[i] != ebpf_handle_invalid) {
            (void)ebpf_handle_close(handle_info->program_handles[i]);
            handle_info->program_handles[i] = ebpf_handle_invalid;
        }
    }
    for (uint32_t i = 0; i < handle_info->count_of_map_handles; i++) {
        if (handle_info->map_handles[i] != ebpf_handle_invalid) {
            (void)ebpf_handle_close(handle_info->map_handles[i]);
            handle_info->map_handles[i] = ebpf_handle_invalid;
        }
    }

    // Detach process from this worker thread.
    ebpf_platform_detach_process(handle_info->process_state);

    // Release the reference on the process object.
    ebpf_platform_dereference_process(handle_info->process_handle);

    ebpf_free(handle_info->process_state);
    ebpf_free(handle_info->program_handles);
    ebpf_free(handle_info->map_handles);
    ebpf_free(handle_info);
    cxplat_free_preemptible_work_item(work_item);
}

/**
 * @brief Clean up all handle information for a given module.
 * @param[in,out] module The module to clean up handles for.
 */
static void
_ebpf_native_clean_up_handle_cleanup_context(_Inout_ ebpf_native_handle_cleanup_context_t* cleanup_context)
{
    if (cleanup_context->handle_information != NULL) {
        ebpf_free(cleanup_context->handle_information->map_handles);
        ebpf_free(cleanup_context->handle_information->program_handles);
        ebpf_free(cleanup_context->handle_information->process_state);

        if (cleanup_context->handle_information->process_handle != 0) {
            ebpf_platform_dereference_process(cleanup_context->handle_information->process_handle);
        }
    }

    if (cleanup_context->handle_cleanup_work_item != NULL) {
        cxplat_free_preemptible_work_item(cleanup_context->handle_cleanup_work_item);
        cleanup_context->handle_cleanup_work_item = NULL;
    }
    ebpf_free(cleanup_context->handle_information);
    cleanup_context->handle_information = NULL;
}

static ebpf_result_t
_ebpf_native_initialize_handle_cleanup_context(
    size_t program_handle_count, size_t map_handle_count, _Inout_ ebpf_native_handle_cleanup_context_t* cleanup_context)
{
    ebpf_result_t result = EBPF_SUCCESS;

    memset(cleanup_context, 0, sizeof(ebpf_native_handle_cleanup_context_t));

    cleanup_context->handle_information =
        (ebpf_native_handle_cleanup_info_t*)ebpf_allocate(sizeof(ebpf_native_handle_cleanup_info_t));
    if (cleanup_context->handle_information == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    if (map_handle_count > 0) {
        cleanup_context->handle_information->map_handles =
            (ebpf_handle_t*)ebpf_allocate(sizeof(ebpf_handle_t) * map_handle_count);
        if (cleanup_context->handle_information->map_handles == NULL) {
            result = EBPF_NO_MEMORY;
            goto Done;
        }
    }
    cleanup_context->handle_information->count_of_map_handles = map_handle_count;

    cleanup_context->handle_information->program_handles =
        (ebpf_handle_t*)ebpf_allocate(sizeof(ebpf_handle_t) * program_handle_count);
    if (cleanup_context->handle_information->program_handles == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }
    cleanup_context->handle_information->count_of_program_handles = program_handle_count;

    for (size_t i = 0; i < map_handle_count; i++) {
        cleanup_context->handle_information->map_handles[i] = ebpf_handle_invalid;
    }
    for (size_t i = 0; i < program_handle_count; i++) {
        cleanup_context->handle_information->program_handles[i] = ebpf_handle_invalid;
    }

    cleanup_context->handle_information->process_state = ebpf_allocate_process_state();
    if (cleanup_context->handle_information->process_state == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    result = ebpf_allocate_preemptible_work_item(
        &cleanup_context->handle_cleanup_work_item,
        (cxplat_work_item_routine_t)_ebpf_native_close_handles_work_item,
        cleanup_context->handle_information);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    cleanup_context->handle_information->process_handle = ebpf_platform_reference_process();

Done:
    if (result != EBPF_SUCCESS) {
        _ebpf_native_clean_up_handle_cleanup_context(cleanup_context);
    }
    return result;
}

static ebpf_result_t
_get_native_module_from_hash_table(_In_ const GUID* module_id, _Outptr_ ebpf_native_module_t** module)
{
    ebpf_result_t result;
    ebpf_lock_state_t hash_table_state = 0;
    ebpf_lock_state_t module_state = 0;
    ebpf_native_module_t** existing_module = NULL;
    *module = NULL;

    // Find the native entry in hash table.
    hash_table_state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
    result = ebpf_hash_table_find(_ebpf_native_client_table, (const uint8_t*)module_id, (uint8_t**)&existing_module);
    if (result != EBPF_SUCCESS) {
        result = EBPF_OBJECT_NOT_FOUND;
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "_get_native_module_from_hash_table: module not found",
            module_id);
        goto Done;
    }

    // The module is deleted from the hash table when the reference count becomes 0. A tiny race condition is possible
    // where one thread has released a reference on the module that made the reference count to be 0, and is about to
    // delete the module from hash table, and clean it up. Another thread at the same time is trying to find the module
    // in the hash table. To handle this, check the reference count of the module. If it is 0, return
    // EBPF_OBJECT_NOT_FOUND. If the reference count is not 0, acquire a reference on the module.
    module_state = ebpf_lock_lock(&(*existing_module)->lock);
    if ((*existing_module)->base.reference_count == 0) {
        result = EBPF_OBJECT_NOT_FOUND;
        ebpf_lock_unlock(&(*existing_module)->lock, module_state);
        goto Done;
    }
    _ebpf_native_acquire_reference_under_lock(*existing_module);
    ebpf_lock_unlock(&(*existing_module)->lock, module_state);
    *module = *existing_module;

Done:
    ebpf_lock_unlock(&_ebpf_native_client_table_lock, hash_table_state);
    return result;
}

_Must_inspect_result_ ebpf_result_t
ebpf_native_load(
    _In_reads_(service_name_length) const wchar_t* service_name,
    uint16_t service_name_length,
    _In_ const GUID* module_id,
    bool unload_driver_on_cleanup,
    _Out_ ebpf_handle_t* module_handle,
    _Out_ size_t* count_of_maps,
    _Out_ size_t* count_of_programs)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    // ebpf_lock_state_t hash_table_state = 0;
    ebpf_lock_state_t state = 0;
    ebpf_native_module_t* module = NULL;
    // ebpf_native_module_t** existing_module = NULL;
    wchar_t* local_service_name = NULL;
    ebpf_handle_t local_module_handle = ebpf_handle_invalid;
    cxplat_preemptible_work_item_t* cleanup_work_item = NULL;
    bool load_driver = false;
    bool wait_for_initialization = false;

    local_service_name = ebpf_allocate_with_tag((size_t)service_name_length + 2, EBPF_POOL_TAG_NATIVE);
    if (local_service_name == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }
    memcpy(local_service_name, (uint8_t*)service_name, service_name_length);

    // Initial attempt to find the native entry in hash table, in case the driver is already loaded.
    result = _get_native_module_from_hash_table(module_id, &module);
    if (result != EBPF_SUCCESS) {
        load_driver = true;
    }

    if (load_driver) {
        ebpf_result_t native_load_result = ebpf_native_load_driver(local_service_name);
        if (native_load_result != EBPF_SUCCESS) {
            EBPF_LOG_MESSAGE_WSTRING(
                EBPF_TRACELOG_LEVEL_WARNING,
                EBPF_TRACELOG_KEYWORD_NATIVE,
                "ebpf_native_load_driver failed",
                local_service_name);
        }

        // Find the native entry in hash table again. It should be present this time.
        result = _get_native_module_from_hash_table(module_id, &module);
        if (result != EBPF_SUCCESS) {
            result = EBPF_OBJECT_NOT_FOUND;
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_NATIVE,
                "ebpf_native_load: module not found",
                module_id);
            goto Done;
        }
    }

    result = ebpf_allocate_preemptible_work_item(
        &cleanup_work_item, (cxplat_work_item_routine_t)_ebpf_native_unload_work_item, local_service_name);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    state = ebpf_lock_lock(&module->lock);

    // If the module is unloading or detaching, return EBPF_TRY_AGAIN so that the
    // caller can try after sometime once the module is unloaded.
    if (module->detaching || module->state == MODULE_STATE_UNLOADING) {
        // This client is detaching / unloading.
        result = EBPF_TRY_AGAIN;
        ebpf_lock_unlock(&module->lock, state);
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_native_load: module is detaching / unloading",
            module_id);
        goto Done;
    } else if (module->state != MODULE_STATE_UNINITIALIZED) {
        // This client has already been initialized or is being initialized.
        // Wait till the module is initialized.
        // ebpf_lock_unlock(&module->lock, state);
        wait_for_initialization = true;
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_native_load: module initializing or already initialized",
            module_id);
    } else {
        // Mark the module as initializing.
        module->state = MODULE_STATE_INITIALIZING;
    }
    ebpf_lock_unlock(&module->lock, state);

    // Create handle to the native module.
    result = ebpf_handle_create(&local_module_handle, (ebpf_base_object_t*)module);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_native_load: Failed to create handle.",
            module_id);

        goto Done;
    }

    if (!wait_for_initialization) {
        state = ebpf_lock_lock(&module->lock);
        module->state = MODULE_STATE_INITIALIZED;
        module->service_name = local_service_name;
        module->cleanup_work_item = cleanup_work_item;
        module->unload_driver_on_cleanup = unload_driver_on_cleanup;

        cleanup_work_item = NULL;
        local_service_name = NULL;

        ebpf_lock_unlock(&module->lock, state);

        // Notify other threads.
        KeSetEvent(&module->event, 0, false);
    } else {
        // Wait for other thread to complete the initialization.
        KeWaitForSingleObject(&module->event, Executive, KernelMode, false, NULL);

        // Grab lock and check the current module state.
        state = ebpf_lock_lock(&module->lock);
        if (module->state != MODULE_STATE_INITIALIZED) {
            result = EBPF_TRY_AGAIN;
            ebpf_lock_unlock(&module->lock, state);
            goto Done;
        }
        // If the user mode has send a request to unload the driver, set the flag.
        if (unload_driver_on_cleanup) {
            module->unload_driver_on_cleanup = true;
        }
        ebpf_lock_unlock(&module->lock, state);
    }

    // Get map and program count;
    *count_of_maps = _ebpf_native_get_count_of_maps(module);
    *count_of_programs = _ebpf_native_get_count_of_programs(module);
    *module_handle = local_module_handle;
    local_module_handle = ebpf_handle_invalid;

Done:
    if (result != EBPF_SUCCESS) {
        if (module && !wait_for_initialization) {
            // If this is the thread doing the initialization, reverse the module state,
            // and notify any other threads waiting for the initialization.
            state = ebpf_lock_lock(&module->lock);
            module->state = MODULE_STATE_UNINITIALIZED;
            KeSetEvent(&module->event, 0, false);
            KeClearEvent(&module->event);
            ebpf_lock_unlock(&module->lock, state);
        }
    }
    if (result != EBPF_SUCCESS || wait_for_initialization) {
        cxplat_free_preemptible_work_item(cleanup_work_item);
        ebpf_free(local_service_name);
    }
    if (local_module_handle != ebpf_handle_invalid) {
        ebpf_assert_success(ebpf_handle_close(local_module_handle));
    }
    if (module) {
        _ebpf_native_release_reference(module);
    }

    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_native_load_programs(
    _In_ const GUID* module_id,
    _In_ const GUID* instance_id,
    size_t count_of_map_handles,
    _Out_writes_opt_(count_of_map_handles) ebpf_handle_t* map_handles,
    size_t count_of_program_handles,
    _Out_writes_(count_of_program_handles) ebpf_handle_t* program_handles)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    ebpf_lock_state_t state = 0;
    ebpf_lock_state_t module_state = 0;
    bool lock_acquired = false;
    bool native_lock_acquired = false;
    ebpf_native_module_t** existing_module = NULL;
    ebpf_native_module_t* module = NULL;
    wchar_t* local_service_name = NULL;
    bool module_referenced = false;
    bool maps_created = false;
    bool programs_created = false;
    bool cleanup_context_created = false;
    ebpf_native_module_instance_t instance = {0};
    // ebpf_native_map_t* native_maps = NULL;
    // size_t map_count = 0;

    if ((count_of_map_handles > 0 && map_handles == NULL) ||
        (count_of_program_handles > 0 && program_handles == NULL)) {
        return EBPF_INVALID_ARGUMENT;
    }

    // Find the native entry in hash table.
    state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
    lock_acquired = true;
    result = ebpf_hash_table_find(_ebpf_native_client_table, (const uint8_t*)module_id, (uint8_t**)&existing_module);
    if (result != EBPF_SUCCESS) {
        result = EBPF_OBJECT_NOT_FOUND;
        EBPF_LOG_MESSAGE_GUID_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_native_load_programs: module not found",
            module_id,
            instance_id);
        goto Done;
    }
    module = *existing_module;
    instance.module = module;
    module_state = ebpf_lock_lock(&module->lock);
    native_lock_acquired = true;

    // Check if the module has reference count > 0.
    if (module->base.reference_count == 0) {
        result = EBPF_OBJECT_NOT_FOUND;
        EBPF_LOG_MESSAGE_GUID_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_native_load_programs: module reference is already 0.",
            module_id,
            instance_id);
        goto Done;
    }

    if (module->state != MODULE_STATE_INITIALIZED || module->detaching) {

        if (module->detaching || module->state == MODULE_STATE_UNLOADING) {
            // This client is detaching / unloading.
            result = EBPF_EXTENSION_FAILED_TO_LOAD;
            EBPF_LOG_MESSAGE_GUID_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_NATIVE,
                "ebpf_native_load_programs: module already detaching / unloading",
                module_id,
                instance_id);
        } else {
            // This client has already been loaded.
            result = EBPF_OBJECT_ALREADY_EXISTS;
            EBPF_LOG_MESSAGE_GUID_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_NATIVE,
                "ebpf_native_load_programs: programs already loaded / loading",
                module_id,
                instance_id);
        }
        goto Done;
    }

    // module->state = MODULE_STATE_LOADING;

    // Take a reference on the native module before releasing the lock.
    // This will ensure the driver cannot unload while we are processing this request.
    _ebpf_native_acquire_reference_under_lock(module);
    module_referenced = true;

    ebpf_lock_unlock(&module->lock, module_state);
    native_lock_acquired = false;

    // Release hash table lock.
    ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
    lock_acquired = false;

    // Create handle cleanup context and work item. This is used to close the handles in a work item in case of failure.
    result = _ebpf_native_initialize_handle_cleanup_context(
        count_of_program_handles, count_of_map_handles, &instance.handle_cleanup_context);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID_GUID(
            EBPF_TRACELOG_LEVEL_VERBOSE,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_native_load_programs: _ebpf_native_initialize_handle_cleanup_context failed",
            module_id,
            instance_id);
        goto Done;
    }
    cleanup_context_created = true;

    // Create maps.
    result = _ebpf_native_create_maps(&instance);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID_GUID(
            EBPF_TRACELOG_LEVEL_VERBOSE,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_native_load_programs: map creation failed",
            module_id,
            instance_id);
        goto Done;
    }
    maps_created = true;

    // Create programs.
    result = _ebpf_native_load_programs(&instance);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID_GUID(
            EBPF_TRACELOG_LEVEL_VERBOSE,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_native_load_programs: program load failed",
            module_id,
            instance_id);
        goto Done;
    }
    programs_created = true;

    // Set initial map values.
    result = _ebpf_native_set_initial_map_values(&instance);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID_GUID(
            EBPF_TRACELOG_LEVEL_VERBOSE,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_native_load_programs: set initial map values failed",
            module_id,
            instance_id);
        goto Done;
    }

    // module_state = ebpf_lock_lock(&module->lock);
    // native_lock_acquired = true;

    // module->state = MODULE_STATE_LOADED;

    // ebpf_lock_unlock(&module->lock, module_state);
    // native_lock_acquired = false;

    ebpf_assert(count_of_map_handles == instance.map_count);
    ebpf_assert(count_of_program_handles == instance.program_count);

    for (int i = 0; i < count_of_map_handles; i++) {
        map_handles[i] = instance.maps[i].handle;
        instance.maps[i].handle = ebpf_handle_invalid;
    }

    for (int i = 0; i < count_of_program_handles; i++) {
        program_handles[i] = instance.programs[i]->handle;
        instance.programs[i]->handle = ebpf_handle_invalid;
    }

Done:
    if (native_lock_acquired) {
        ebpf_lock_unlock(&module->lock, module_state);
        native_lock_acquired = false;
    }
    if (lock_acquired) {
        ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
        lock_acquired = false;
    }
    if (result != EBPF_SUCCESS) {
        if (maps_created) {
            for (uint32_t i = 0; i < instance.map_count; i++) {
                instance.handle_cleanup_context.handle_information->map_handles[i] = instance.maps[i].handle;
            }
            _ebpf_native_clean_up_maps(instance.maps, instance.map_count, true, false);
            instance.maps = NULL;
            instance.map_count = 0;
        }

        if (programs_created) {
            for (uint32_t i = 0; i < instance.program_count; i++) {
                instance.handle_cleanup_context.handle_information->program_handles[i] = instance.programs[i]->handle;
            }
            _ebpf_native_clean_up_programs(instance.programs, instance.program_count, false);
            instance.programs = NULL;
            instance.program_count = 0;
        }

        ebpf_free(local_service_name);

        if (cleanup_context_created) {
            __analysis_assume(instance.handle_cleanup_context.handle_cleanup_work_item != NULL);
            // Queue work item to close map and program handles.
            cxplat_queue_preemptible_work_item(instance.handle_cleanup_context.handle_cleanup_work_item);
            instance.handle_cleanup_context.handle_cleanup_work_item = NULL;
            instance.handle_cleanup_context.handle_information = NULL;
        }
    } else {
        // Success case. No need to close program and map handles. Clean up handle cleanup context.
        _ebpf_native_clean_up_handle_cleanup_context(&instance.handle_cleanup_context);
        // Free the map contexts.
        _ebpf_native_clean_up_maps(instance.maps, instance.map_count, false, false);
        instance.maps = NULL;
        instance.map_count = 0;
        // Free the program context array. Individual program contexts are freed when the program is unloaded.
        ebpf_free(instance.programs);
        instance.programs = NULL;
    }

    if (module_referenced) {
        _ebpf_native_release_reference(module);
        module_referenced = false;
    }

    // TODO: Add cleanup logic for instance.

    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_native_get_count_of_programs(_In_ const GUID* module_id, _Out_ size_t* count_of_programs)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_lock_state_t state = 0;
    ebpf_native_module_t** module = NULL;

    // Find the native entry in hash table.
    state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
    result = ebpf_hash_table_find(_ebpf_native_client_table, (const uint8_t*)module_id, (uint8_t**)&module);
    if (result != EBPF_SUCCESS) {
        result = EBPF_OBJECT_NOT_FOUND;
        goto Done;
    }

    *count_of_programs = _ebpf_native_get_count_of_programs(*module);

Done:
    ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_native_get_count_of_maps(_In_ const GUID* module_id, _Out_ size_t* count_of_maps)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_lock_state_t state = 0;
    ebpf_native_module_t** module = NULL;

    // Find the native entry in hash table.
    state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
    result = ebpf_hash_table_find(_ebpf_native_client_table, (const uint8_t*)module_id, (uint8_t**)&module);
    if (result != EBPF_SUCCESS) {
        result = EBPF_OBJECT_NOT_FOUND;
        goto Done;
    }

    *count_of_maps = _ebpf_native_get_count_of_maps(*module);

Done:
    ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_native_helper_address_changed(
    size_t address_count, _In_reads_opt_(address_count) uintptr_t* addresses, _In_opt_ void* context)
{
    ebpf_result_t return_value;
    ebpf_native_helper_address_changed_context_t* helper_address_changed_context =
        (ebpf_native_helper_address_changed_context_t*)context;

    uint64_t* helper_function_addresses = NULL;
    _Analysis_assume_(context != NULL);
    size_t helper_count = helper_address_changed_context->native_program->entry->helper_count;

    if (helper_count == 0) {
        return_value = EBPF_SUCCESS;
        goto Done;
    }

    if (helper_count != address_count || addresses == NULL) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    // ANUSA TODO: See if we need to "deregister" from these callbacks before deleting native_program when program
    // reference is released.
    for (size_t i = 0; i < helper_count; i++) {
        // *(uint64_t*)&(helper_address_changed_context->native_program->entry->helpers[i].address) = addresses[i];
        *(uint64_t*)&(helper_address_changed_context->native_program->runtime_context.helper_data[i].address) =
            addresses[i];
    }

    return_value = EBPF_SUCCESS;
Done:
    ebpf_free(helper_function_addresses);

    return return_value;
}
