// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_core.h"
#include "ebpf_handle.h"
#include "ebpf_native.h"
#include "ebpf_object.h"
#include "ebpf_program.h"
#include "ebpf_protocol.h"

#include <intrin.h>

#define DEFAULT_PIN_ROOT_PATH "/ebpf/global"
#define EBPF_MAX_PIN_PATH_LENGTH 256

static const uint32_t _ebpf_native_marker = 'entv';

// Set this value if there is a need to block older version of the native driver.
static bpf2c_version_t _ebpf_minimum_version = {0, 0, 0};

#ifndef GUID_NULL
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
    ebpf_utf8_string_t pin_path;
    bool reused;
    bool pinned;
} ebpf_native_map_t;

typedef struct _ebpf_native_program
{
    program_entry_t* entry;
    ebpf_handle_t handle;
    struct _ebpf_native_helper_address_changed_context* addresses_changed_callback_context;
} ebpf_native_program_t;

typedef enum _ebpf_native_module_state
{
    MODULE_STATE_UNINITIALIZED = 0,
    MODULE_STATE_INITIALIZING,
    MODULE_STATE_INITIALIZED,
    MODULE_STATE_LOADING,
    MODULE_STATE_LOADED,
    MODULE_STATE_UNLOADING,
} ebpf_native_module_state_t;

typedef struct _ebpf_native_module
{
    ebpf_base_object_t base;
    GUID client_module_id;
    metadata_table_t* table;
    ebpf_native_module_state_t state;
    bool detaching;
    _Field_z_ wchar_t* service_name; // This will be used to pass to the unload module workitem.
    ebpf_lock_t lock;
    ebpf_native_map_t* maps;
    size_t map_count;
    ebpf_native_program_t* programs;
    size_t program_count;
    HANDLE nmr_binding_handle;
    ebpf_list_entry_t list_entry;
    ebpf_preemptible_work_item_t* cleanup_workitem;
} ebpf_native_module_t;

static GUID _ebpf_native_npi_id = {/* c847aac8-a6f2-4b53-aea3-f4a94b9a80cb */
                                   0xc847aac8,
                                   0xa6f2,
                                   0x4b53,
                                   {0xae, 0xa3, 0xf4, 0xa9, 0x4b, 0x9a, 0x80, 0xcb}};

static GUID _ebpf_native_provider_id = {/* 5e24d2f5-f799-42c3-a945-87feefd930a7 */
                                        0x5e24d2f5,
                                        0xf799,
                                        0x42c3,
                                        {0xa9, 0x45, 0x87, 0xfe, 0xef, 0xd9, 0x30, 0xa7}};

static ebpf_extension_provider_t* _ebpf_native_provider = NULL;

#define EBPF_CLIENT_TABLE_BUCKET_COUNT 64
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
    ebpf_native_module_t* module;
    ebpf_native_program_t* native_program;
} ebpf_native_helper_address_changed_context_t;

static ebpf_result_t
_ebpf_native_helper_address_changed(_Inout_ ebpf_program_t* program, _Inout_opt_ void* context);

static void
_ebpf_native_unload_work_item(_In_opt_ const void* service)
{
    // Do not free "service" here. It is freed by platform.
    if (service != NULL) {
        ebpf_native_unload_driver((const wchar_t*)service);
    }
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
_ebpf_native_clean_up_maps(_In_reads_(map_count) _Frees_ptr_ ebpf_native_map_t* maps, size_t map_count, bool unpin)
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
        if (map->handle != ebpf_handle_invalid) {
            ebpf_assert_success(ebpf_handle_close(map->handle));
        }
    }

    ebpf_free(maps);
}

static void
_ebpf_native_clean_up_programs(_In_reads_(count_of_programs) ebpf_native_program_t* programs, size_t count_of_programs)
{
    for (uint32_t i = 0; i < count_of_programs; i++) {
        if (programs[i].handle != ebpf_handle_invalid) {
            ebpf_assert_success(ebpf_handle_close(programs[i].handle));
        }
        ebpf_free(programs[i].addresses_changed_callback_context);
        programs[i].addresses_changed_callback_context = NULL;
    }

    ebpf_free(programs);
}

static void
_ebpf_native_clean_up_module(_In_ _Post_invalid_ ebpf_native_module_t* module)
{
    _ebpf_native_clean_up_maps(module->maps, module->map_count, false);
    _ebpf_native_clean_up_programs(module->programs, module->program_count);

    module->maps = NULL;
    module->map_count = 0;
    module->programs = NULL;
    module->program_count = 0;

    // Note: Do not free module->service_name here explicitly.
    // It will be freed automatically when workitem is freed.
    ebpf_free_preemptible_work_item(module->cleanup_workitem);

    ebpf_lock_destroy(&module->lock);

    ebpf_free(module);
}

_Requires_lock_held_(module->lock) static ebpf_result_t _ebpf_native_unload(_Inout_ ebpf_native_module_t* module)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_preemptible_work_item_t* work_item = NULL;

    if (module->state == MODULE_STATE_UNLOADING) {
        // If module is already unloading, skip unloading it again.
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "_ebpf_native_unload: module already unloading",
            module->client_module_id);
        result = EBPF_SUCCESS;
        goto Done;
    }
    module->state = MODULE_STATE_UNLOADING;

    // Queue pre-allocated work item to unload the driver.
    work_item = module->cleanup_workitem;
    module->cleanup_workitem = NULL;
    module->service_name = NULL;

    ebpf_queue_preemptible_work_item(work_item);

Done:
    EBPF_RETURN_RESULT(result);
}

void
ebpf_native_acquire_reference(_Inout_ ebpf_native_module_t* module)
{
    ebpf_assert(module->base.marker == _ebpf_native_marker);

    int64_t new_ref_count = ebpf_interlocked_increment_int64(&module->base.reference_count);
    if (new_ref_count == 1) {
        __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }
}

void
ebpf_native_release_reference(_In_opt_ _Post_invalid_ ebpf_native_module_t* module)
{
    int64_t new_ref_count;
    ebpf_lock_state_t module_lock_state = 0;

    if (!module) {
        EBPF_RETURN_VOID();
    }

    ebpf_assert(module->base.marker == _ebpf_native_marker);

    new_ref_count = ebpf_interlocked_decrement_int64(&module->base.reference_count);
    if (new_ref_count < 0) {
        __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    }

    if (new_ref_count == 1) {
        // Check if all the program references have been released. If that
        // is the case, explicitly unload the driver, if it is safe to do so.
        module_lock_state = ebpf_lock_lock(&module->lock);
        if (!module->detaching) {
            // If the module is not yet marked as detaching, and reference
            // count is 1, it means all the program references have been
            // released.
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_INFO,
                EBPF_TRACELOG_KEYWORD_NATIVE,
                "ebpf_native_release_reference: all program references released. Unloading module",
                module->client_module_id);

            ebpf_assert_success(_ebpf_native_unload(module));
        }
        ebpf_lock_unlock(&module->lock, module_lock_state);
    } else if (new_ref_count == 0) {
        ebpf_lock_state_t state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
        // Delete entry from hash table.
        ebpf_assert_success(
            ebpf_hash_table_delete(_ebpf_native_client_table, (const uint8_t*)&module->client_module_id));
        ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);

        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_INFO,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_native_release_reference: ref is 0, complete detach callback",
            module->client_module_id);

        // All references to the module have been released. Safe to complete the detach callback.
        NmrProviderDetachClientComplete(module->nmr_binding_handle);

        // Clean up the native module.
        _ebpf_native_clean_up_module(module);
    }

    EBPF_RETURN_VOID();
}

void
ebpf_native_terminate()
{
    EBPF_LOG_ENTRY();

    // ebpf_provider_unload is blocking call until all the
    // native modules have been detached.
    ebpf_provider_unload(_ebpf_native_provider);
    _ebpf_native_provider = NULL;

    // All native modules should be cleaned up by now.
    ebpf_assert(!_ebpf_native_client_table || ebpf_hash_table_key_count(_ebpf_native_client_table) == 0);

    ebpf_hash_table_destroy(_ebpf_native_client_table);
    _ebpf_native_client_table = NULL;
    ebpf_lock_destroy(&_ebpf_native_client_table_lock);

    EBPF_RETURN_VOID();
}

static NTSTATUS
_ebpf_native_provider_attach_client_callback(
    HANDLE nmr_binding_handle,
    _In_ const void* provider_context,
    _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
    _In_ const void* client_binding_context,
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
        *client_module_id);
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

    // If the metadata table changes in size, then require the regeneration of the native module.
    if (table->size != sizeof(metadata_table_t)) {
        result = EBPF_INVALID_ARGUMENT;
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "The metadata table size is wrong for client module. The version of bpf2c used to generate this module "
            "may be too old.",
            *client_module_id);
        goto Done;
    }

    bpf2c_version_t client_version = {0, 0, 0};
    table->version(&client_version);
    if (_ebpf_compare_versions(&client_version, &_ebpf_minimum_version) < 0) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    ebpf_lock_create(&client_context->lock);
    client_context->base.marker = _ebpf_native_marker;
    client_context->base.acquire_reference = ebpf_native_acquire_reference;
    client_context->base.release_reference = ebpf_native_release_reference;
    // Acquire "attach" reference. Released when detach is called for this module.
    client_context->base.reference_count = 1;
    client_context->client_module_id = *client_module_id;
    client_context->state = MODULE_STATE_UNINITIALIZED;
    client_context->table = table;
    client_context->nmr_binding_handle = nmr_binding_handle;

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
            *client_module_id);
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
_ebpf_native_provider_detach_client_callback(_In_ const void* provider_binding_context)
{
    ebpf_native_module_t* context = (ebpf_native_module_t*)provider_binding_context;

    EBPF_LOG_MESSAGE_GUID(
        EBPF_TRACELOG_LEVEL_INFO,
        EBPF_TRACELOG_KEYWORD_NATIVE,
        "_ebpf_native_client_detach_callback: Called for",
        context->client_module_id);
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
    ebpf_native_release_reference(module);

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

    return_value = ebpf_provider_load(
        &_ebpf_native_provider,
        &_ebpf_native_npi_id,
        &_ebpf_native_provider_id,
        NULL,
        NULL,
        NULL,
        NULL,
        (NPI_PROVIDER_ATTACH_CLIENT_FN*)_ebpf_native_provider_attach_client_callback,
        (NPI_PROVIDER_DETACH_CLIENT_FN*)_ebpf_native_provider_detach_client_callback,
        NULL);

    if (return_value != EBPF_SUCCESS) {
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
        if (maps[i].definition.pinning != PIN_NONE && maps[i].definition.pinning != PIN_GLOBAL_NS) {
            result = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        native_maps[i].entry = &maps[i];
        native_maps[i].original_id = i + ORIGINAL_ID_OFFSET;
        maps[i].address = NULL;

        if (maps[i].definition.pinning == PIN_GLOBAL_NS) {
            // Construct the pin path.
            size_t prefix_length = strnlen(DEFAULT_PIN_ROOT_PATH, EBPF_MAX_PIN_PATH_LENGTH);
            size_t name_length = strnlen_s(maps[i].name, BPF_OBJ_NAME_LEN);
            if (name_length == 0 || name_length >= BPF_OBJ_NAME_LEN ||
                prefix_length + name_length + 1 >= EBPF_MAX_PIN_PATH_LENGTH) {
                EBPF_LOG_MESSAGE_GUID(
                    EBPF_TRACELOG_LEVEL_ERROR,
                    EBPF_TRACELOG_KEYWORD_NATIVE,
                    "_ebpf_native_initialize_maps: map pin path too long",
                    *module_id);
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
    ebpf_result_t result = ebpf_object_reference_by_handle(original_map_handle, EBPF_OBJECT_MAP, &object);
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
    ebpf_object_release_reference(object);
    EBPF_RETURN_RESULT(result);
}

static ebpf_result_t
_ebpf_native_reuse_map(_Inout_ ebpf_native_map_t* map)
{
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
    return result;
}

static ebpf_result_t
_ebpf_native_create_maps(_Inout_ ebpf_native_module_t* module)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_native_map_t* native_maps = NULL;
    map_entry_t* maps = NULL;
    size_t map_count = 0;
    ebpf_utf8_string_t map_name = {0};
    ebpf_map_definition_in_memory_t map_definition = {0};

    // Get the maps
    module->table->maps(&maps, &map_count);
    if (map_count == 0) {
        EBPF_RETURN_RESULT(EBPF_SUCCESS);
    }

    module->maps =
        (ebpf_native_map_t*)ebpf_allocate_with_tag(map_count * sizeof(ebpf_native_map_t), EBPF_POOL_TAG_NATIVE);
    if (module->maps == NULL) {
        EBPF_RETURN_RESULT(EBPF_NO_MEMORY);
    }

    module->map_count = map_count;
    native_maps = module->maps;

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
                "_ebpf_native_create_maps: module already detaching / unloading",
                module->client_module_id);
            break;
        }

        if (native_map->entry->definition.pinning == PIN_GLOBAL_NS) {
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
        _ebpf_native_clean_up_maps(module->maps, module->map_count, true);
        module->maps = NULL;
        module->map_count = 0;
    }
    if (map_name.value != NULL) {
        ebpf_free(map_name.value);
    }

    EBPF_RETURN_RESULT(result);
}

static void
_ebpf_native_initialize_programs(
    _Out_writes_(program_count) ebpf_native_program_t* native_programs,
    _In_reads_(program_count) program_entry_t* programs,
    size_t program_count)
{
    for (uint32_t i = 0; i < program_count; i++) {
        native_programs[i].entry = &programs[i];
        native_programs[i].handle = ebpf_handle_invalid;
    }
}

static ebpf_result_t
_ebpf_native_resolve_maps_for_program(_In_ ebpf_native_module_t* module, _In_ const ebpf_native_program_t* program)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    ebpf_handle_t* map_handles = NULL;
    uintptr_t* map_addresses = NULL;
    uint16_t* map_indices = program->entry->referenced_map_indices;
    uint16_t map_count = program->entry->referenced_map_count;
    ebpf_native_map_t* native_maps = module->maps;

    if (map_count == 0) {
        // No maps associated with this program.
        EBPF_RETURN_RESULT(EBPF_SUCCESS);
    }

    // Validate all map indices are within range.
    for (uint32_t i = 0; i < map_count; i++) {
        if (map_indices[i] >= module->map_count) {
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_NATIVE,
                "_ebpf_native_resolve_maps_for_program: map indices not within range",
                module->client_module_id);
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
        // Same map can be used in multiple programs and hence resolved multiple times.
        // Verify that the address of a map does not change.
        if (native_maps[map_indices[i]].entry->address != NULL &&
            native_maps[map_indices[i]].entry->address != (void*)map_addresses[i]) {
            result = EBPF_INVALID_ARGUMENT;
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_NATIVE,
                "_ebpf_native_resolve_maps_for_program: map address changed",
                module->client_module_id);
            goto Done;
        }
        native_maps[map_indices[i]].entry->address = (void*)map_addresses[i];
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
    helper_function_entry_t* helpers = program->entry->helpers;

    if (helper_count == 0) {
        // No helpers called by this program.
        EBPF_RETURN_RESULT(EBPF_SUCCESS);
    }

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
        helper_ids[i] = helpers[i].helper_id;
    }

    result = ebpf_core_resolve_helper(program->handle, helper_count, helper_ids, (uint64_t*)helper_addresses);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_core_resolve_helper failed",
            module->client_module_id);
        goto Done;
    }

    // Update the addresses in the helper entries.
    for (uint16_t i = 0; i < helper_count; i++) {
        helpers[i].address = helper_addresses[i];
    }

Done:
    ebpf_free(helper_ids);
    ebpf_free(helper_addresses);
    EBPF_RETURN_RESULT(result);
}

static void
_ebpf_native_initialize_helpers_for_program(
    _In_ const ebpf_native_module_t* module, _Inout_ ebpf_native_program_t* program)
{
    UNREFERENCED_PARAMETER(module);
    size_t helper_count = program->entry->helper_count;
    helper_function_entry_t* helpers = program->entry->helpers;
    // Initialize the helper entries.
    for (size_t i = 0; i < helper_count; i++) {
        helpers[i].address = NULL;
        if (helpers[i].helper_id == BPF_FUNC_tail_call) {
            helpers[i].tail_call = true;
        }
    }
}

static ebpf_result_t
_ebpf_native_load_programs(_Inout_ ebpf_native_module_t* module)
{
    ebpf_result_t result = EBPF_SUCCESS;
    ebpf_native_program_t* native_programs = NULL;
    program_entry_t* programs = NULL;
    size_t program_count = 0;
    size_t program_name_length = 0;
    size_t section_name_length = 0;
    uint8_t* program_name = NULL;
    uint8_t* section_name = NULL;

    // Get the programs.
    module->table->programs(&programs, &program_count);
    if (program_count == 0 || programs == NULL) {
        return EBPF_INVALID_OBJECT;
    }

    module->programs = (ebpf_native_program_t*)ebpf_allocate_with_tag(
        program_count * sizeof(ebpf_native_program_t), EBPF_POOL_TAG_NATIVE);
    if (module->programs == NULL) {
        return EBPF_NO_MEMORY;
    }
    module->program_count = program_count;
    native_programs = module->programs;

    _ebpf_native_initialize_programs(native_programs, programs, program_count);

    for (uint32_t count = 0; count < program_count; count++) {
        ebpf_native_program_t* native_program = &native_programs[count];
        program_entry_t* program = native_program->entry;
        ebpf_program_parameters_t parameters = {0};

        _ebpf_native_initialize_helpers_for_program(module, native_program);

        program_name_length = strnlen_s(program->program_name, BPF_OBJ_NAME_LEN);
        section_name_length = strnlen_s(program->section_name, BPF_OBJ_NAME_LEN);
        if (program_name_length == 0 || program_name_length >= BPF_OBJ_NAME_LEN || section_name_length == 0 ||
            section_name_length >= BPF_OBJ_NAME_LEN) {
            result = EBPF_INVALID_ARGUMENT;
            break;
        }

        program_name = ebpf_allocate_with_tag(program_name_length, EBPF_POOL_TAG_NATIVE);
        if (program_name == NULL) {
            result = EBPF_NO_MEMORY;
            break;
        }
        section_name = ebpf_allocate_with_tag(section_name_length, EBPF_POOL_TAG_NATIVE);
        if (section_name == NULL) {
            result = EBPF_NO_MEMORY;
            break;
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

        result = ebpf_program_create_and_initialize(&parameters, &native_program->handle);
        if (result != EBPF_SUCCESS) {
            break;
        }

        ebpf_free(program_name);
        ebpf_free(section_name);
        program_name = NULL;
        section_name = NULL;

        // Load machine code.
        result = ebpf_core_load_code(
            native_program->handle, EBPF_CODE_NATIVE, module, (uint8_t*)native_program->entry->function, 0);
        if (result != EBPF_SUCCESS) {
            break;
        }

        // Resolve and associate maps with the program.
        result = _ebpf_native_resolve_maps_for_program(module, native_program);
        if (result != EBPF_SUCCESS) {
            break;
        }

        ebpf_native_helper_address_changed_context_t* context = NULL;

        context = (ebpf_native_helper_address_changed_context_t*)ebpf_allocate(
            sizeof(ebpf_native_helper_address_changed_context_t));

        if (context == NULL) {
            result = EBPF_NO_MEMORY;
            break;
        }

        context->module = module;
        context->native_program = native_program;

        ebpf_program_t* program_object = NULL;
        result = ebpf_object_reference_by_handle(
            native_program->handle, EBPF_OBJECT_PROGRAM, (ebpf_core_object_t**)&program_object);
        if (result != EBPF_SUCCESS) {
            ebpf_free(context);
            break;
        }

        result = ebpf_program_register_for_helper_changes(program_object, _ebpf_native_helper_address_changed, context);

        ebpf_object_release_reference((ebpf_core_object_t*)program_object);

        if (result != EBPF_SUCCESS) {
            ebpf_free(context);
            break;
        }

        native_program->addresses_changed_callback_context = context;

        // Resolve helper addresses.
        result = _ebpf_native_resolve_helpers_for_program(module, native_program);
        if (result != EBPF_SUCCESS) {
            break;
        }
    }

    if (result != EBPF_SUCCESS) {
        _ebpf_native_clean_up_programs(module->programs, module->program_count);
        module->programs = NULL;
        module->program_count = 0;
    }

    ebpf_free(program_name);
    ebpf_free(section_name);
    return result;
}

size_t
_ebpf_native_get_count_of_maps(_In_ const ebpf_native_module_t* module)
{
    map_entry_t* maps = NULL;
    size_t count_of_maps;
    module->table->maps(&maps, &count_of_maps);

    return count_of_maps;
}

size_t
_ebpf_native_get_count_of_programs(_In_ const ebpf_native_module_t* module)
{
    program_entry_t* programs = NULL;
    size_t count_of_programs;
    module->table->programs(&programs, &count_of_programs);

    return count_of_programs;
}

_Must_inspect_result_ ebpf_result_t
ebpf_native_load(
    _In_reads_(service_name_length) const wchar_t* service_name,
    uint16_t service_name_length,
    _In_ const GUID* module_id,
    _Out_ ebpf_handle_t* module_handle,
    _Out_ size_t* count_of_maps,
    _Out_ size_t* count_of_programs)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    ebpf_lock_state_t hash_table_state = 0;
    ebpf_lock_state_t state = 0;
    bool table_lock_acquired = false;
    ebpf_native_module_t* module = NULL;
    ebpf_native_module_t** existing_module = NULL;
    wchar_t* local_service_name = NULL;
    ebpf_handle_t local_module_hande = ebpf_handle_invalid;
    ebpf_preemptible_work_item_t* cleanup_workitem = NULL;

    local_service_name = ebpf_allocate_with_tag((size_t)service_name_length + 2, EBPF_POOL_TAG_NATIVE);
    if (local_service_name == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }
    memcpy(local_service_name, (uint8_t*)service_name, service_name_length);

    result = ebpf_allocate_preemptible_work_item(&cleanup_workitem, _ebpf_native_unload_work_item, local_service_name);
    if (result != EBPF_SUCCESS) {
        ebpf_free(local_service_name);
        goto Done;
    }

    ebpf_result_t native_load_result = ebpf_native_load_driver(local_service_name);
    if (native_load_result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_WSTRING(
            EBPF_TRACELOG_LEVEL_WARNING,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_native_load_driver failed",
            local_service_name);
    }

    // Find the native entry in hash table.
    hash_table_state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
    table_lock_acquired = true;
    result = ebpf_hash_table_find(_ebpf_native_client_table, (const uint8_t*)module_id, (uint8_t**)&existing_module);
    if (result != EBPF_SUCCESS) {
        result = EBPF_OBJECT_NOT_FOUND;
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_NATIVE, "ebpf_native_load: module not found", *module_id);
        goto Done;
    }
    module = *existing_module;
    ebpf_lock_unlock(&_ebpf_native_client_table_lock, hash_table_state);
    table_lock_acquired = false;

    state = ebpf_lock_lock(&module->lock);
    if (module->state != MODULE_STATE_UNINITIALIZED || module->detaching) {
        if (module->detaching || module->state == MODULE_STATE_UNLOADING) {
            // This client is detaching / unloading.
            result = EBPF_EXTENSION_FAILED_TO_LOAD;
            ebpf_lock_unlock(&module->lock, state);
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_NATIVE,
                "ebpf_native_load: module is detaching / unloading",
                *module_id);
        } else {
            // This client has already been initialized.
            result = EBPF_OBJECT_ALREADY_EXISTS;
            ebpf_lock_unlock(&module->lock, state);
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_NATIVE,
                "ebpf_native_load: module already initialized",
                *module_id);
        }
        goto Done;
    }
    // Mark the module as initializing.
    module->state = MODULE_STATE_INITIALIZING;
    ebpf_lock_unlock(&module->lock, state);

    // Create handle for the native module.
    result = ebpf_handle_create(&local_module_hande, (ebpf_base_object_t*)module);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_native_load: Failed to create handle.",
            *module_id);
        goto Done;
    }

    state = ebpf_lock_lock(&module->lock);
    module->state = MODULE_STATE_INITIALIZED;
    module->service_name = local_service_name;
    module->cleanup_workitem = cleanup_workitem;

    cleanup_workitem = NULL;

    ebpf_lock_unlock(&module->lock, state);

    // Get map and program count;
    *count_of_maps = _ebpf_native_get_count_of_maps(module);
    *count_of_programs = _ebpf_native_get_count_of_programs(module);
    *module_handle = local_module_hande;
    local_module_hande = ebpf_handle_invalid;

Done:
    if (table_lock_acquired) {
        ebpf_lock_unlock(&_ebpf_native_client_table_lock, hash_table_state);
        table_lock_acquired = false;
    }
    if (result != EBPF_SUCCESS) {
        ebpf_free_preemptible_work_item(cleanup_workitem);
    }
    if (local_module_hande != ebpf_handle_invalid) {
        ebpf_assert_success(ebpf_handle_close(local_module_hande));
    }

    EBPF_RETURN_RESULT(result);
}

_Must_inspect_result_ ebpf_result_t
ebpf_native_load_programs(
    _In_ const GUID* module_id,
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

    // Find the native entry in hash table.
    state = ebpf_lock_lock(&_ebpf_native_client_table_lock);
    lock_acquired = true;
    result = ebpf_hash_table_find(_ebpf_native_client_table, (const uint8_t*)module_id, (uint8_t**)&existing_module);
    if (result != EBPF_SUCCESS) {
        result = EBPF_OBJECT_NOT_FOUND;
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_native_load_programs: module not found",
            *module_id);
        goto Done;
    }
    module = *existing_module;
    module_state = ebpf_lock_lock(&module->lock);
    native_lock_acquired = true;

    if (module->state != MODULE_STATE_INITIALIZED || module->detaching) {

        if (module->detaching || module->state == MODULE_STATE_UNLOADING) {
            // This client is detaching / unloading.
            result = EBPF_EXTENSION_FAILED_TO_LOAD;
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_NATIVE,
                "ebpf_native_load_programs: module already detaching / unloading",
                *module_id);
        } else {
            // This client has already been loaded.
            result = EBPF_OBJECT_ALREADY_EXISTS;
            EBPF_LOG_MESSAGE_GUID(
                EBPF_TRACELOG_LEVEL_ERROR,
                EBPF_TRACELOG_KEYWORD_NATIVE,
                "ebpf_native_load_programs: programs already loaded / loading",
                *module_id);
        }
        goto Done;
    }

    module->state = MODULE_STATE_LOADING;

    // Take a reference on the native module before releasing the lock.
    // This will ensure the driver cannot unload while we are processing this request.
    ebpf_native_acquire_reference(module);
    module_referenced = true;

    ebpf_lock_unlock(&module->lock, module_state);
    native_lock_acquired = false;

    // Release hash table lock.
    ebpf_lock_unlock(&_ebpf_native_client_table_lock, state);
    lock_acquired = false;

    // Create maps.
    result = _ebpf_native_create_maps(module);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_VERBOSE,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_native_load_programs: map creation failed",
            *module_id);
        goto Done;
    }
    maps_created = true;

    // Create programs.
    result = _ebpf_native_load_programs(module);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE_GUID(
            EBPF_TRACELOG_LEVEL_VERBOSE,
            EBPF_TRACELOG_KEYWORD_NATIVE,
            "ebpf_native_load_programs: program load failed",
            *module_id);
        goto Done;
    }

    module_state = ebpf_lock_lock(&module->lock);
    native_lock_acquired = true;

    module->state = MODULE_STATE_LOADED;

    ebpf_lock_unlock(&module->lock, module_state);
    native_lock_acquired = false;

    ebpf_assert(count_of_map_handles == module->map_count);
    ebpf_assert(count_of_program_handles == module->program_count);

    for (int i = 0; i < count_of_map_handles; i++) {
        map_handles[i] = module->maps[i].handle;
        module->maps[i].handle = ebpf_handle_invalid;
    }

    for (int i = 0; i < count_of_program_handles; i++) {
        program_handles[i] = module->programs[i].handle;
        module->programs[i].handle = ebpf_handle_invalid;
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
            _ebpf_native_clean_up_maps(module->maps, module->map_count, true);
            module->maps = NULL;
            module->map_count = 0;
        }
        ebpf_free(local_service_name);
    }
    if (module_referenced) {
        ebpf_native_release_reference(module);
        module_referenced = false;
    }

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
_ebpf_native_helper_address_changed(_Inout_ ebpf_program_t* program, _Inout_opt_ void* context)
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

    helper_function_addresses = ebpf_allocate(helper_count * sizeof(uint64_t));
    if (helper_function_addresses == NULL) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    return_value = ebpf_program_get_helper_function_addresses(program, helper_count, helper_function_addresses);

    if (return_value != EBPF_SUCCESS) {
        goto Done;
    }

    for (size_t i = 0; i < helper_count; i++) {
        *(uint64_t*)&(helper_address_changed_context->native_program->entry->helpers[i].address) =
            helper_function_addresses[i];
    }

    return_value = EBPF_SUCCESS;
Done:
    ebpf_free(helper_function_addresses);

    return return_value;
}
