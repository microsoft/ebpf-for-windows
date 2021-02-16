/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#include <wdm.h>
#include <ntdef.h>
#include <netiodef.h>
#include <ntintsafe.h>

#include "types.h"
#include "protocol.h"

#include "ebpf_core.h"
#include "types.h"



static DWORD _count_of_seh_raised = 0;

_Requires_lock_held_(_ebpf_core_code_entry_list_lock)
static LIST_ENTRY _ebpf_core_code_entry_list;
static KSPIN_LOCK _ebpf_core_code_entry_list_lock;

_Requires_lock_held_(_ebpf_core_map_entry_list_lock)
static LIST_ENTRY _ebpf_core_map_entry_list;
static KSPIN_LOCK _ebpf_core_map_entry_list_lock;

// TODO: Switch this to use real object manager handles
static UINT64 _next_pseudo_handle = 0;


typedef struct _ebpf_core_code_entry {
    LIST_ENTRY entry;

    // pointer to code buffer
    uint8_t* code;

    // handle returned to user mode application
    uint64_t handle;

    ebpf_hook_point_t hook_point;
} ebpf_core_code_entry_t;

typedef struct _ebpf_core_map {
    struct _ebpf_map_definition ebpf_map_definition;
    uint8_t* data;
} ebpf_core_map_t;

typedef struct _ebpf_core_map_entry {
    LIST_ENTRY entry;
    ebpf_core_map_t map;
    uint64_t handle;
} ebpf_core_map_entry_t;

typedef enum
{
    ebpfPoolTag = 'fpbe'
} EBPF_POOL_TAG;

static void* _ebpf_core_map_lookup_element(ebpf_core_map_t* map, uint32_t* key);
static void _ebpf_core_map_update_element(ebpf_core_map_t* map, uint32_t* key, uint8_t* data);
static void _ebpf_core_map_delete_element(ebpf_core_map_t* map, uint32_t* key);

static const void * _ebpf_program_helpers[] =
{
    NULL,
    (void*)&_ebpf_core_map_lookup_element,
    (void*)&_ebpf_core_map_update_element,
    (void*)&_ebpf_core_map_delete_element
};

_Requires_exclusive_lock_held_(_ebpf_core_map_entry_list_lock)
static ebpf_core_map_entry_t* _ebpf_core_find_map_entry(uint64_t handle)
{
    // TODO: Switch this to use real object manager handles
    LIST_ENTRY* list_entry = _ebpf_core_map_entry_list.Flink;
    while (list_entry != &_ebpf_core_map_entry_list)
    {
        ebpf_core_map_entry_t* map = CONTAINING_RECORD(list_entry, ebpf_core_map_entry_t, entry);
        if (handle == map->handle)
            return map;

        list_entry = list_entry->Flink;
    }
    return NULL;
}

_Requires_exclusive_lock_held_(_ebpf_core_code_entry_list_lock)
ebpf_core_code_entry_t* _ebpf_core_find_user_code(uint64_t handle)
{
    // TODO: Switch this to use real object manager handles
    LIST_ENTRY* list_entry = _ebpf_core_code_entry_list.Flink;
    while (list_entry != &_ebpf_core_code_entry_list)
    {
        ebpf_core_code_entry_t* code = CONTAINING_RECORD(list_entry, ebpf_core_code_entry_t, entry);
        if (handle == code->handle)
            return code;

        list_entry = list_entry->Flink;
    }
    return NULL;
}

NTSTATUS
ebpf_core_initialize()
{
    
    KeInitializeSpinLock(&_ebpf_core_code_entry_list_lock);
    InitializeListHead(&_ebpf_core_code_entry_list);

    KeInitializeSpinLock(&_ebpf_core_map_entry_list_lock);
    InitializeListHead(&_ebpf_core_map_entry_list);

    return STATUS_SUCCESS;
}

void
ebpf_core_terminate()
{
    KIRQL old_irql;

    KeAcquireSpinLock(&_ebpf_core_code_entry_list_lock, &old_irql);
    LIST_ENTRY* list_entry = _ebpf_core_code_entry_list.Flink;
    while (list_entry != &_ebpf_core_code_entry_list)
    {
        ebpf_core_code_entry_t* code = CONTAINING_RECORD(list_entry, ebpf_core_code_entry_t, entry);
        list_entry = list_entry->Flink;
        RemoveEntryList(&code->entry);
        ExFreePool(code);
    }
    KeReleaseSpinLock(&_ebpf_core_code_entry_list_lock, old_irql);

    KeAcquireSpinLock(&_ebpf_core_map_entry_list_lock, &old_irql);
    list_entry = _ebpf_core_map_entry_list.Flink;
    while (list_entry != &_ebpf_core_map_entry_list)
    {
        ebpf_core_map_entry_t* map = CONTAINING_RECORD(list_entry, ebpf_core_map_entry_t, entry);
        list_entry = list_entry->Flink;
        RemoveEntryList(&map->entry);
        ExFreePool(map);
    }
    KeReleaseSpinLock(&_ebpf_core_map_entry_list_lock, old_irql);

}

NTSTATUS
ebpf_core_protocol_attach_code(
    _In_ struct _ebpf_operation_attach_detach_request* request,
    _Inout_ void* reply
)
{
    NTSTATUS status = STATUS_INVALID_HANDLE;
    KIRQL old_irql;
    ebpf_core_code_entry_t* code = NULL;
    UNREFERENCED_PARAMETER(reply);

    if (request->hook != EBPF_HOOK_XDP)
    {
        status = STATUS_NOT_SUPPORTED;
        goto Done;
    }

    // TODO: Switch this to use real object manager handles
    KeAcquireSpinLock(&_ebpf_core_code_entry_list_lock, &old_irql);
    code = _ebpf_core_find_user_code(request->handle);
    if (code)
    {
        code->hook_point = request->hook;
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&_ebpf_core_code_entry_list_lock, old_irql);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: AttachCodeToHook 0x%llx handle\n", request->handle));

Done:
    return status;
}

NTSTATUS
ebpf_core_protocol_detach_code(
    _In_ struct _ebpf_operation_attach_detach_request* request,
    _Inout_ void* reply
)
{
    NTSTATUS status = STATUS_INVALID_HANDLE;
    KIRQL old_irql;
    ebpf_core_code_entry_t* code = NULL;
    UNREFERENCED_PARAMETER(reply);

    if (request->hook != EBPF_HOOK_XDP)
    {
        status = STATUS_NOT_SUPPORTED;
    }

    // TODO: Switch this to use real object manager handles
    KeAcquireSpinLock(&_ebpf_core_code_entry_list_lock, &old_irql);
    code = _ebpf_core_find_user_code(request->handle);
    if (code)
    {
        code->hook_point = EBPF_HOOK_NONE;
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&_ebpf_core_code_entry_list_lock, old_irql);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: DetachCodeFromHook 0x%llx handle\n", request->handle));

    return status;
}

NTSTATUS
ebpf_core_protocol_unload_code(
    _In_ struct _ebpf_operation_unload_code_request* request,
    _Inout_ void* reply)
{
    NTSTATUS status = STATUS_INVALID_HANDLE;
    KIRQL old_irql;
    ebpf_core_code_entry_t* code = NULL;
    UNREFERENCED_PARAMETER(reply);

    KeAcquireSpinLock(&_ebpf_core_code_entry_list_lock, &old_irql);
    // TODO: Switch this to use real object manager handles
    code = _ebpf_core_find_user_code(request->handle);
    if (code)
    {
        RemoveEntryList(&code->entry);
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: UnloadCode: 0x%llp handle: 0x%llx\n", code, code->handle));
        ExFreePool(code);
        status = STATUS_SUCCESS;
    }

    KeReleaseSpinLock(&_ebpf_core_code_entry_list_lock, old_irql);
    if (status != STATUS_SUCCESS)
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "EbpfCore: UnloadCode: failed to find handle 0x%llx\n", request->handle));
    }
    return status;
}

NTSTATUS
ebpf_core_protocol_load_code(
    _In_ struct _ebpf_operation_load_code_request* request,
    _Inout_ struct _ebpf_operation_load_code_reply* reply)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID  buffer = NULL;
    UINT16 codeSize = 0;
    KIRQL old_irql;
    ebpf_core_code_entry_t* code = NULL;

    // allocate
    codeSize = request->header.length;
    buffer = ExAllocatePool2(
        POOL_FLAG_NON_PAGED_EXECUTE,
        codeSize + sizeof(ebpf_core_code_entry_t),
        ebpfPoolTag
    );
    if (buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    // copy and hang on to user code
    code = buffer;
    buffer = (uint8_t*)buffer + sizeof(ebpf_core_code_entry_t);
    RtlCopyMemory(buffer, (PUCHAR)request->machine_code, codeSize);
    code->code = buffer;

    // TODO: Switch this to use real object manager handles
    code->handle = (0xffff | _next_pseudo_handle++);

    KeAcquireSpinLock(&_ebpf_core_code_entry_list_lock, &old_irql);
    InsertTailList(&_ebpf_core_code_entry_list, &code->entry);
    KeReleaseSpinLock(&_ebpf_core_code_entry_list_lock, old_irql);

    // construct the response
    reply->handle = code->handle;
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: AllocateAndLoadCode code: 0x%llp handle: 0x%llx\n", code, code->handle));

Done:
    if (!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "EbpfCore: AllocateAndLoadCode code failed %d\n", status));
    }
    return status;
}

NTSTATUS ebpf_core_protocol_resolve_helper(
    _In_ struct _ebpf_operation_resolve_helper_request* request,
    _Out_ struct _ebpf_operation_resolve_helper_reply* reply)
{
    if (request->helper_id[0] >= EBPF_INVALID)
    {
        return STATUS_INVALID_PARAMETER;
    }
    reply->address[0] = (uint64_t)_ebpf_program_helpers[request->helper_id[0]];

    return STATUS_SUCCESS;;
}

NTSTATUS ebpf_core_protocol_resolve_map(
    _In_ struct _ebpf_operation_resolve_map_request* request,
    _Out_ struct _ebpf_operation_resolve_map_reply* reply)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL old_irql;
    ebpf_core_map_entry_t* map = NULL;

    KeAcquireSpinLock(&_ebpf_core_map_entry_list_lock, &old_irql);
    // TODO: Switch this to use real object manager handles
    map = _ebpf_core_find_map_entry(request->map_handle[0]);
    if (map)
    {
        status = STATUS_SUCCESS;
        reply->address[0] = (uint64_t)&map->map;
    }
    KeReleaseSpinLock(&_ebpf_core_map_entry_list_lock, old_irql);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: ebpf_core_protocol_resolve_map 0x%llx handle\n", request->map_handle[0]));

    return status;
}

xdp_action_t
ebpf_core_invoke_xdp_hook(
    _In_ void* buffer,
    _In_ uint32_t buffer_length)
{
    KIRQL old_irql;
    ebpf_core_code_entry_t* code = NULL;
    xdp_hook_function function_pointer;
    xdp_action_t result = XDP_PASS;
    BOOLEAN found = FALSE;

    xdp_md_t ctx = { 0 };
    ctx.data = (UINT64)buffer;
    ctx.data_end = (UINT64)buffer_length;

    KeAcquireSpinLock(&_ebpf_core_code_entry_list_lock, &old_irql);

    // TODO: Switch this to use real object manager handles
    LIST_ENTRY* list_entry = _ebpf_core_code_entry_list.Flink;
    while (list_entry != &_ebpf_core_code_entry_list)
    {
        code = CONTAINING_RECORD(list_entry, ebpf_core_code_entry_t, entry);
        if (code->hook_point == EBPF_HOOK_XDP)
        {
            // find the first one and run.
            found = TRUE;
            break;
        }

        list_entry = list_entry->Flink;
    }

    if (found)
    {
        function_pointer = (xdp_hook_function)code->code;
        __try {
            result = (*function_pointer)(&ctx);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            _count_of_seh_raised++;
        }
    }

    KeReleaseSpinLock(&_ebpf_core_code_entry_list_lock, old_irql);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: ExecuteCode. _count_of_seh_raised %d\n", _count_of_seh_raised));

    return (xdp_action_t)result;
}

NTSTATUS ebpf_core_protocol_create_map(
    _In_ struct _ebpf_operation_create_map_request* request,
    _Inout_ struct _ebpf_operation_create_map_reply* reply)
{
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T map_entry_size = sizeof(ebpf_core_map_entry_t);
    SIZE_T map_data_size = 0;
    KIRQL old_irql;
    ebpf_core_map_entry_t* map = NULL;

    // TODO: Add support for other map types
    if (request->ebpf_map_definition.type != EBPF_MAP_ARRAY)
    {
        status = STATUS_NOT_IMPLEMENTED;
        goto Done;
    }

    status = RtlSizeTMult(request->ebpf_map_definition.max_entries, request->ebpf_map_definition.value_size, &map_data_size);
    if (status != STATUS_SUCCESS)
    {
        goto Done;
    }

    status = RtlSizeTMult(map_data_size, map_entry_size, &map_entry_size);
    if (status != STATUS_SUCCESS)
    {
        goto Done;
    }

    // allocate
    map = ExAllocatePool2(
        POOL_FLAG_NON_PAGED_EXECUTE,
        map_entry_size,
        ebpfPoolTag
    );
    if (map == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }
    memset(map, 0, map_entry_size);

    map->map.ebpf_map_definition = request->ebpf_map_definition;
    map->map.data = (uint8_t*)(map + 1);

    // TODO: Switch this to use real object manager handles
    map->handle = (0xffff | _next_pseudo_handle++);

    KeAcquireSpinLock(&_ebpf_core_map_entry_list_lock, &old_irql);
    InsertTailList(&_ebpf_core_map_entry_list, &map->entry);
    KeReleaseSpinLock(&_ebpf_core_map_entry_list_lock, old_irql);

    // construct the response
    reply->handle = map->handle;
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: ebpf_core_protocol_create_map map: 0x%llp handle: 0x%llx\n", map, map->handle));

Done:
    if (!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "EbpfCore: ebpf_core_protocol_create_map code failed %d\n", status));
    }
    return status;
}

NTSTATUS ebpf_core_protocol_map_lookup_element(
    _In_ struct _ebpf_operation_map_lookup_element_request* request,
    _Inout_ struct _ebpf_operation_map_lookup_element_reply* reply)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL old_irql;
    ebpf_core_map_entry_t* map = NULL;
    uint32_t key;
    SIZE_T value_offset = 0;

    if (request->header.length < sizeof(struct _ebpf_operation_map_lookup_element_request) - 1 + sizeof(uint32_t))
    {
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    key = *(uint32_t*)request->key;

    KeAcquireSpinLock(&_ebpf_core_map_entry_list_lock, &old_irql);
    // TODO: Switch this to use real object manager handles
    map = _ebpf_core_find_map_entry(request->handle);
    if (map)
    {
        // Compute offset into data.
        status = RtlSizeTMult(key, map->map.ebpf_map_definition.value_size, &value_offset);
        status = key < map->map.ebpf_map_definition.max_entries ? status : STATUS_INVALID_PARAMETER;
        status = (reply->header.length - sizeof(struct _ebpf_operation_map_lookup_element_reply) + 1) == (map->map.ebpf_map_definition.value_size) ? status : STATUS_INVALID_PARAMETER;

        if (status == STATUS_SUCCESS)
        {
            memcpy(reply->value, map->map.data + value_offset, map->map.ebpf_map_definition.value_size);
        }
    }
    KeReleaseSpinLock(&_ebpf_core_map_entry_list_lock, old_irql);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: ebpf_core_protocol_map_lookup_element 0x%llx handle\n", request->handle));

Done:
    return status;
}

NTSTATUS ebpf_core_protocol_map_update_element(
    _In_ struct _ebpf_operation_map_update_element_request* request,
    _Inout_ void* reply)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL old_irql;
    ebpf_core_map_entry_t* map = NULL;
    uint32_t key;
    SIZE_T value_offset = 0;

    UNREFERENCED_PARAMETER(reply);

    KeAcquireSpinLock(&_ebpf_core_map_entry_list_lock, &old_irql);
    // TODO: Switch this to use real object manager handles
    map = _ebpf_core_find_map_entry(request->handle);
    if (map)
    {
        // Is the request big enough to contain both key + value?
        status = (request->header.length - sizeof(struct _ebpf_operation_map_update_element_request) + 1) == ((size_t)map->map.ebpf_map_definition.key_size + (size_t)map->map.ebpf_map_definition.value_size) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;

        // If success, then extract key
        key = (status == STATUS_SUCCESS) ? *(uint32_t*)request->data : 0;

        // If success, check if key is in range
        status = (status == STATUS_SUCCESS) ? key < map->map.ebpf_map_definition.max_entries ? status : STATUS_INVALID_PARAMETER : status;

        // If success, then compute value offset
        status = (status == STATUS_SUCCESS) ? RtlSizeTMult(key, map->map.ebpf_map_definition.value_size, &value_offset) : status;

        if (status == STATUS_SUCCESS)
        {
            memcpy(map->map.data + value_offset, request->data + sizeof(uint32_t), map->map.ebpf_map_definition.value_size);
        }
    }
    KeReleaseSpinLock(&_ebpf_core_map_entry_list_lock, old_irql);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: ebpf_core_protocol_map_lookup_element 0x%llx handle\n", request->handle));

    return status;
}

NTSTATUS ebpf_core_protocol_map_delete_element(
    _In_ struct _ebpf_operation_map_delete_element_request* request,
    _Inout_ void* reply)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL old_irql;
    ebpf_core_map_entry_t* map = NULL;
    uint32_t key;
    SIZE_T value_offset = 0;
    UNREFERENCED_PARAMETER(reply);

    KeAcquireSpinLock(&_ebpf_core_map_entry_list_lock, &old_irql);
    // TODO: Switch this to use real object manager handles
    map = _ebpf_core_find_map_entry(request->handle);
    if (map)
    {
        // Is the request big enough to contain both key + value?
        status = (request->header.length - sizeof(struct _ebpf_operation_map_update_element_request) + 1) == map->map.ebpf_map_definition.key_size ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;

        // If success, then extract key
        key = (status == STATUS_SUCCESS) ? *(uint32_t*)request->key : 0;

        // If success, check if key is in range
        status = (status == STATUS_SUCCESS) ? key < map->map.ebpf_map_definition.max_entries ? status : STATUS_INVALID_PARAMETER : status;

        // If success, then compute value offset
        status = (status == STATUS_SUCCESS) ? RtlSizeTMult(key, map->map.ebpf_map_definition.value_size, &value_offset) : status;

        if (status == STATUS_SUCCESS)
        {
            memset(map->map.data + value_offset, 0, map->map.ebpf_map_definition.value_size);
        }
    }
    KeReleaseSpinLock(&_ebpf_core_map_entry_list_lock, old_irql);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: ebpf_core_protocol_map_lookup_element 0x%llx handle\n", request->handle));

    return status;
}

// EBPF helper functions
void* _ebpf_core_map_lookup_element(ebpf_core_map_t* map, uint32_t* key)
{
    if (!map || !key)
        return NULL;

    if (*key > map->ebpf_map_definition.max_entries)
        return NULL;

    return &map->data[*key * map->ebpf_map_definition.value_size];
}

void _ebpf_core_map_update_element(ebpf_core_map_t* map, uint32_t* key, uint8_t* data)
{
    if (!map || !key)
        return;

    if (*key > map->ebpf_map_definition.max_entries)
        return;

    uint8_t* entry = &map->data[*key * map->ebpf_map_definition.value_size];
    memcpy(entry, data, map->ebpf_map_definition.value_size);
}

void _ebpf_core_map_delete_element(ebpf_core_map_t* map, uint32_t* key)
{
    if (!map || !key)
        return;

    if (*key > map->ebpf_map_definition.max_entries)
        return;

    uint8_t* entry = &map->data[*key * map->ebpf_map_definition.value_size];
    memset(entry, 0, map->ebpf_map_definition.value_size);
}
