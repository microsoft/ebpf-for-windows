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



DWORD gError = 0;

LIST_ENTRY gUserCodeList;
KSPIN_LOCK gUserCodeLock;

// TODO: Switch this to use real object manager handles
UINT64 gHandle = 0;

LIST_ENTRY gMapList;
KSPIN_LOCK gMapLock;


typedef struct {
    LIST_ENTRY entry;

    // pointer to code buffer
    uint8_t* code;

    // handle required for attach/detach/unload
    uint64_t handle;

    ebpf_hook_point hook_point;
} UserCodeEntry;

typedef struct EbpfCoreMap_
{
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint8_t* data;
} EbpfCoreMap;

typedef struct {
    LIST_ENTRY entry;
    EbpfCoreMap map;
    uint64_t handle;
} EbpfCoreMapEntry;

// Externs
extern LIST_ENTRY gUserCodeList;
extern KSPIN_LOCK gUserCodeLock;

extern LIST_ENTRY gMapList;
extern KSPIN_LOCK gMapLock;

typedef enum
{
    ebpfPoolTag = 'fpbe'
} EBPF_POOL_TAG;

void* EbpfCoreMapLookupElement(EbpfCoreMap* map, uint32_t* key);
void EbpfCoreMapUpdateElement(EbpfCoreMap* map, uint32_t* key, uint8_t* data);
void EbpfCoreMapDeleteElement(EbpfCoreMap* map, uint32_t* key);

void * EbpfProgramHelpers[] =
{
    NULL,
    (void*)&EbpfCoreMapLookupElement,
    (void*)&EbpfCoreMapUpdateElement,
    (void*)&EbpfCoreMapDeleteElement
};

_Requires_exclusive_lock_held_(gMapLock)
EbpfCoreMapEntry* EbpfCoreFindMapEntry(uint64_t handle)
{
    // TODO: Switch this to use real object manager handles
    LIST_ENTRY* listEntry = gMapList.Flink;
    while (listEntry != &gMapList)
    {
        EbpfCoreMapEntry* map = CONTAINING_RECORD(listEntry, EbpfCoreMapEntry, entry);
        if (handle == map->handle)
            return map;

        listEntry = listEntry->Flink;
    }
    return NULL;
}

_Requires_exclusive_lock_held_(gUserCodeLock)
UserCodeEntry* EbpfCoreFindUserCode(uint64_t handle)
{
    // TODO: Switch this to use real object manager handles
    LIST_ENTRY* listEntry = gUserCodeList.Flink;
    while (listEntry != &gUserCodeList)
    {
        UserCodeEntry* code = CONTAINING_RECORD(listEntry, UserCodeEntry, entry);
        if (handle == code->handle)
            return code;

        listEntry = listEntry->Flink;
    }
    return NULL;
}

NTSTATUS
EbpfCoreInitialize()
{
    
    KeInitializeSpinLock(&gUserCodeLock);
    InitializeListHead(&gUserCodeList);

    KeInitializeSpinLock(&gMapLock);
    InitializeListHead(&gMapList);

    return STATUS_SUCCESS;
}

void
EbpfCoreTerminate()
{

}

NTSTATUS
EbpfCoreProtocolAttachCode(
    _In_ struct EbpfOpAttachDetachRequest* request,
    _Inout_ void* reply
)
{
    NTSTATUS status = STATUS_INVALID_HANDLE;
    KIRQL irql;
    UserCodeEntry* code = NULL;
    UNREFERENCED_PARAMETER(reply);

    if (request->hook != ebpf_hook_xdp)
    {
        status = STATUS_NOT_SUPPORTED;
        goto Done;
    }

    // TODO: Switch this to use real object manager handles
    KeAcquireSpinLock(&gUserCodeLock, &irql);
    code = EbpfCoreFindUserCode(request->handle);
    if (code)
    {
        code->hook_point = request->hook;
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&gUserCodeLock, irql);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: AttachCodeToHook 0x%llx handle\n", request->handle));

Done:
    return status;
}

NTSTATUS
EbpfCoreProtocolDetachCode(
    _In_ struct EbpfOpAttachDetachRequest* request,
    _Inout_ void* reply
)
{
    NTSTATUS status = STATUS_INVALID_HANDLE;
    KIRQL irql;
    UserCodeEntry* code = NULL;
    UNREFERENCED_PARAMETER(reply);

    if (request->hook != ebpf_hook_xdp)
    {
        status = STATUS_NOT_SUPPORTED;
    }

    // TODO: Switch this to use real object manager handles
    KeAcquireSpinLock(&gUserCodeLock, &irql);
    code = EbpfCoreFindUserCode(request->handle);
    if (code)
    {
        code->hook_point = ebpf_hook_none;
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&gUserCodeLock, irql);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: DetachCodeFromHook 0x%llx handle\n", request->handle));

    return status;
}

NTSTATUS
EbpfCoreProtocolUnloadCode(
    _In_ struct EbpfOpUnloadRequest* request,
    _Inout_ void* reply)
{
    NTSTATUS status = STATUS_INVALID_HANDLE;
    KIRQL irql;
    UserCodeEntry* code = NULL;
    UNREFERENCED_PARAMETER(reply);

    KeAcquireSpinLock(&gUserCodeLock, &irql);
    // TODO: Switch this to use real object manager handles
    code = EbpfCoreFindUserCode(request->handle);
    if (code)
    {
        RemoveEntryList(&code->entry);
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: UnloadCode: 0x%llp handle: 0x%llx\n", code, code->handle));
        ExFreePool(code);
        status = STATUS_SUCCESS;
    }

    KeReleaseSpinLock(&gUserCodeLock, irql);
    if (status != STATUS_SUCCESS)
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "EbpfCore: UnloadCode: failed to find handle 0x%llx\n", request->handle));
    }
    return status;
}

NTSTATUS
EbpfCoreProtocolLoadCode(
    _In_ struct EbpfOpLoadRequest* inputRequest,
    _Inout_ struct EbpfOpLoadReply* loadReply)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID  buffer = NULL;
    UINT16 codeSize = 0;
    KIRQL irql;
    UserCodeEntry* code = NULL;

    // allocate
    codeSize = inputRequest->header.length;
    buffer = ExAllocatePool2(
        POOL_FLAG_NON_PAGED_EXECUTE,
        codeSize + sizeof(UserCodeEntry),
        ebpfPoolTag
    );
    if (buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Done;
    }

    // copy and hang on to user code
    code = buffer;
    buffer = (uint8_t*)buffer + sizeof(UserCodeEntry);
    RtlCopyMemory(buffer, (PUCHAR)inputRequest->machine_code, codeSize);
    code->code = buffer;

    // TODO: Switch this to use real object manager handles
    code->handle = (0xffff | gHandle++);

    KeAcquireSpinLock(&gUserCodeLock, &irql);
    InsertTailList(&gUserCodeList, &code->entry);
    KeReleaseSpinLock(&gUserCodeLock, irql);

    // construct the response
    loadReply->handle = code->handle;
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: AllocateAndLoadCode code: 0x%llp handle: 0x%llx\n", code, code->handle));

Done:
    if (!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "EbpfCore: AllocateAndLoadCode code failed %d\n", status));
    }
    return status;
}

NTSTATUS EbpfCoreProtocolResolveHelper(
    _In_ struct EbpfOpResolveHelperRequest* request,
    _Out_ struct EbpfOpResolveHelperReply* reply)
{
    if (request->helper_id[0] >= ebpf_invalid)
    {
        return STATUS_INVALID_PARAMETER;
    }
    reply->address[0] = (uint64_t)EbpfProgramHelpers[request->helper_id[0]];

    return STATUS_SUCCESS;;
}

NTSTATUS EbpfCoreProtocolResolveMap(
    _In_ struct EbpfOpResolveMapRequest* request,
    _Out_ struct EbpfOpResolveMapReply* reply)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL irql;
    EbpfCoreMapEntry* map = NULL;

    KeAcquireSpinLock(&gMapLock, &irql);
    // TODO: Switch this to use real object manager handles
    map = EbpfCoreFindMapEntry(request->map_id[0]);
    if (map)
    {
        status = STATUS_SUCCESS;
        reply->address[0] = (uint64_t)&map->map;
    }
    KeReleaseSpinLock(&gMapLock, irql);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: EbpfCoreProtocolResolveMap 0x%llx handle\n", request->map_id[0]));

    return status;
}

xdp_action
EbpfCoreInvokeXdpHook(
    _In_ void* buffer,
    _In_ uint32_t buffer_length)
{
    KIRQL irql;
    UserCodeEntry* code = NULL;
    XDP_HOOK funcPtr;
    xdp_action result = XDP_PASS;
    BOOLEAN found = FALSE;

    xdp_md ctx = { 0 };
    ctx.data = (UINT64)buffer;
    ctx.data_end = (UINT64)buffer_length;

    KeAcquireSpinLock(&gUserCodeLock, &irql);

    // TODO: Switch this to use real object manager handles
    LIST_ENTRY* listEntry = gUserCodeList.Flink;
    while (listEntry != &gUserCodeList)
    {
        code = CONTAINING_RECORD(listEntry, UserCodeEntry, entry);
        if (code->hook_point == ebpf_hook_xdp)
        {
            // find the first one and run.
            found = TRUE;
            break;
        }

        listEntry = listEntry->Flink;
    }

    if (found)
    {
        funcPtr = (XDP_HOOK)code->code;
        __try {
            result = (*funcPtr)(&ctx);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            gError++;
        }
    }

    KeReleaseSpinLock(&gUserCodeLock, irql);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: ExecuteCode. gError %d\n", gError));

    return (xdp_action)result;
}

NTSTATUS EbpfCoreProtocolCreateMap(
    _In_ struct EbpfOpCreateMapRequest* request,
    _Inout_ struct EbpfOpCreateMapReply* reply)
{
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T map_entry_size = sizeof(EbpfCoreMapEntry);
    SIZE_T map_data_size = 0;
    KIRQL irql;
    EbpfCoreMapEntry* map = NULL;

    // TODO: Add support for other map types
    if (request->type != ebpf_map_array)
    {
        status = STATUS_NOT_IMPLEMENTED;
        goto Done;
    }

    status = RtlSizeTMult(request->max_entries, request->value_size, &map_data_size);
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

    map->map.key_size = request->key_size;
    map->map.type = request->type;
    map->map.max_entries = request->max_entries;
    map->map.value_size = request->value_size;
    map->map.data = (uint8_t*)(map + 1);

    // TODO: Switch this to use real object manager handles
    map->handle = (0xffff | gHandle++);

    KeAcquireSpinLock(&gMapLock, &irql);
    InsertTailList(&gMapList, &map->entry);
    KeReleaseSpinLock(&gMapLock, irql);

    // construct the response
    reply->handle = map->handle;
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: EbpfCoreProtocolCreateMap map: 0x%llp handle: 0x%llx\n", map, map->handle));

Done:
    if (!NT_SUCCESS(status))
    {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "EbpfCore: EbpfCoreProtocolCreateMap code failed %d\n", status));
    }
    return status;
}

NTSTATUS EbpfCoreProtocolMapLookupElement(
    _In_ struct EbpfOpMapLookupElementRequest* request,
    _Inout_ struct EbpfOpMapLookupElementReply* reply)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL irql;
    EbpfCoreMapEntry* map = NULL;
    uint32_t key;
    SIZE_T value_offset = 0;

    if (request->header.length < sizeof(struct EbpfOpMapLookupElementRequest) - 1 + sizeof(uint32_t))
    {
        status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    key = *(uint32_t*)request->key;

    KeAcquireSpinLock(&gMapLock, &irql);
    // TODO: Switch this to use real object manager handles
    map = EbpfCoreFindMapEntry(request->handle);
    if (map)
    {
        // Compute offset into data.
        status = RtlSizeTMult(key, map->map.value_size, &value_offset);
        status = key < map->map.max_entries ? status : STATUS_INVALID_PARAMETER;
        status = (reply->header.length - sizeof(struct EbpfOpMapLookupElementReply) + 1) == (map->map.value_size) ? status : STATUS_INVALID_PARAMETER;

        if (status == STATUS_SUCCESS)
        {
            memcpy(reply->value, map->map.data + value_offset, map->map.value_size);
        }
    }
    KeReleaseSpinLock(&gMapLock, irql);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: EbpfCoreProtocolMapLookupElement 0x%llx handle\n", request->handle));

Done:
    return status;
}

NTSTATUS EbpfCoreProtocolMapUpdateElement(
    _In_ struct EpfOpMapUpdateElementRequest* request,
    _Inout_ void* reply)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL irql;
    EbpfCoreMapEntry* map = NULL;
    uint32_t key;
    SIZE_T value_offset = 0;

    UNREFERENCED_PARAMETER(reply);

    KeAcquireSpinLock(&gMapLock, &irql);
    // TODO: Switch this to use real object manager handles
    map = EbpfCoreFindMapEntry(request->handle);
    if (map)
    {
        // Is the request big enough to contain both key + value?
        status = (request->header.length - sizeof(struct EpfOpMapUpdateElementRequest) + 1) == ((size_t)map->map.key_size + (size_t)map->map.value_size) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;

        // If success, then extract key
        key = (status == STATUS_SUCCESS) ? *(uint32_t*)request->data : 0;

        // If success, check if key is in range
        status = (status == STATUS_SUCCESS) ? key < map->map.max_entries ? status : STATUS_INVALID_PARAMETER : status;

        // If success, then compute value offset
        status = (status == STATUS_SUCCESS) ? RtlSizeTMult(key, map->map.value_size, &value_offset) : status;

        if (status == STATUS_SUCCESS)
        {
            memcpy(map->map.data + value_offset, request->data + sizeof(uint32_t), map->map.value_size);
        }
    }
    KeReleaseSpinLock(&gMapLock, irql);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: EbpfCoreProtocolMapLookupElement 0x%llx handle\n", request->handle));

    return status;
}

NTSTATUS EbpfCoreProtocolMapDeleteElement(
    _In_ struct EbpfOpMapDeleteElementRequest* request,
    _Inout_ void* reply)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL irql;
    EbpfCoreMapEntry* map = NULL;
    uint32_t key;
    SIZE_T value_offset = 0;
    UNREFERENCED_PARAMETER(reply);

    KeAcquireSpinLock(&gMapLock, &irql);
    // TODO: Switch this to use real object manager handles
    map = EbpfCoreFindMapEntry(request->handle);
    if (map)
    {
        // Is the request big enough to contain both key + value?
        status = (request->header.length - sizeof(struct EpfOpMapUpdateElementRequest) + 1) == map->map.key_size ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;

        // If success, then extract key
        key = (status == STATUS_SUCCESS) ? *(uint32_t*)request->key : 0;

        // If success, check if key is in range
        status = (status == STATUS_SUCCESS) ? key < map->map.max_entries ? status : STATUS_INVALID_PARAMETER : status;

        // If success, then compute value offset
        status = (status == STATUS_SUCCESS) ? RtlSizeTMult(key, map->map.value_size, &value_offset) : status;

        if (status == STATUS_SUCCESS)
        {
            memset(map->map.data + value_offset, 0, map->map.value_size);
        }
    }
    KeReleaseSpinLock(&gMapLock, irql);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "EbpfCore: EbpfCoreProtocolMapLookupElement 0x%llx handle\n", request->handle));

    return status;
}

// EBPF helper functions
void* EbpfCoreMapLookupElement(EbpfCoreMap* map, uint32_t* key)
{
    if (!map || !key)
        return NULL;

    if (*key > map->max_entries)
        return NULL;

    return &map->data[*key * map->value_size];
}

void EbpfCoreMapUpdateElement(EbpfCoreMap* map, uint32_t* key, uint8_t* data)
{
    if (!map || !key)
        return;

    if (*key > map->max_entries)
        return;

    uint8_t* entry = &map->data[*key * map->value_size];
    memcpy(entry, data, map->value_size);
}

void EbpfCoreMapDeleteElement(EbpfCoreMap* map, uint32_t* key)
{
    if (!map || !key)
        return;

    if (*key > map->max_entries)
        return;

    uint8_t* entry = &map->data[*key * map->value_size];
    memset(entry, 0, map->value_size);
}
