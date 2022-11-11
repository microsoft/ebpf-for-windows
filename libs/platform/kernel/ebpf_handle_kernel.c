// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_handle.h"
#include "framework.h"

extern DEVICE_OBJECT*
ebpf_driver_get_device_object();

_Must_inspect_result_ ebpf_result_t
ebpf_handle_table_initiate()
{
    return EBPF_SUCCESS;
}

void
ebpf_handle_table_terminate()
{}

_Must_inspect_result_ ebpf_result_t
ebpf_handle_create(ebpf_handle_t* handle, ebpf_core_object_t* object)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t return_value;
    HANDLE file_handle = 0;
    OBJECT_ATTRIBUTES object_attributes;
    UNICODE_STRING object_name;
    IO_STATUS_BLOCK io_status_block;
    NTSTATUS status;
    FILE_OBJECT* file_object = NULL;

    RtlInitUnicodeString(&object_name, EBPF_SYMBOLIC_DEVICE_NAME);

    InitializeObjectAttributes(&object_attributes, &object_name, 0, NULL, NULL);

    status = ZwCreateFile(
        &file_handle,
        GENERIC_READ | GENERIC_WRITE,
        &object_attributes,
        &io_status_block,
        NULL,
        0,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0);

    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, ZwCreateFile, status);
        return_value = EBPF_OPERATION_NOT_SUPPORTED;
        goto Done;
    }

    status = ObReferenceObjectByHandle(file_handle, 0, NULL, UserMode, &file_object, NULL);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, ObReferenceObjectByHandle, status);
        return_value = EBPF_OPERATION_NOT_SUPPORTED;
        goto Done;
    }

    ebpf_object_acquire_reference(object);
    file_object->FsContext2 = object;

    *handle = (ebpf_handle_t)file_handle;
    file_handle = 0;
    return_value = EBPF_SUCCESS;
Done:
    if (file_object)
        ObDereferenceObject(file_object);

    if (file_handle)
        ObCloseHandle(file_handle, UserMode);

    EBPF_RETURN_RESULT(return_value);
}

_Must_inspect_result_ ebpf_result_t
ebpf_handle_close(ebpf_handle_t handle)
{
    EBPF_LOG_ENTRY();
    NTSTATUS status = ObCloseHandle((HANDLE)handle, UserMode);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, ObCloseHandle, status);
        EBPF_RETURN_RESULT(EBPF_INVALID_OBJECT);
    } else
        EBPF_RETURN_RESULT(EBPF_SUCCESS);
}

_IRQL_requires_max_(PASSIVE_LEVEL) ebpf_result_t ebpf_reference_object_by_handle(
    ebpf_handle_t handle, ebpf_object_type_t object_type, _Outptr_ ebpf_core_object_t** object)
{
    ebpf_result_t return_value;
    NTSTATUS status;
    FILE_OBJECT* file_object = NULL;
    ebpf_core_object_t* local_object;

    status = ObReferenceObjectByHandle((HANDLE)handle, 0, NULL, UserMode, &file_object, NULL);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_BASE, ObReferenceObjectByHandle, status);
        return_value = EBPF_INVALID_OBJECT;
        goto Done;
    }

    if (file_object->DeviceObject != ebpf_driver_get_device_object()) {
        return_value = EBPF_INVALID_OBJECT;
        goto Done;
    }

    local_object = (ebpf_core_object_t*)file_object->FsContext2;
    if (local_object == NULL) {
        return_value = EBPF_INVALID_OBJECT;
        goto Done;
    }

    if ((object_type != EBPF_OBJECT_UNKNOWN) && (ebpf_object_get_type(local_object) != object_type)) {
        return_value = EBPF_INVALID_OBJECT;
        goto Done;
    }

    ebpf_object_acquire_reference(local_object);
    *object = local_object;
    return_value = EBPF_SUCCESS;

Done:
    if (file_object)
        ObDereferenceObject(file_object);
    return return_value;
}

_Must_inspect_result_ ebpf_result_t
ebpf_get_next_handle_by_type(ebpf_handle_t previous_handle, ebpf_object_type_t object_type, ebpf_handle_t* next_handle)
{
    UNREFERENCED_PARAMETER(previous_handle);
    UNREFERENCED_PARAMETER(object_type);
    UNREFERENCED_PARAMETER(next_handle);
    return EBPF_OPERATION_NOT_SUPPORTED;
}
