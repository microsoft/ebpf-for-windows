// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

/*++

Abstract:
WDF based driver that does the following:
1. Registers a set of WFP callouts.
2. Registers as an eBPF program information provider and hook provider.

Environment:

    Kernel mode

--*/

// ntddk.h needs to be included first due to inter header dependencies on Windows.
#include <ntddk.h>

#pragma warning(push)
#pragma warning(disable : 4201) // unnamed struct/union
#include <fwpmk.h>
#include <fwpsk.h>
#pragma warning(pop)
#include <netiodef.h>
#include <wdf.h>

#include "ebpf_platform.h"
#include "ebpf_store_helper.h"
#include "net_ebpf_ext.h"

#define NET_EBPF_EXT_DEVICE_NAME L"\\Device\\NetEbpfExt"

// Driver global variables
static WDFDEVICE _net_ebpf_ext_device = NULL;
static BOOLEAN _net_ebpf_ext_driver_unloading_flag = FALSE;
DEVICE_OBJECT* _net_ebpf_ext_driver_device_object;

//
// Pre-Declarations
//
DRIVER_INITIALIZE DriverEntry;

static void
_net_ebpf_ext_driver_uninitialize_objects()
{
    _net_ebpf_ext_driver_unloading_flag = TRUE;

    net_ebpf_ext_unregister_providers();

    net_ebpf_extension_uninitialize_wfp_components();

    net_ebpf_ext_uninitialize_ndis_handles();

    net_ebpf_ext_trace_terminate();

    if (_net_ebpf_ext_device != NULL)
        WdfObjectDelete(_net_ebpf_ext_device);
}

static _Function_class_(EVT_WDF_DRIVER_UNLOAD) _IRQL_requires_same_
    _IRQL_requires_max_(PASSIVE_LEVEL) void _net_ebpf_ext_driver_unload(_In_ WDFDRIVER driver_object)
{
    UNREFERENCED_PARAMETER(driver_object);
    _net_ebpf_ext_driver_uninitialize_objects();
}

//
// Create and initialize WDF driver, device object,
// WFP callouts and NPI providers.
//
static NTSTATUS
_net_ebpf_ext_driver_initialize_objects(_Inout_ DRIVER_OBJECT* driver_object, _In_ const UNICODE_STRING* registry_path)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG driver_configuration;
    PWDFDEVICE_INIT device_initialize = NULL;
    UNICODE_STRING ebpf_device_name;
    WDFDRIVER driver;

    WDF_DRIVER_CONFIG_INIT(&driver_configuration, WDF_NO_EVENT_CALLBACK);

    driver_configuration.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    driver_configuration.EvtDriverUnload = _net_ebpf_ext_driver_unload;

    status = WdfDriverCreate(driver_object, registry_path, WDF_NO_OBJECT_ATTRIBUTES, &driver_configuration, &driver);

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    device_initialize = WdfControlDeviceInitAllocate(
        driver,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL // only kernel/system and administrators.
    );
    if (!device_initialize) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    WdfDeviceInitSetDeviceType(device_initialize, FILE_DEVICE_NETWORK);

    WdfDeviceInitSetCharacteristics(device_initialize, FILE_DEVICE_SECURE_OPEN, FALSE);

    WdfDeviceInitSetCharacteristics(device_initialize, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);

    RtlInitUnicodeString(&ebpf_device_name, NET_EBPF_EXT_DEVICE_NAME);
    status = WdfDeviceInitAssignName(device_initialize, &ebpf_device_name);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = WdfDeviceCreate(&device_initialize, WDF_NO_OBJECT_ATTRIBUTES, &_net_ebpf_ext_device);

    if (!NT_SUCCESS(status)) {
        // do not free if any other call
        // after WdfDeviceCreate fails.
        WdfDeviceInitFree(device_initialize);
        device_initialize = NULL;
        goto Exit;
    }

    _net_ebpf_ext_driver_device_object = WdfDeviceWdmGetDeviceObject(_net_ebpf_ext_device);

    status = net_ebpf_ext_initialize_ndis_handles((const DRIVER_OBJECT*)driver_object);
    if (!NT_SUCCESS(status))
        goto Exit;

    status = net_ebpf_ext_register_providers();
    if (!NT_SUCCESS(status))
        goto Exit;

    // TODO: https://github.com/microsoft/ebpf-for-windows/issues/521
    (void)net_ebpf_extension_initialize_wfp_components(_net_ebpf_ext_driver_device_object);

    WdfControlFinishInitializing(_net_ebpf_ext_device);

Exit:
    return status;
}

NTSTATUS
DriverEntry(_In_ DRIVER_OBJECT* driver_object, _In_ UNICODE_STRING* registry_path)
{
    NTSTATUS status;

    status = net_ebpf_ext_trace_initiate();
    if (!NT_SUCCESS(status)) {
        // Fail silently as there is no other mechanism to indicate this failure. Note that in this case, the
        // NET_EBPF_EXT_LOG_EXIT() call at the end will not log anything either.
        goto Exit;
    }

    NET_EBPF_EXT_LOG_ENTRY();

    // Request NX Non-Paged Pool when available
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    status = _net_ebpf_ext_driver_initialize_objects(driver_object, registry_path);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_CRITICAL,
            NET_EBPF_EXT_TRACELOG_KEYWORD_BASE,
            (char*)"_net_ebpf_ext_driver_initialize_objects() failed",
            status);
        goto Exit;
    }

Exit:
    if (!NT_SUCCESS(status)) {
        _net_ebpf_ext_driver_uninitialize_objects();
    }

    NET_EBPF_EXT_LOG_EXIT();
    return status;
}
