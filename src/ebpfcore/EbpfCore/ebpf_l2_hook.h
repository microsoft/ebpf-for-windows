/*++

Copyright (c) Microsoft Corporation. All rights reserved

Abstract:

   Header file for structures/prototypes of the driver.


Environment:

    Kernel mode

--*/

#ifndef _EBPF_L2HOOK_H_
#define _EBPF_L2HOOK_H_

// Externs
extern UINT32 gL2CalloutId;
extern BOOLEAN gDriverUnloading;

//
// Shared function prototypes
//

NTSTATUS
EbpfHookRegisterCallouts(
    _Inout_ void* deviceObject
);

void
EbpfHookUnregisterCallouts(void);

void
EbpfHookL2Classify(
   _In_ const FWPS_INCOMING_VALUES* inFixedValues,
   _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   _Inout_opt_ void* layerData,
   _In_opt_ const void* classifyContext,
   _In_ const FWPS_FILTER* filter,
   _In_ UINT64 flowContext,
   _Inout_ FWPS_CLASSIFY_OUT* classifyOut
   );

void
EbpfHookL2FlowDelete(
   _In_ UINT16 layerId,
   _In_ UINT32 calloutId,
   _In_ UINT64 flowContext
   );

NTSTATUS
EbpfHookL2Notify(
   _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
   _In_ const GUID* filterKey,
   _Inout_ const FWPS_FILTER* filter
   );

#endif // _EBPF_L2HOOK_H_
