// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * WDF based driver that does the following:
 * 1. Initializes the eBPF execution context.
 * 2. Opens an IOCTL surface that forwards commands to ebpf_core.
 */

#include "ebpf_core.h"
#include "ebpf_error.h"
#include "ebpf_tracelog.h"
#include "ebpf_version.h"
#include "git_commit_id.h"

#pragma warning(push)
#pragma warning(disable : 4062) // enumerator 'identifier' in switch of enum 'enumeration' is not handled
#include <wdf.h>
#pragma warning(pop)

// Driver global variables
static DEVICE_OBJECT* _ebpf_driver_device_object;
static BOOLEAN _ebpf_driver_unloading_flag = FALSE;
static const ULONG _ebpfsvc_sid_subauthorities[] = {
    SECURITY_SERVICE_ID_BASE_RID, 3453964624, 2861012444, 1105579853, 3193141192, 1897355174};

// SID for ebpfsvc (generated using command "sc.exe showsid ebpfsvc"):
// S-1-5-80-3453964624-2861012444-1105579853-3193141192-1897355174
//
// SDDL_DEVOBJ_SYS_ALL_ADM_ALL + LocalService + SID for ebpfsvc.
#define EBPF_EXECUTION_CONTEXT_DEVICE_SDDL                                                                           \
    L"D:P(A;;GA;;;S-1-5-80-3453964624-2861012444-1105579853-3193141192-1897355174)(A;;GA;;;LS)(A;;GA;;;BA)(A;;GA;;;" \
    L"SY)"

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif
// Device type
#define EBPF_IOCTL_TYPE FILE_DEVICE_NETWORK

// Function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_EBPF_CTL_METHOD_BUFFERED CTL_CODE(EBPF_IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define EBPF_EXECUTION_CONTEXT_PRIVILEGED_ACCESS ((ACCESS_MASK)0x1)

const char ebpf_core_version[] = EBPF_VERSION " " GIT_COMMIT_ID;

PSECURITY_DESCRIPTOR ebpf_execution_context_privileged_security_descriptor = NULL;

//
// Pre-Declarations
//
static EVT_WDF_FILE_CLOSE _ebpf_driver_file_close;
static EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL _ebpf_driver_io_device_control;
static EVT_WDFDEVICE_WDM_IRP_PREPROCESS _ebpf_driver_query_volume_information;
static EVT_WDF_REQUEST_CANCEL _ebpf_driver_io_device_control_cancel;
DRIVER_INITIALIZE DriverEntry;

static VOID
_ebpf_driver_io_device_control(
    _In_ WDFQUEUE queue,
    _In_ WDFREQUEST request,
    size_t output_buffer_length,
    size_t input_buffer_length,
    unsigned long io_control_code);

static _Must_inspect_result_ NTSTATUS
_ebpf_driver_initialize_local_service_sid(_Out_ PSID sid)
{
    const SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    NTSTATUS status = RtlInitializeSid(sid, (SID_IDENTIFIER_AUTHORITY*)&nt_authority, 1);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlInitializeSid, status);
        return status;
    }

    *RtlSubAuthoritySid(sid, 0) = SECURITY_LOCAL_SERVICE_RID;
    return STATUS_SUCCESS;
}

static _Must_inspect_result_ NTSTATUS
_ebpf_driver_initialize_builtin_admin_sid(_Out_ PSID sid)
{
    const SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    NTSTATUS status = RtlInitializeSid(sid, (SID_IDENTIFIER_AUTHORITY*)&nt_authority, 2);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlInitializeSid, status);
        return status;
    }

    *RtlSubAuthoritySid(sid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
    *RtlSubAuthoritySid(sid, 1) = DOMAIN_ALIAS_RID_ADMINS;
    return STATUS_SUCCESS;
}

static _Must_inspect_result_ NTSTATUS
_ebpf_driver_initialize_local_system_sid(_Out_ PSID sid)
{
    const SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    NTSTATUS status = RtlInitializeSid(sid, (SID_IDENTIFIER_AUTHORITY*)&nt_authority, 1);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlInitializeSid, status);
        return status;
    }

    *RtlSubAuthoritySid(sid, 0) = SECURITY_LOCAL_SYSTEM_RID;
    return STATUS_SUCCESS;
}

static _Must_inspect_result_ NTSTATUS
_ebpf_driver_initialize_ebpfsvc_sid(_Out_ PSID sid)
{
    const SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    NTSTATUS status =
        RtlInitializeSid(sid, (SID_IDENTIFIER_AUTHORITY*)&nt_authority, EBPF_COUNT_OF(_ebpfsvc_sid_subauthorities));
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlInitializeSid, status);
        return status;
    }

    for (ULONG i = 0; i < EBPF_COUNT_OF(_ebpfsvc_sid_subauthorities); i++) {
        *RtlSubAuthoritySid(sid, i) = _ebpfsvc_sid_subauthorities[i];
    }

    return STATUS_SUCCESS;
}

static void
_ebpf_driver_find_group_sid_attributes(
    _In_opt_ TOKEN_GROUPS* groups, _In_ PSID sid, _Out_ BOOLEAN* present, _Out_ ULONG* attributes)
{
    *present = FALSE;
    *attributes = 0;

    if (groups == NULL) {
        return;
    }

    for (ULONG i = 0; i < groups->GroupCount; i++) {
        if (RtlEqualSid(groups->Groups[i].Sid, sid)) {
            *present = TRUE;
            *attributes = groups->Groups[i].Attributes;
            break;
        }
    }
}

typedef struct _ebpf_privileged_access_check_trace_state
{
    ebpf_operation_id_t operation_id;
    ACCESS_MASK desired_access;
    ACCESS_MASK granted_access;
    NTSTATUS access_check_status;
    NTSTATUS token_user_status;
    NTSTATUS token_groups_status;
    NTSTATUS token_restricted_sids_status;
    ULONG group_count;
    ULONG restricted_sid_count;
    ULONG local_service_attributes;
    ULONG local_service_restricted_attributes;
    ULONG ebpfsvc_attributes;
    ULONG ebpfsvc_restricted_attributes;
    BOOLEAN access_check_result;
    BOOLEAN access_granted;
    BOOLEAN local_service_present;
    BOOLEAN local_service_restricted_present;
    BOOLEAN ebpfsvc_present;
    BOOLEAN ebpfsvc_restricted_present;
} ebpf_privileged_access_check_trace_state_t;

static void
_ebpf_driver_trace_privileged_access_check_with_sid(
    _In_ const ebpf_privileged_access_check_trace_state_t* trace_state, _In_ PSID user_sid);

static void
_ebpf_driver_trace_privileged_access_check_without_sid(
    _In_ const ebpf_privileged_access_check_trace_state_t* trace_state);

static void
_ebpf_driver_trace_privileged_access_check_with_sid(
    _In_ const ebpf_privileged_access_check_trace_state_t* trace_state, _In_ PSID user_sid)
{
    if (trace_state->access_granted) {
        TraceLoggingWrite(
            ebpf_tracelog_provider,
            "EbpfPrivilegedAccessCheck",
            TraceLoggingLevel(WINEVENT_LEVEL_INFO),
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_CORE),
            TraceLoggingUInt32((uint32_t)trace_state->operation_id, "OperationId"),
            TraceLoggingUInt32((uint32_t)trace_state->desired_access, "DesiredAccess"),
            TraceLoggingUInt32((uint32_t)trace_state->granted_access, "GrantedAccess"),
            TraceLoggingBool(!!trace_state->access_check_result, "SeAccessCheckResult"),
            TraceLoggingNTStatus(trace_state->access_check_status, "AccessStatus"),
            TraceLoggingSid(user_sid, "UserSid"),
            TraceLoggingUInt32(trace_state->group_count, "GroupCount"),
            TraceLoggingNTStatus(trace_state->token_groups_status, "TokenGroupsStatus"),
            TraceLoggingBool(!!trace_state->local_service_present, "LocalServicePresent"),
            TraceLoggingUInt32(trace_state->local_service_attributes, "LocalServiceAttributes"),
            TraceLoggingBool(!!trace_state->ebpfsvc_present, "EbpfSvcSidPresent"),
            TraceLoggingUInt32(trace_state->ebpfsvc_attributes, "EbpfSvcSidAttributes"),
            TraceLoggingUInt32(trace_state->restricted_sid_count, "RestrictedSidCount"),
            TraceLoggingNTStatus(trace_state->token_restricted_sids_status, "RestrictedSidsStatus"),
            TraceLoggingBool(!!trace_state->local_service_restricted_present, "LocalServiceRestrictedPresent"),
            TraceLoggingUInt32(trace_state->local_service_restricted_attributes, "LocalServiceRestrictedAttributes"),
            TraceLoggingBool(!!trace_state->ebpfsvc_restricted_present, "EbpfSvcSidRestrictedPresent"),
            TraceLoggingUInt32(trace_state->ebpfsvc_restricted_attributes, "EbpfSvcSidRestrictedAttributes"));
    } else {
        TraceLoggingWrite(
            ebpf_tracelog_provider,
            "EbpfPrivilegedAccessCheck",
            TraceLoggingLevel(WINEVENT_LEVEL_ERROR),
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_CORE | EBPF_TRACELOG_KEYWORD_ERROR),
            TraceLoggingUInt32((uint32_t)trace_state->operation_id, "OperationId"),
            TraceLoggingUInt32((uint32_t)trace_state->desired_access, "DesiredAccess"),
            TraceLoggingUInt32((uint32_t)trace_state->granted_access, "GrantedAccess"),
            TraceLoggingBool(!!trace_state->access_check_result, "SeAccessCheckResult"),
            TraceLoggingNTStatus(trace_state->access_check_status, "AccessStatus"),
            TraceLoggingSid(user_sid, "UserSid"),
            TraceLoggingUInt32(trace_state->group_count, "GroupCount"),
            TraceLoggingNTStatus(trace_state->token_groups_status, "TokenGroupsStatus"),
            TraceLoggingBool(!!trace_state->local_service_present, "LocalServicePresent"),
            TraceLoggingUInt32(trace_state->local_service_attributes, "LocalServiceAttributes"),
            TraceLoggingBool(!!trace_state->ebpfsvc_present, "EbpfSvcSidPresent"),
            TraceLoggingUInt32(trace_state->ebpfsvc_attributes, "EbpfSvcSidAttributes"),
            TraceLoggingUInt32(trace_state->restricted_sid_count, "RestrictedSidCount"),
            TraceLoggingNTStatus(trace_state->token_restricted_sids_status, "RestrictedSidsStatus"),
            TraceLoggingBool(!!trace_state->local_service_restricted_present, "LocalServiceRestrictedPresent"),
            TraceLoggingUInt32(trace_state->local_service_restricted_attributes, "LocalServiceRestrictedAttributes"),
            TraceLoggingBool(!!trace_state->ebpfsvc_restricted_present, "EbpfSvcSidRestrictedPresent"),
            TraceLoggingUInt32(trace_state->ebpfsvc_restricted_attributes, "EbpfSvcSidRestrictedAttributes"));
    }
}

static void
_ebpf_driver_trace_privileged_access_check_without_sid(
    _In_ const ebpf_privileged_access_check_trace_state_t* trace_state)
{
    if (trace_state->access_granted) {
        TraceLoggingWrite(
            ebpf_tracelog_provider,
            "EbpfPrivilegedAccessCheck",
            TraceLoggingLevel(WINEVENT_LEVEL_INFO),
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_CORE),
            TraceLoggingUInt32((uint32_t)trace_state->operation_id, "OperationId"),
            TraceLoggingUInt32((uint32_t)trace_state->desired_access, "DesiredAccess"),
            TraceLoggingUInt32((uint32_t)trace_state->granted_access, "GrantedAccess"),
            TraceLoggingBool(!!trace_state->access_check_result, "SeAccessCheckResult"),
            TraceLoggingNTStatus(trace_state->access_check_status, "AccessStatus"),
            TraceLoggingNTStatus(trace_state->token_user_status, "TokenUserStatus"),
            TraceLoggingUInt32(trace_state->group_count, "GroupCount"),
            TraceLoggingNTStatus(trace_state->token_groups_status, "TokenGroupsStatus"),
            TraceLoggingBool(!!trace_state->local_service_present, "LocalServicePresent"),
            TraceLoggingUInt32(trace_state->local_service_attributes, "LocalServiceAttributes"),
            TraceLoggingBool(!!trace_state->ebpfsvc_present, "EbpfSvcSidPresent"),
            TraceLoggingUInt32(trace_state->ebpfsvc_attributes, "EbpfSvcSidAttributes"),
            TraceLoggingUInt32(trace_state->restricted_sid_count, "RestrictedSidCount"),
            TraceLoggingNTStatus(trace_state->token_restricted_sids_status, "RestrictedSidsStatus"),
            TraceLoggingBool(!!trace_state->local_service_restricted_present, "LocalServiceRestrictedPresent"),
            TraceLoggingUInt32(trace_state->local_service_restricted_attributes, "LocalServiceRestrictedAttributes"),
            TraceLoggingBool(!!trace_state->ebpfsvc_restricted_present, "EbpfSvcSidRestrictedPresent"),
            TraceLoggingUInt32(trace_state->ebpfsvc_restricted_attributes, "EbpfSvcSidRestrictedAttributes"));
    } else {
        TraceLoggingWrite(
            ebpf_tracelog_provider,
            "EbpfPrivilegedAccessCheck",
            TraceLoggingLevel(WINEVENT_LEVEL_ERROR),
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_CORE | EBPF_TRACELOG_KEYWORD_ERROR),
            TraceLoggingUInt32((uint32_t)trace_state->operation_id, "OperationId"),
            TraceLoggingUInt32((uint32_t)trace_state->desired_access, "DesiredAccess"),
            TraceLoggingUInt32((uint32_t)trace_state->granted_access, "GrantedAccess"),
            TraceLoggingBool(!!trace_state->access_check_result, "SeAccessCheckResult"),
            TraceLoggingNTStatus(trace_state->access_check_status, "AccessStatus"),
            TraceLoggingNTStatus(trace_state->token_user_status, "TokenUserStatus"),
            TraceLoggingUInt32(trace_state->group_count, "GroupCount"),
            TraceLoggingNTStatus(trace_state->token_groups_status, "TokenGroupsStatus"),
            TraceLoggingBool(!!trace_state->local_service_present, "LocalServicePresent"),
            TraceLoggingUInt32(trace_state->local_service_attributes, "LocalServiceAttributes"),
            TraceLoggingBool(!!trace_state->ebpfsvc_present, "EbpfSvcSidPresent"),
            TraceLoggingUInt32(trace_state->ebpfsvc_attributes, "EbpfSvcSidAttributes"),
            TraceLoggingUInt32(trace_state->restricted_sid_count, "RestrictedSidCount"),
            TraceLoggingNTStatus(trace_state->token_restricted_sids_status, "RestrictedSidsStatus"),
            TraceLoggingBool(!!trace_state->local_service_restricted_present, "LocalServiceRestrictedPresent"),
            TraceLoggingUInt32(trace_state->local_service_restricted_attributes, "LocalServiceRestrictedAttributes"),
            TraceLoggingBool(!!trace_state->ebpfsvc_restricted_present, "EbpfSvcSidRestrictedPresent"),
            TraceLoggingUInt32(trace_state->ebpfsvc_restricted_attributes, "EbpfSvcSidRestrictedAttributes"));
    }
}

static void
_ebpf_driver_trace_privileged_access_check(
    _In_ SECURITY_SUBJECT_CONTEXT* subject_context,
    ebpf_operation_id_t operation_id,
    ACCESS_MASK desired_access,
    ACCESS_MASK granted_access,
    BOOLEAN access_check_result,
    NTSTATUS access_check_status)
{
    PACCESS_TOKEN access_token = NULL;
    PTOKEN_USER token_user = NULL;
    PTOKEN_GROUPS token_groups = NULL;
    PTOKEN_GROUPS token_restricted_sids = NULL;
    ebpf_privileged_access_check_trace_state_t trace_state = {
        .operation_id = operation_id,
        .desired_access = desired_access,
        .granted_access = granted_access,
        .access_check_status = access_check_status,
        .token_user_status = STATUS_NOT_FOUND,
        .token_groups_status = STATUS_NOT_FOUND,
        .token_restricted_sids_status = STATUS_NOT_FOUND,
        .access_check_result = access_check_result,
        .access_granted = access_check_result && NT_SUCCESS(access_check_status),
    };
    BOOLEAN enabled;
    struct
    {
        SID sid;
        ULONG sub_authority[1];
    } local_service_sid = {0};
    struct
    {
        SID sid;
        ULONG sub_authority[EBPF_COUNT_OF(_ebpfsvc_sid_subauthorities)];
    } ebpfsvc_sid = {0};

    enabled =
        trace_state.access_granted
            ? TraceLoggingProviderEnabled(ebpf_tracelog_provider, EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_CORE)
            : TraceLoggingProviderEnabled(
                  ebpf_tracelog_provider,
                  EBPF_TRACELOG_LEVEL_ERROR,
                  EBPF_TRACELOG_KEYWORD_CORE | EBPF_TRACELOG_KEYWORD_ERROR);
    if (!enabled) {
        return;
    }

    if (!NT_SUCCESS(_ebpf_driver_initialize_local_service_sid((PSID)&local_service_sid)) ||
        !NT_SUCCESS(_ebpf_driver_initialize_ebpfsvc_sid((PSID)&ebpfsvc_sid))) {
        return;
    }

    access_token = SeQuerySubjectContextToken(subject_context);
    if (access_token != NULL) {
        trace_state.token_user_status = SeQueryInformationToken(access_token, TokenUser, (void**)&token_user);
        trace_state.token_groups_status = SeQueryInformationToken(access_token, TokenGroups, (void**)&token_groups);
        trace_state.token_restricted_sids_status =
            SeQueryInformationToken(access_token, TokenRestrictedSids, (void**)&token_restricted_sids);
    } else {
        trace_state.token_user_status = STATUS_NO_TOKEN;
        trace_state.token_groups_status = STATUS_NO_TOKEN;
        trace_state.token_restricted_sids_status = STATUS_NO_TOKEN;
    }

    if (NT_SUCCESS(trace_state.token_groups_status)) {
        trace_state.group_count = token_groups->GroupCount;
        _ebpf_driver_find_group_sid_attributes(
            token_groups,
            (PSID)&local_service_sid,
            &trace_state.local_service_present,
            &trace_state.local_service_attributes);
        _ebpf_driver_find_group_sid_attributes(
            token_groups, (PSID)&ebpfsvc_sid, &trace_state.ebpfsvc_present, &trace_state.ebpfsvc_attributes);
    }

    if (NT_SUCCESS(trace_state.token_restricted_sids_status)) {
        trace_state.restricted_sid_count = token_restricted_sids->GroupCount;
        _ebpf_driver_find_group_sid_attributes(
            token_restricted_sids,
            (PSID)&local_service_sid,
            &trace_state.local_service_restricted_present,
            &trace_state.local_service_restricted_attributes);
        _ebpf_driver_find_group_sid_attributes(
            token_restricted_sids,
            (PSID)&ebpfsvc_sid,
            &trace_state.ebpfsvc_restricted_present,
            &trace_state.ebpfsvc_restricted_attributes);
    }

    if (NT_SUCCESS(trace_state.token_user_status)) {
        _ebpf_driver_trace_privileged_access_check_with_sid(&trace_state, token_user->User.Sid);
    } else {
        _ebpf_driver_trace_privileged_access_check_without_sid(&trace_state);
    }

    if (token_user != NULL) {
        ExFreePool(token_user);
    }

    if (token_groups != NULL) {
        ExFreePool(token_groups);
    }

    if (token_restricted_sids != NULL) {
        ExFreePool(token_restricted_sids);
    }
}

static _Function_class_(EVT_WDF_DRIVER_UNLOAD) _IRQL_requires_same_
    _IRQL_requires_max_(PASSIVE_LEVEL) void _ebpf_driver_unload(_In_ WDFDRIVER driver_object)
{
    UNREFERENCED_PARAMETER(driver_object);

    _ebpf_driver_unloading_flag = TRUE;

    if (ebpf_execution_context_privileged_security_descriptor) {
        ebpf_free(ebpf_execution_context_privileged_security_descriptor);
        ebpf_execution_context_privileged_security_descriptor = NULL;
    }

    ebpf_core_terminate();
}

static _Check_return_ NTSTATUS
_ebpf_driver_build_privileged_security_descriptor()
{
    PACL dacl = NULL;
    PSID ebpfsvc_sid = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    SECURITY_DESCRIPTOR security_descriptor;
    PSECURITY_DESCRIPTOR self_relative_security_descriptor = NULL;
    const ULONG subauthority_count = EBPF_COUNT_OF(_ebpfsvc_sid_subauthorities);
    ULONG security_descriptor_size = 0;

    // Well-known SIDs for LocalService (LS), Administrators (BA), and SYSTEM (SY).
    struct
    { // Stack-allocated SID for LS.
        SID sid;
        ULONG sub_authority[1];
    } local_service_sid_buf = {0};
    struct
    { // Stack-allocated SID for BA.
        SID sid;
        ULONG sub_authority[2];
    } admin_sid_buf = {0};
    struct
    { // Stack-allocated SID for SY.
        SID sid;
        ULONG sub_authority[1];
    } system_sid_buf = {0};
    PSID local_service_sid = (PSID)&local_service_sid_buf;
    PSID admin_sid = (PSID)&admin_sid_buf;
    PSID system_sid = (PSID)&system_sid_buf;

    // Build S-1-5-19 (LOCAL SERVICE).
    status = _ebpf_driver_initialize_local_service_sid(local_service_sid);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Build S-1-5-32-544 (BUILTIN\Administrators).
    status = _ebpf_driver_initialize_builtin_admin_sid(admin_sid);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Build S-1-5-18 (SYSTEM).
    status = _ebpf_driver_initialize_local_system_sid(system_sid);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    // Build the ebpfsvc service SID.
    ebpfsvc_sid = (PSID)ebpf_allocate_with_tag(RtlLengthRequiredSid(subauthority_count), 'fpBE');
    if (ebpfsvc_sid == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, ebpf_allocate_with_tag, status);
        goto Exit;
    }

    status = _ebpf_driver_initialize_ebpfsvc_sid(ebpfsvc_sid);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = RtlCreateSecurityDescriptor(&security_descriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlCreateSecurityDescriptor, status);
        goto Exit;
    }

#if !defined(USERSIM_DLLMAIN)
    // Set the owner to Administrators.
    status = RtlSetOwnerSecurityDescriptor(&security_descriptor, admin_sid, FALSE);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlSetOwnerSecurityDescriptor, status);
        goto Exit;
    }

    // Set the group to SYSTEM.
    status = RtlSetGroupSecurityDescriptor(&security_descriptor, system_sid, FALSE);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlSetGroupSecurityDescriptor, status);
        goto Exit;
    }
#endif

    // Allocate DACL with four ACEs: ebpfsvc, LocalService, Administrators, SYSTEM.
    size_t acl_size = 0;
    size_t total_sid_length = 0;
    ebpf_result_t safe_result = EBPF_SUCCESS;
    ULONG aclSize = 0;
    safe_result = ebpf_safe_size_t_add(
        (size_t)RtlLengthSid(ebpfsvc_sid), (size_t)RtlLengthSid(local_service_sid), &total_sid_length);
    if (safe_result != EBPF_SUCCESS) {
        status = STATUS_INTEGER_OVERFLOW;
        goto Exit;
    }
    safe_result = ebpf_safe_size_t_add(total_sid_length, (size_t)RtlLengthSid(admin_sid), &total_sid_length);
    if (safe_result != EBPF_SUCCESS) {
        status = STATUS_INTEGER_OVERFLOW;
        goto Exit;
    }
    safe_result = ebpf_safe_size_t_add(total_sid_length, (size_t)RtlLengthSid(system_sid), &total_sid_length);
    if (safe_result != EBPF_SUCCESS) {
        status = STATUS_INTEGER_OVERFLOW;
        goto Exit;
    }
    safe_result = ebpf_safe_size_t_add(sizeof(ACL), (size_t)4 * sizeof(ACCESS_ALLOWED_ACE), &acl_size);
    if (safe_result != EBPF_SUCCESS) {
        status = STATUS_INTEGER_OVERFLOW;
        goto Exit;
    }
    safe_result = ebpf_safe_size_t_add(acl_size, total_sid_length, &acl_size);
    if (safe_result != EBPF_SUCCESS) {
        status = STATUS_INTEGER_OVERFLOW;
        goto Exit;
    }
    safe_result = ebpf_safe_size_t_subtract(acl_size, (size_t)4 * sizeof(ULONG), &acl_size);
    if (safe_result != EBPF_SUCCESS || acl_size > MAXULONG) {
        status = STATUS_INTEGER_OVERFLOW;
        goto Exit;
    }
    aclSize = (ULONG)acl_size;
    dacl = (PACL)ebpf_allocate_with_tag(aclSize, 'fpBE');
    if (dacl == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, ebpf_allocate_with_tag, status);
        goto Exit;
    }

    status = RtlCreateAcl(dacl, aclSize, ACL_REVISION);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlCreateAcl, status);
        goto Exit;
    }

    status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, EBPF_EXECUTION_CONTEXT_PRIVILEGED_ACCESS, ebpfsvc_sid);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlAddAccessAllowedAce, status);
        goto Exit;
    }

    status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, EBPF_EXECUTION_CONTEXT_PRIVILEGED_ACCESS, local_service_sid);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlAddAccessAllowedAce, status);
        goto Exit;
    }

    status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, EBPF_EXECUTION_CONTEXT_PRIVILEGED_ACCESS, admin_sid);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlAddAccessAllowedAce, status);
        goto Exit;
    }

    status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, EBPF_EXECUTION_CONTEXT_PRIVILEGED_ACCESS, system_sid);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlAddAccessAllowedAce, status);
        goto Exit;
    }

    // Set the DACL in the security descriptor.
    status = RtlSetDaclSecurityDescriptor(&security_descriptor, TRUE, dacl, FALSE);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlSetDaclSecurityDescriptor, status);
        goto Exit;
    }

#if defined(USERSIM_DLLMAIN)
    //
    // usersim does not implement the full kernel security descriptor helpers used to materialize a
    // self-relative descriptor. Build a stable absolute descriptor instead; usersim's access check
    // currently ignores the descriptor contents and only requires a persistent, non-NULL pointer.
    //
    security_descriptor_size = (ULONG)(sizeof(SECURITY_DESCRIPTOR) + aclSize);
    self_relative_security_descriptor = ebpf_allocate_with_tag(security_descriptor_size, 'fpBE');
    if (self_relative_security_descriptor == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, ebpf_allocate_with_tag, status);
        goto Exit;
    }

    RtlZeroMemory(self_relative_security_descriptor, security_descriptor_size);
    memcpy(self_relative_security_descriptor, &security_descriptor, sizeof(security_descriptor));

    ((SECURITY_DESCRIPTOR*)self_relative_security_descriptor)->Revision = SECURITY_DESCRIPTOR_REVISION;
    ((SECURITY_DESCRIPTOR*)self_relative_security_descriptor)->Control = SE_DACL_PRESENT;
    ((SECURITY_DESCRIPTOR*)self_relative_security_descriptor)->Dacl =
        (PACL)((uint8_t*)self_relative_security_descriptor + sizeof(SECURITY_DESCRIPTOR));
    memcpy(((SECURITY_DESCRIPTOR*)self_relative_security_descriptor)->Dacl, dacl, aclSize);
#else
    // Convert security descriptor to self-relative format.
    status = RtlAbsoluteToSelfRelativeSD(&security_descriptor, NULL, &security_descriptor_size);
    if (status != STATUS_BUFFER_TOO_SMALL) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlAbsoluteToSelfRelativeSD, status);
        goto Exit;
    }

    self_relative_security_descriptor = ebpf_allocate_with_tag(security_descriptor_size, 'fpBE');
    if (self_relative_security_descriptor == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, ebpf_allocate_with_tag, status);
        goto Exit;
    }

    status =
        RtlAbsoluteToSelfRelativeSD(&security_descriptor, self_relative_security_descriptor, &security_descriptor_size);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, RtlAbsoluteToSelfRelativeSD, status);
        goto Exit;
    }
#endif

    ebpf_execution_context_privileged_security_descriptor = self_relative_security_descriptor;
    self_relative_security_descriptor = NULL;

    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_CORE)) {
        TraceLoggingWrite(
            ebpf_tracelog_provider,
            "EbpfPrivilegedSecurityDescriptor",
            TraceLoggingLevel(WINEVENT_LEVEL_INFO),
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_CORE),
            TraceLoggingUInt32(security_descriptor_size, "SecurityDescriptorLength"),
            TraceLoggingUInt32(dacl->AceCount, "AceCount"),
            TraceLoggingSid(ebpfsvc_sid, "EbpfSvcSid"),
            TraceLoggingSid(local_service_sid, "LocalServiceSid"),
            TraceLoggingSid(admin_sid, "AdministratorsSid"),
            TraceLoggingSid(system_sid, "SystemSid"),
            TraceLoggingBinary(
                ebpf_execution_context_privileged_security_descriptor, security_descriptor_size, "SecurityDescriptor"));
    }

Exit:
    if (ebpfsvc_sid) {
        ebpf_free(ebpfsvc_sid);
    }

    if (dacl) {
        ebpf_free(dacl);
    }

    if (self_relative_security_descriptor) {
        ebpf_free(self_relative_security_descriptor);
    }

    return status;
}

static _Check_return_ NTSTATUS
_ebpf_driver_initialize_device(WDFDRIVER driver_handle, _Out_ WDFDEVICE* device)
{
    NTSTATUS status;
    PWDFDEVICE_INIT device_initialize = NULL;
    WDF_OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING ebpf_device_name;
    WDF_FILEOBJECT_CONFIG file_object_config;
    UNICODE_STRING ebpf_symbolic_device_name;

    // Log the version of the driver at startup.
    // This is useful for debugging purposes and to ensure that the version string is present in the binary.
    EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_VERBOSE, EBPF_TRACELOG_KEYWORD_CORE, ebpf_core_version);
    if (TraceLoggingProviderEnabled(ebpf_tracelog_provider, EBPF_TRACELOG_LEVEL_INFO, EBPF_TRACELOG_KEYWORD_CORE)) {
        TraceLoggingWrite(
            ebpf_tracelog_provider,
            "EbpfExecutionContextDeviceSecurity",
            TraceLoggingLevel(WINEVENT_LEVEL_INFO),
            TraceLoggingKeyword(EBPF_TRACELOG_KEYWORD_CORE),
            TraceLoggingWideString(EBPF_EXECUTION_CONTEXT_DEVICE_SDDL, "DeviceSddl"));
    }

    // Allow access to kernel/system, administrators, LocalService, and ebpfsvc only.
    DECLARE_CONST_UNICODE_STRING(security_descriptor, EBPF_EXECUTION_CONTEXT_DEVICE_SDDL);
    device_initialize = WdfControlDeviceInitAllocate(driver_handle, &security_descriptor);
    if (!device_initialize) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfControlDeviceInitAllocate, status);
        goto Exit;
    }

    WdfDeviceInitSetDeviceType(device_initialize, FILE_DEVICE_NULL);
    WdfDeviceInitSetCharacteristics(device_initialize, FILE_DEVICE_SECURE_OPEN, FALSE);
    WdfDeviceInitSetCharacteristics(device_initialize, FILE_AUTOGENERATED_DEVICE_NAME, TRUE);
    RtlInitUnicodeString(&ebpf_device_name, EBPF_DEVICE_NAME);
    status = WdfDeviceInitAssignName(device_initialize, &ebpf_device_name);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfDeviceInitAssignName, status);
        goto Exit;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.SynchronizationScope = WdfSynchronizationScopeNone;
    WDF_FILEOBJECT_CONFIG_INIT(&file_object_config, NULL, _ebpf_driver_file_close, WDF_NO_EVENT_CALLBACK);
    WdfDeviceInitSetFileObjectConfig(device_initialize, &file_object_config, &attributes);

    // WDF framework doesn't handle IRP_MJ_QUERY_VOLUME_INFORMATION so register a handler for this IRP.
    status = WdfDeviceInitAssignWdmIrpPreprocessCallback(
        device_initialize, _ebpf_driver_query_volume_information, IRP_MJ_QUERY_VOLUME_INFORMATION, NULL, 0);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfDeviceInitAssignWdmIrpPreprocessCallback, status);
        goto Exit;
    }

    status = WdfDeviceCreate(&device_initialize, WDF_NO_OBJECT_ATTRIBUTES, device);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfDeviceCreate, status);
        goto Exit;
    }

    // Create symbolic link for control object for user mode.
    RtlInitUnicodeString(&ebpf_symbolic_device_name, EBPF_SYMBOLIC_DEVICE_NAME);
    status = WdfDeviceCreateSymbolicLink(*device, &ebpf_symbolic_device_name);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfDeviceCreateSymbolicLink, status);
        goto Exit;
    }

Exit:
    if (device_initialize) {
        WdfDeviceInitFree(device_initialize);
    }
    return status;
}

// Create a basic WDF driver, set up the device object for a callout driver and set up the ioctl surface.
static _Check_return_ NTSTATUS
_ebpf_driver_initialize_objects(
    _Inout_ DRIVER_OBJECT* driver_object,
    _In_ const UNICODE_STRING* registry_path,
    _Out_ WDFDRIVER* driver_handle,
    _Out_ WDFDEVICE* device)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG driver_configuration;
    WDF_IO_QUEUE_CONFIG io_queue_configuration;
    BOOLEAN device_create_flag = FALSE;
    BOOLEAN ebpf_core_initialized = FALSE;

    // IMPORTANT NOTE: The choice of implementing part of the driver initialization in another function
    // (_ebpf_driver_initialize_device()) is deliberate.  We perform a lot of standard WDF driver initialization here
    // (and ebpf support code as well) and consequently need quite a few local variables (most of 'struct' type). Some
    // of these are quite large and end up chewing up a lot of stack space. This causes Code Analysis tools to flag
    // compile-time stack overflow errors when these variables (together) exceed the default stack size of 1024 bytes.
    //
    // This split between multiple functions ensures we don't hit this condition. Please keep this mind when
    // refactoring/enhancing this function.
    //
    // One way to ensure this would be to run Code Analysis tools locally to catch such issues very early rather than
    // wait for them to be flagged at the CI/CD gate during PR validation.
    //
    // OTOH, the CI/CD pipeline performs this check on a 'Draft PR' as well, so that's an option too.

    WDF_DRIVER_CONFIG_INIT(&driver_configuration, WDF_NO_EVENT_CALLBACK);
    driver_configuration.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    driver_configuration.EvtDriverUnload = _ebpf_driver_unload;
    status =
        WdfDriverCreate(driver_object, registry_path, WDF_NO_OBJECT_ATTRIBUTES, &driver_configuration, driver_handle);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfDriverCreate, status);
        goto Exit;
    }

    status = _ebpf_driver_initialize_device(*driver_handle, device);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_MESSAGE_NTSTATUS(
            EBPF_TRACELOG_LEVEL_CRITICAL, EBPF_TRACELOG_KEYWORD_ERROR, (char*)"_ebpf_driver_initialize_device", status);
        goto Exit;
    }

    device_create_flag = TRUE;

    // Create default queue.
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&io_queue_configuration, WdfIoQueueDispatchParallel);
    io_queue_configuration.EvtIoDeviceControl = _ebpf_driver_io_device_control;
    status = WdfIoQueueCreate(*device, &io_queue_configuration, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfIoQueueCreate, status);
        goto Exit;
    }

    status = ebpf_result_to_ntstatus(ebpf_core_initiate());
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, ebpf_core_initiate, status);
        goto Exit;
    }

    ebpf_core_initialized = TRUE;

    status = _ebpf_driver_build_privileged_security_descriptor();
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_NTSTATUS_API_FAILURE(
            EBPF_TRACELOG_KEYWORD_ERROR, _ebpf_driver_build_privileged_security_descriptor, status);
        goto Exit;
    }

    WdfControlFinishInitializing(*device);

Exit:
    if (!NT_SUCCESS(status)) {
        if (ebpf_core_initialized) {
            ebpf_core_terminate();
        }

        if (device_create_flag && device != NULL) {

            // Release the reference on the newly created object, since we couldn't initialize it.
            WdfObjectDelete(*device);
        }
    }
    return status;
}

static void
_ebpf_driver_file_close(WDFFILEOBJECT wdf_file_object)
{
    FILE_OBJECT* file_object = WdfFileObjectWdmGetFileObject(wdf_file_object);
    ebpf_core_close_context(file_object->FsContext2);
}

static void
_ebpf_driver_io_device_control_complete(_Inout_ void* context, size_t output_buffer_length, ebpf_result_t result)
{
    NTSTATUS status;
    WDFREQUEST request = (WDFREQUEST)context;
    status = WdfRequestUnmarkCancelable(request);
    UNREFERENCED_PARAMETER(status);
    WdfRequestCompleteWithInformation(request, ebpf_result_to_ntstatus(result), output_buffer_length);
    WdfObjectDereference(request);
}

static void
_ebpf_driver_io_device_control_cancel(WDFREQUEST request)
{
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfrequest/nc-wdfrequest-evt_wdf_request_cancel
    ebpf_core_cancel_protocol_handler(request);
}

static bool
_ebpf_driver_is_caller_privileged(ebpf_operation_id_t operation_id)
{
    // Check if the caller has the required privileges.
    SECURITY_SUBJECT_CONTEXT subject_context;
    const ACCESS_MASK desired_access = EBPF_EXECUTION_CONTEXT_PRIVILEGED_ACCESS;
    SeCaptureSubjectContext(&subject_context);
    ACCESS_MASK granted_access = 0;
    GENERIC_MAPPING generic_mapping = {0, 0, 0, 0};
    NTSTATUS status;
    BOOLEAN result = SeAccessCheck(
        ebpf_execution_context_privileged_security_descriptor,
        &subject_context,
        FALSE,            // Subject context is not locked
        desired_access,   // Desired access
        0,                // Previously granted access
        NULL,             // No privileges
        &generic_mapping, // Generic mapping
        UserMode,         // Access mode
        &granted_access,  // Granted access
        &status);
    _ebpf_driver_trace_privileged_access_check(
        &subject_context, operation_id, desired_access, granted_access, result, status);
    SeReleaseSubjectContext(&subject_context);
    return result && NT_SUCCESS(status);
}

static VOID
_ebpf_driver_io_device_control(
    _In_ WDFQUEUE queue,
    _In_ WDFREQUEST request,
    size_t output_buffer_length,
    size_t input_buffer_length,
    unsigned long io_control_code)
{
    NTSTATUS status = STATUS_SUCCESS;
    WDFDEVICE device;
    void* input_buffer = NULL;
    void* output_buffer = NULL;
    size_t actual_input_length = 0;
    size_t actual_output_length = 0;
    const struct _ebpf_operation_header* user_request = NULL;
    struct _ebpf_operation_header* user_reply = NULL;
    bool async = false;
    bool privileged = false;
    bool wdf_request_ref_acquired = false;

    device = WdfIoQueueGetDevice(queue);

    switch (io_control_code) {
    case IOCTL_EBPF_CTL_METHOD_BUFFERED:
        // Verify that length of the input buffer supplied to the request object
        // is not zero
        if (input_buffer_length != 0) {
            // Retrieve the input buffer associated with the request object
            status = WdfRequestRetrieveInputBuffer(
                request,             // Request object
                input_buffer_length, // Length of input buffer
                &input_buffer,       // Pointer to buffer
                &actual_input_length // Length of buffer
            );

            if (!NT_SUCCESS(status)) {
                EBPF_LOG_NTSTATUS_API_FAILURE(EBPF_TRACELOG_KEYWORD_ERROR, WdfRequestRetrieveInputBuffer, status);
                goto Done;
            }

            if (input_buffer == NULL) {
                status = STATUS_INVALID_PARAMETER;
                EBPF_LOG_NTSTATUS_API_FAILURE_MESSAGE(
                    EBPF_TRACELOG_KEYWORD_ERROR, "WdfRequestRetrieveInputBuffer", status, "Input buffer is null");
                goto Done;
            }

            if (input_buffer != NULL) {
                size_t minimum_request_size = 0;
                size_t minimum_reply_size = 0;
                void* async_context = NULL;

                user_request = input_buffer;
                if (actual_input_length < sizeof(struct _ebpf_operation_header)) {
                    EBPF_LOG_MESSAGE(
                        EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_ERROR, "Input buffer is too small");
                    status = STATUS_INVALID_PARAMETER;
                    goto Done;
                }

                status = ebpf_result_to_ntstatus(ebpf_core_get_protocol_handler_properties(
                    user_request->id, &minimum_request_size, &minimum_reply_size, &async, &privileged));
                if (status != STATUS_SUCCESS) {
                    EBPF_LOG_NTSTATUS_API_FAILURE(
                        EBPF_TRACELOG_KEYWORD_ERROR, ebpf_core_get_protocol_handler_properties, status);
                    goto Done;
                }

                if (privileged && !_ebpf_driver_is_caller_privileged(user_request->id)) {
                    EBPF_LOG_MESSAGE(
                        EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_ERROR, "Caller is not privileged");
                    status = STATUS_ACCESS_DENIED;
                    goto Done;
                }

                // Be aware: Input and output buffer point to the same memory.
                if (minimum_reply_size > 0) {
                    // Retrieve output buffer associated with the request object
                    status = WdfRequestRetrieveOutputBuffer(
                        request, output_buffer_length, &output_buffer, &actual_output_length);
                    if (!NT_SUCCESS(status)) {
                        EBPF_LOG_NTSTATUS_API_FAILURE(
                            EBPF_TRACELOG_KEYWORD_ERROR, WdfRequestRetrieveOutputBuffer, status);
                        goto Done;
                    }
                    if (output_buffer == NULL) {
                        status = STATUS_INVALID_PARAMETER;
                        EBPF_LOG_NTSTATUS_API_FAILURE_MESSAGE(
                            EBPF_TRACELOG_KEYWORD_ERROR,
                            "WdfRequestRetrieveOutputBuffer",
                            status,
                            "Output buffer is null");
                        goto Done;
                    }

                    if (actual_output_length < minimum_reply_size) {
                        EBPF_LOG_MESSAGE(
                            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_ERROR, "Output buffer is too small");
                        status = STATUS_BUFFER_TOO_SMALL;
                        goto Done;
                    }
                    user_reply = output_buffer;

                    // Zero any output buffer bytes beyond the input data to prevent
                    // leaking uninitialized kernel pool memory to user-mode.
                    if (actual_output_length > actual_input_length) {
                        memset(
                            (uint8_t*)output_buffer + actual_input_length,
                            0,
                            actual_output_length - actual_input_length);
                    }
                }

                if ((actual_input_length > UINT16_MAX) || (actual_output_length > UINT16_MAX)) {
                    status = STATUS_INVALID_PARAMETER;
                    EBPF_LOG_MESSAGE(
                        EBPF_TRACELOG_LEVEL_ERROR,
                        EBPF_TRACELOG_KEYWORD_ERROR,
                        "Input or output buffer length exceeds protocol limit");
                    goto Done;
                }

                if (async) {
                    WdfObjectReference(request);
                    async_context = request;
                    WdfRequestMarkCancelable(request, _ebpf_driver_io_device_control_cancel);
                    wdf_request_ref_acquired = true;
                }

                status = ebpf_result_to_ntstatus(ebpf_core_invoke_protocol_handler(
                    user_request->id,
                    user_request,
                    (uint16_t)actual_input_length,
                    user_reply,
                    (uint16_t)actual_output_length,
                    async_context,
                    _ebpf_driver_io_device_control_complete));
                if (status != STATUS_SUCCESS) {
                    EBPF_LOG_NTSTATUS_API_FAILURE(
                        EBPF_TRACELOG_KEYWORD_ERROR, "ebpf_core_invoke_protocol_handler", status);
                }
                goto Done;
            }
        } else {
            EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_ERROR, "Zero length input buffer");
            status = STATUS_INVALID_PARAMETER;
            goto Done;
        }
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

Done:
    if (status != STATUS_PENDING) {
        if (wdf_request_ref_acquired) {
            ebpf_assert(status != STATUS_SUCCESS);
            // Async operation failed. Remove cancellable marker.
            (void)WdfRequestUnmarkCancelable(request);
            WdfObjectDereference(request);
        }
        WdfRequestCompleteWithInformation(request, status, output_buffer_length);
    }
    return;
}

NTSTATUS
DriverEntry(_In_ DRIVER_OBJECT* driver_object, _In_ UNICODE_STRING* registry_path)
{
    NTSTATUS status;
    WDFDRIVER driver_handle;
    WDFDEVICE device;

    status = ebpf_trace_initiate();
    if (!NT_SUCCESS(status)) {

        // Fail silently as there is no other mechanism to indicate this failure. Note that in this case, the
        // EBPF_LOG_EXIT() call at the end will not log anything either.
        goto Exit;
    }

    EBPF_LOG_ENTRY();

    // Request NX Non-Paged Pool when available
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    status = _ebpf_driver_initialize_objects(driver_object, registry_path, &driver_handle, &device);
    if (!NT_SUCCESS(status)) {
        EBPF_LOG_MESSAGE_NTSTATUS(
            EBPF_TRACELOG_LEVEL_CRITICAL,
            EBPF_TRACELOG_KEYWORD_ERROR,
            (char*)"_ebpf_driver_initialize_objects failed",
            status);
        goto Exit;
    }

    _ebpf_driver_device_object = WdfDeviceWdmGetDeviceObject(device);

Exit:
    EBPF_LOG_EXIT();
    if (!NT_SUCCESS(status)) {
        ebpf_trace_terminate();
    }
    return status;
}

_Ret_notnull_ DEVICE_OBJECT*
ebpf_driver_get_device_object()
{
    return _ebpf_driver_device_object;
}

// The C runtime queries the file type via GetFileType when creating a file
// descriptor. GetFileType queries volume information to get device type via
// FileFsDeviceInformation information class.
NTSTATUS
_ebpf_driver_query_volume_information(_In_ WDFDEVICE device, _Inout_ IRP* irp)
{
    NTSTATUS status;
    IO_STACK_LOCATION* irp_stack_location;
    UNREFERENCED_PARAMETER(device);
    irp_stack_location = IoGetCurrentIrpStackLocation(irp);

    switch (irp_stack_location->Parameters.QueryVolume.FsInformationClass) {
    case FileFsDeviceInformation:
        if (irp_stack_location->Parameters.DeviceIoControl.OutputBufferLength < sizeof(FILE_FS_DEVICE_INFORMATION)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            FILE_FS_DEVICE_INFORMATION* device_info = (FILE_FS_DEVICE_INFORMATION*)irp->AssociatedIrp.SystemBuffer;
            device_info->DeviceType = FILE_DEVICE_NULL;
            device_info->Characteristics = 0;
            status = STATUS_SUCCESS;
        }
        break;
    default:
        status = STATUS_NOT_SUPPORTED;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, 0);
    return status;
}
