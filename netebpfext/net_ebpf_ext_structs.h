// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

/**
 * @file
 * @brief Header file for structures of the driver.
 */
#include "ebpf_extension.h"

typedef enum _net_ebpf_extension_hook_attach_capability
{
    ATTACH_CAPABILITY_MULTI_ATTACH_WITH_WILDCARD =
        0,                           ///< Multiple clients can attach to the hook, for each attach parameters.
    ATTACH_CAPABILITY_SINGLE_ATTACH, ///< Only one client can attach to the hook, irrespective of the attach parameters.
    ATTACH_CAPABILITY_SINGLE_ATTACH_PER_HOOK, ///< One client can attach to the hook for each attach parameter, but with
                                              ///< wildcard attach parameter, only one client can attach.
} net_ebpf_extension_hook_attach_capability_t;

/**
 *  @brief This is the per client binding context for the eBPF Hook
 *         NPI provider.
 */
typedef struct _net_ebpf_extension_hook_client net_ebpf_extension_hook_client_t;

/**
 *  @brief This is the per filter context for the eBPF Hook
 *         NPI provider.
 */
typedef struct _net_ebpf_extension_wfp_filter_context net_ebpf_extension_wfp_filter_context_t;

/**
 *  @brief This is the provider context of eBPF Hook NPI provider.
 */
typedef struct _net_ebpf_extension_hook_provider net_ebpf_extension_hook_provider_t;

/**
 * @brief Callback function to create hook specific filter context. This callback is invoked when a hook NPI client
          is attempting to attach to the hook NPI provider.
 *
 * @param[in] attaching_client Pointer to context of the hook NPI client that is requesting to be attached.
 * @param[in] provider_context Pointer to the hook NPI provider context to which the client is being attached.
 * @param[out] filter_context Pointer to the filter context being created.
 *
 * @return EBPF_SUCCESS when operation succeeded, failure otherwise.
 */
typedef ebpf_result_t (*net_ebpf_extension_create_filter_context)(
    _In_ const net_ebpf_extension_hook_client_t* attaching_client,
    _In_ const net_ebpf_extension_hook_provider_t* provider_context,
    _Outptr_ net_ebpf_extension_wfp_filter_context_t** filter_context);

/**
 * @brief Callback function to delete hook specific filter context. This callback is invoked when a hook NPI client
          is detaching from the hook NPI provider.
 *
 * @param[in] filter_context Pointer to the filter context being deleted.
 */
typedef void (*net_ebpf_extension_delete_filter_context)(
    _In_opt_ _Frees_ptr_opt_ net_ebpf_extension_wfp_filter_context_t* filter_context);

/**
 * @brief Callback function to validate if the attach parameters (i.e., client data) is valid, and to get information
 *        if the attach parameter is a wildcard attach parameter.
 *
 * @param[in] client_data Pointer to the attach parameters (client data) that is being validated.
 * @param[out] is_wildcard Pointer to a boolean that will be set to true if the attach parameter is a wildcard attach
 *             parameter.
 *
 * @return EBPF_SUCCESS when the attach parameters are valid, failure otherwise.
 */
typedef ebpf_result_t (*net_ebpf_extension_validate_client_data)(
    _In_ const ebpf_extension_data_t* client_data, _Out_ bool* is_wildcard);

/**
 * @brief When hook provider supports multiple programs per hook, this callback function is invoked after
 * every program invocation to determine whether the next program in the list should be invoked.
 *
 * @param[in] program_context Pointer to context passed to the eBPF program.
 * @param[in] progrma_verdict Result returned by the eBPF program.
 *
 * @returns TRUE if the next program should be invoked, FALSE otherwise.
 */
typedef bool (*net_ebpf_extension_hook_process_verdict)(_Inout_ void* program_context, int program_verdict);

typedef struct _net_ebpf_extension_hook_provider_dispatch_table
{
    net_ebpf_extension_create_filter_context create_filter_context;
    net_ebpf_extension_delete_filter_context delete_filter_context;
    net_ebpf_extension_validate_client_data validate_client_data;
    net_ebpf_extension_hook_process_verdict process_verdict;
} net_ebpf_extension_hook_provider_dispatch_table_t;

/**
 * @brief Data structure for hook NPI provider registration parameters.
 */
typedef struct _net_ebpf_extension_hook_provider_parameters
{
    const NPI_MODULEID* provider_module_id;           ///< NPI provider module ID.
    const ebpf_attach_provider_data_t* provider_data; ///< Hook provider data (contains supported program types).
} net_ebpf_extension_hook_provider_parameters_t;

typedef struct _net_ebpf_ext_hook_client_rundown
{
    EX_RUNDOWN_REF protection;
    bool rundown_occurred;
    bool rundown_initialized;
} net_ebpf_ext_hook_rundown_t;

struct _net_ebpf_extension_hook_provider;

/**
 * @brief Data structure representing a hook NPI client (attached eBPF program). This is returned
 * as the provider binding context in the NMR client attach callback.
 */
typedef struct _net_ebpf_extension_hook_client
{
    HANDLE nmr_binding_handle;                     ///< NMR binding handle.
    GUID client_module_id;                         ///< NMR module Id.
    const void* client_binding_context;            ///< Client supplied context to be passed when invoking eBPF program.
    const ebpf_extension_data_t* client_data;      ///< Client supplied attach parameters.
    ebpf_program_invoke_function_t invoke_program; ///< Pointer to function to invoke eBPF program.
    void* provider_data;                 ///< Opaque pointer to hook specific data associated with this client.
    PIO_WORKITEM detach_work_item;       ///< Pointer to IO work item that is invoked to detach the client.
    net_ebpf_ext_hook_rundown_t rundown; ///< Pointer to rundown object used to synchronize detach operation.
} net_ebpf_extension_hook_client_t;

typedef struct _net_ebpf_extension_hook_provider
{
    NPI_PROVIDER_CHARACTERISTICS characteristics;                  ///< NPI Provider characteristics.
    net_ebpf_ext_hook_rundown_t rundown;                           ///< Rundown reference for the hook provider.
    HANDLE nmr_provider_handle;                                    ///< NMR binding handle.
    EX_PUSH_LOCK lock;                                             ///< Lock for serializing attach / detach calls.
    net_ebpf_extension_hook_provider_dispatch_table_t dispatch;    ///< Hook specific dispatch table.
    net_ebpf_extension_hook_attach_capability_t attach_capability; ///< Attach capability for specific hook provider.
    const void* custom_data; ///< Opaque pointer to hook specific data associated for this provider.
    _Guarded_by_(lock)
        LIST_ENTRY filter_context_list; ///< Linked list of filter contexts that are attached to this provider.
    LIST_ENTRY cleanup_list_entry;      ///< List entry for cleanup.
} net_ebpf_extension_hook_provider_t;

typedef struct _net_ebpf_extension_invoke_programs_parameters
{
    net_ebpf_extension_wfp_filter_context_t* filter_context;
    void* program_context;
    uint32_t verdict;
    ebpf_result_t result;
} net_ebpf_extension_invoke_programs_parameters_t;