// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

// This program is for testing bind hook policies (currently just reject and soft/hard permit).
//
#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define AF_INET 2
#define AF_INET6 0x17

/**
 * @brief Policy lookup key structure for bind operations.
 *
 * This structure defines the key used to look up bind policies in the policy map.
 * It supports hierarchical matching where 0 values act as wildcards, allowing
 * policies to be defined at different levels of specificity:
 * 1. Specific: process_id + port + protocol
 * 2. Port-based: port + protocol (any process)
 * 3. Process-based: process_id (any port/protocol)
 * 4. Global: all wildcards (fallback policy)
 */
typedef struct _bind_policy_key
{
    uint64_t process_id; ///< Target process ID (0 = wildcard, applies to all processes)
    uint16_t port;       ///< Target port number (0 = wildcard, applies to all ports)
    uint8_t protocol;    ///< IP protocol (0 = wildcard, applies to all protocols)
} bind_policy_key_t;

/**
 * @brief Policy action configuration for bind operations.
 *
 * This structure defines what action to take when a bind operation matches
 * a policy entry (doesn't currently test redirection).
 */
typedef struct _bind_policy_value
{
    bind_action_t action; ///< Action to take: BIND_PERMIT_SOFT, BIND_PERMIT_HARD, BIND_DENY
} bind_policy_value_t;

/**
 * @brief Audit log entry for bind operations.
 *
 * This structure records bind policy enforcement actions for security monitoring.
 * The entry is stored with a timestamp key to maintain an audit trail of
 * all bind operations and the actions taken by the policy engine.
 *
 * Note: action_taken is stored as uint32_t instead of bind_action_t for
 * eBPF verifier compatibility while maintaining the same semantic meaning.
 */
typedef struct _bind_audit_entry
{
    uint16_t port;         ///< Port number that was being bound
    uint32_t action_taken; ///< Action taken (maps to bind_action_t values)
} bind_audit_entry_t;

/**
 * @brief Hash map storing bind policy configurations.
 *
 * This map stores the actual bind policies that control which operations are allowed
 * or denied. Policies are looked up using the hierarchical key structure
 * with fallback logic from specific to general matching rules.
 *
 * Key: bind_policy_key_t (process_id, port, protocol combination)
 * Value: bind_policy_value_t (action to take)
 * Max entries: 100 policy rules
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, bind_policy_key_t);
    __type(value, bind_policy_value_t);
    __uint(max_entries, 100);
} bind_policy_map SEC(".maps");

/**
 * @brief Hash map storing audit log entries for bind operations.
 *
 * This map maintains a security audit trail of all bind operations processed
 * by the policy engine. Each entry is keyed by timestamp to provide chronological
 * ordering of events for security analysis and compliance monitoring.
 *
 * Key: uint64_t (timestamp from bpf_ktime_get_ns())
 * Value: bind_audit_entry_t (port and action taken)
 * Max entries: 1000 audit records (LRU eviction for older entries)
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t);
    __type(value, bind_audit_entry_t);
    __uint(max_entries, 1000);
} bind_audit_map SEC(".maps");

/**
 * @brief Record a bind operation in the audit log.
 *
 * This function creates an audit trail entry for the bind operation, recording
 * the port number and the action taken by the policy engine. The entry is stored
 * with a nanosecond timestamp as the key to maintain chronological ordering.
 *
 * This audit functionality demonstrates how eBPF programs can provide security
 * monitoring and compliance logging for network operations.
 *
 * @param[in] ctx Bind operation context containing socket address information
 * @param[in] action_taken The policy decision made for this bind operation
 */
__inline void
update_audit_entry(bind_md_t* ctx, bind_action_t action_taken)
{
    uint64_t key = bpf_ktime_get_ns(); // Use nanosecond timestamp as unique key
    bind_audit_entry_t entry = {0};

    // Extract port from sockaddr_in structure (port is at offset 2)
    entry.port = *(uint16_t*)&ctx->socket_address[2];
    entry.action_taken = (uint32_t)action_taken;

    // Store in audit map (BPF_ANY flag allows overwrite if timestamp collision occurs)
    bpf_map_update_elem(&bind_audit_map, &key, &entry, 0);
}

/**
 * @brief Perform hierarchical policy lookup for bind operations.
 *
 * This function implements a comprehensive policy lookup system with fallback logic
 * that searches from most specific to most general policy rules:
 *
 * 1. Exact match: process_id + port + protocol (most specific)
 * 2. Port-based: port + protocol, any process
 * 3. Process-based: process_id only, any port/protocol
 * 4. Global fallback: wildcard policy for all operations
 *
 * The hierarchical approach allows administrators to define granular policies
 * (e.g., "deny process X from binding to port Y") while providing reasonable
 * defaults through broader rules.
 *
 * @param[in,out] ctx Bind operation context; socket_address may be modified for redirects
 * @return bind_action_t Action to take (PERMIT_SOFT, PERMIT_HARD, DENY, or REDIRECT)
 */
__inline __attribute__((always_inline)) bind_action_t
lookup_bind_policy(bind_md_t* ctx)
{
    bind_policy_key_t key = {0};
    bind_policy_value_t* policy_value = NULL;
    bind_action_t result = BIND_PERMIT_SOFT; // Default: soft permit allows other security layers to decide

    // Extract port from sockaddr_in structure (assumes IPv4; port at offset 2)
    uint16_t port = *(uint16_t*)&ctx->socket_address[2];

    //
    // Policy lookup hierarchy: most specific to most general
    //

    // Level 1: Try exact match policy (process_id + port + protocol)
    key.process_id = ctx->process_id;
    key.port = port;
    key.protocol = ctx->protocol;
    bpf_printk(
        "Looking up bind policy for PID=%llu, Port=%u (net), Protocol=%u\n", key.process_id, key.port, key.protocol);

    policy_value = bpf_map_lookup_elem(&bind_policy_map, &key);
    if (policy_value) {
        bpf_printk("Found exact match bind policy: Action=%u\n", policy_value->action);
        result = policy_value->action;
        goto exit;
    }

    // Level 2: Try port + protocol policy (any process)
    // This allows port-based policies that apply to any application
    key.process_id = 0; // Wildcard for process
    policy_value = bpf_map_lookup_elem(&bind_policy_map, &key);
    if (policy_value) {
        bpf_printk("Found port-based bind policy: Action=%u\n", policy_value->action);
        result = policy_value->action;
        goto exit;
    }

    // Level 3: Try process-only policy (any port, any protocol)
    // This allows application-wide policies regardless of port/protocol
    key.process_id = ctx->process_id;
    key.port = 0;     // Wildcard for port
    key.protocol = 0; // Wildcard for protocol
    policy_value = bpf_map_lookup_elem(&bind_policy_map, &key);
    if (policy_value) {
        bpf_printk("Found process-based bind policy: Action=%u\n", policy_value->action);
        result = policy_value->action;
        goto exit;
    }

    // Level 4: Try global wildcard policy (any process, any port, any protocol)
    // This provides the system-wide default policy when no specific rules match
    key.process_id = 0; // Already set, but explicit for clarity
    policy_value = bpf_map_lookup_elem(&bind_policy_map, &key);
    if (policy_value) {
        result = policy_value->action;
        goto exit;
    }

    // If no policies match, use the default action (BIND_PERMIT_SOFT)
    // This provides a secure default that allows the operation but permits
    // other security layers to make the final decision

exit:
    // Log all policy decisions for security auditing and compliance
    update_audit_entry(ctx, result);
    return result;
}

/**
 * @brief Main entry point for bind policy enforcement.
 *
 * This is the primary eBPF program function that gets called by the eBPF runtime
 * when a bind operation occurs. It demonstrates a complete bind hook implementation
 * including operation filtering, hierarchical policy lookup, and audit logging.
 *
 * The function showcases key bind hook capabilities:
 * - Selective processing (only BIND_OPERATION_BIND operations)
 * - Policy-based access control with multiple enforcement levels
 * - Hard vs soft permit enforcement for integration with other security layers
 * - Comprehensive audit logging for security monitoring
 *
 * @param[in,out] ctx Bind operation metadata and context
 * @return bind_action_t Policy decision: PERMIT_SOFT, PERMIT_HARD, DENY, or REDIRECT
 */
SEC("bind")
bind_action_t
authorize_bind(bind_md_t* ctx)
{
    // Filter: Only process actual bind operations, allow others (like unbind) to proceed
    if (ctx->operation != BIND_OPERATION_BIND) {
        update_audit_entry(ctx, BIND_PERMIT_SOFT);
        return BIND_PERMIT_SOFT; // Soft permit allows other layers to potentially override
    }

    // Perform hierarchical policy lookup and enforcement
    return lookup_bind_policy(ctx);
}