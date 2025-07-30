# Dual Stack Redirect Tests for PR #2562

This document describes the automated tests added to validate the fix for dual stack socket redirection issue addressed in PR #2562.

## Problem Description

PR #2562 fixed an issue where dual stack sockets were not properly handling the `redirected_by_self` case. The problem occurred when:

1. An original connection used a dual stack socket (AF_INET6) to connect to an IPv4-mapped address
2. This triggered the v6 connect_redirect filter in WFP
3. The connection was redirected to a proxy
4. The proxy then created an IPv4 socket (AF_INET) to connect to the original destination
5. This triggered the v4 connect_redirect filter
6. Due to different filter IDs, `FwpsQueryConnectionRedirectState` returned `REDIRECTED_BY_OTHER` instead of `REDIRECTED_BY_SELF`
7. This caused the proxy connection to be redirected again, creating an infinite loop

## Solution

The fix changed the redirect handle allocation from per-filter to per-filter_context (per eBPF program), ensuring that both v4 and v6 filters for the same eBPF program share the same redirect handle.

## Test Coverage

### 1. End-to-End Tests (`tests/connect_redirect/connect_redirect_tests.cpp`)

#### Test Function: `dual_stack_redirected_by_self_test()`

This comprehensive test validates the complete dual stack redirect scenario:

**Test Steps:**
1. Create a dual stack socket (AF_INET6 with dual stack enabled)
2. Create an IPv4 proxy socket 
3. Configure redirect policy to redirect VIP to local proxy
4. Dual stack socket connects to VIP → triggers v6 filter → gets redirected to proxy
5. Proxy IPv4 socket connects to original destination → triggers v4 filter → should be recognized as REDIRECTED_BY_SELF
6. Verify no infinite redirection occurs

**Test Cases:**
- `dual_stack_redirected_by_self_vip_address_local_address_TCP`
- `dual_stack_redirected_by_self_vip_address_local_address_UNCONNECTED_UDP`  
- `dual_stack_redirected_by_self_vip_address_local_address_CONNECTED_UDP`

### 2. Unit Tests (`tests/netebpfext_unit/netebpfext_unit.cpp`)

#### Test: `dual_stack_redirect_handle_per_filter_context`

Validates that IPv4 and IPv6 connect filters for the same eBPF program share the same redirect handle.

#### Test: `dual_stack_redirect_context_consistency`

Validates the initialization order fix where `sock_addr_ctx` is populated before WFP field access.

### 3. Sample eBPF Program (`tests/sample/dual_stack_redirect_test.c`)

A dedicated eBPF program that demonstrates dual stack redirect logic with:
- Separate handling for IPv4 and IPv6 connections
- Counters to track which filters are invoked
- Policy map for controlling redirect behavior

## Running the Tests

### Prerequisites
- Windows development environment with WDK
- eBPF for Windows built and installed
- Test infrastructure set up (TCP/UDP listeners on required ports)

### Running End-to-End Tests

```cmd
# Build the solution
msbuild ebpf-for-windows.sln /p:Configuration=Debug

# Run connect redirect tests with dual stack tag
connect_redirect_tests.exe --tags="[connect_authorize_redirect_tests_dual_stack_redirected_by_self]"
```

### Running Unit Tests

```cmd
# Run netebpfext unit tests with dual stack redirect tag
netebpfext_unit.exe --tags="[dual_stack_redirect]"  
```

### Test Parameters

The connect redirect tests require network configuration parameters:

```cmd
connect_redirect_tests.exe --virtual-ip-v4=192.168.1.100 --virtual-ip-v6=fe80::100 --local-ip-v4=192.168.1.50 --local-ip-v6=fe80::50 --remote-ip-v4=192.168.1.200 --remote-ip-v6=fe80::200 --destination-port=4444 --proxy-port=4443
```

## Expected Results

### Successful Test Results

1. **Dual Stack Connection**: Successfully redirected from VIP to proxy
2. **Proxy Connection**: Successfully connects to original destination without redirection
3. **No Infinite Loop**: Proxy connection is recognized as REDIRECTED_BY_SELF
4. **Proper Response**: Client receives expected server response through proxy

### Test Validation Points

- ✅ Redirect handle is shared between v4 and v6 filters
- ✅ `FwpsQueryConnectionRedirectState` returns `REDIRECTED_BY_SELF` for proxy connections
- ✅ No infinite redirection loops occur
- ✅ Redirect context is properly initialized before WFP field access
- ✅ Both TCP and UDP protocols work correctly

## Troubleshooting

### Common Issues

1. **Test Infrastructure**: Ensure TCP/UDP listeners are running on specified ports
2. **Network Configuration**: Verify IP addresses are reachable and properly configured
3. **Permissions**: Tests may require administrator privileges for WFP operations
4. **eBPF Program Loading**: Verify eBPF programs are properly loaded and attached

### Debug Information

The tests include extensive logging:
- Connection attempt details
- Redirect policy application
- WFP filter invocations  
- Expected vs actual responses

### Log Analysis

Look for these key log messages:
- `"DUAL_STACK_REDIRECTED_BY_SELF: vip_address -> local_address"`
- `"Found v6 proxy entry value"` (dual stack connection)
- `"Found v4 proxy entry value"` (proxy connection, should not redirect)

## Integration with CI/CD

These tests should be included in the automated test suite to prevent regression of the dual stack redirect fix. They validate critical functionality for:
- Load balancers using dual stack sockets
- Proxy servers handling mixed IPv4/IPv6 traffic
- Service mesh implementations with traffic redirection