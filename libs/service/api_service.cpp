// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "api_common.hpp"
#include "api_service.h"
#include "device_helper.hpp"
#include "ebpf_protocol.h"
#include "ebpf_shared_framework.h"
#include "hash.h"
#include "map_descriptors.hpp"
#include "platform.h"
extern "C"
{
#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
#include "ubpf.h"
#endif
}
#include "Verifier.h"
#include "verifier_service.h"
#include "windows_platform.hpp"

#include <map>
#include <set>
#include <softpub.h>
#include <stdexcept>
#include <string>
#include <wintrust.h>

// Include wintrust.lib
#pragma comment(lib, "wintrust.lib")

static bool _ebpf_service_test_signing_enabled = false;
static bool _ebpf_service_hypervisor_kernel_mode_code_enforcement_enabled = false;

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)

// Maximum size of JIT'ed native code.
#define MAX_NATIVE_CODE_SIZE_IN_BYTES (32 * 1024) // 32 KB

// TODO(Issue #345 (ubpf)): uBPF has a max number of helper functions hard coded,
// but doesn't expose the define to callers, so we define it here.
#define UBPF_MAX_EXT_FUNCS 64

static ebpf_result_t
_resolve_helper_functions(
    ebpf_handle_t program_handle,
    _In_reads_(instruction_count) ebpf_inst* instructions,
    uint32_t instruction_count,
    std::map<uint32_t, helper_function_address_t>& helper_id_to_address)
{
    // Note:
    // eBPF supports helper IDs in the range [1, MAXUINT32]
    // uBPF jitter only supports helper IDs in the range [0,63]
    // Build a table to map [1, MAXUINT32] -> [0,63]
    for (size_t index = 0; index < instruction_count; index++) {
        ebpf_inst& instruction = instructions[index];
        if (instruction.opcode != prevail::INST_OP_CALL || instruction.src != prevail::INST_CALL_STATIC_HELPER) {
            continue;
        }
        helper_id_to_address[instruction.imm] = {0};
    }

    ebpf_protocol_buffer_t request_buffer(
        offsetof(ebpf_operation_resolve_helper_request_t, helper_id) + sizeof(uint32_t) * helper_id_to_address.size());

    ebpf_protocol_buffer_t reply_buffer(
        offsetof(ebpf_operation_resolve_helper_reply_t, address) +
        sizeof(helper_function_address_t) * helper_id_to_address.size());

    auto request = reinterpret_cast<ebpf_operation_resolve_helper_request_t*>(request_buffer.data());
    auto reply = reinterpret_cast<ebpf_operation_resolve_helper_reply_t*>(reply_buffer.data());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_HELPER;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->program_handle = program_handle;

    uint32_t index = 0;
    for (auto& [helper_id, address] : helper_id_to_address) {
        request->helper_id[index] = helper_id;
        index++;
    }

    uint32_t result = invoke_ioctl(request_buffer, reply_buffer);
    if (result != ERROR_SUCCESS) {
        return win32_error_code_to_ebpf_result(result);
    }

    index = 0;
    for (auto& [helper_id, helper_address] : helper_id_to_address) {
        helper_address = reply->address[index++];
    }

    return EBPF_SUCCESS;
}

static ebpf_result_t
_build_helper_id_to_address_map(
    _In_reads_(instruction_count) ebpf_inst* instructions,
    uint32_t instruction_count,
    const std::map<uint32_t, helper_function_address_t>& helper_id_to_address,
    uint32_t& unwind_index)
{
    // Note:
    // eBPF supports helper IDs in the range [1, MAXUINT32].
    // uBPF jitter only supports helper IDs in the range [0,63].
    // Build a table to map [1, MAXUINT32] -> [0,63].
    std::map<uint32_t, uint32_t> helper_id_mapping;
    unwind_index = MAXUINT32;

    if (helper_id_to_address.size() == 0) {
        return EBPF_SUCCESS;
    }

    // The uBPF JIT compiler supports a maximum of UBPF_MAX_EXT_FUNCS helper functions.
    if (helper_id_to_address.size() > UBPF_MAX_EXT_FUNCS) {
        return EBPF_OPERATION_NOT_SUPPORTED;
    }

    uint32_t index = 0;
    for (auto [helper_id, helper_address] : helper_id_to_address) {
        helper_id_mapping[helper_id] = index++;
    }

    // Replace old helper_ids in range [1, MAXUINT32] with new helper ids in range [0,63]
    for (index = 0; index < instruction_count; index++) {
        ebpf_inst& instruction = instructions[index];
        if (instruction.opcode != prevail::INST_OP_CALL) {
            continue;
        }
        instruction.imm = helper_id_mapping[instruction.imm];
    }
    for (auto& [old_helper_id, new_helper_id] : helper_id_mapping) {
        if (get_helper_prototype_windows(old_helper_id).return_type !=
            EBPF_RETURN_TYPE_INTEGER_OR_NO_RETURN_IF_SUCCEED) {
            continue;
        }
        unwind_index = new_helper_id;
        break;
    }

    return EBPF_SUCCESS;
}

static ebpf_result_t
_resolve_ec_function(ebpf_ec_function_t function, uint64_t* address)
{
    ebpf_operation_get_ec_function_request_t request = {sizeof(request), EBPF_OPERATION_GET_EC_FUNCTION, function};
    ebpf_operation_get_ec_function_reply_t reply;

    uint32_t result = invoke_ioctl(request, reply);
    if (result != ERROR_SUCCESS) {
        return win32_error_code_to_ebpf_result(result);
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_GET_EC_FUNCTION) {
        return EBPF_INVALID_ARGUMENT;
    }

    *address = reply.address;

    return EBPF_SUCCESS;
}

// Replace map fds with map addresses.
static ebpf_result_t
_resolve_maps_in_byte_code(
    ebpf_handle_t program_handle, _In_reads_(instruction_count) ebpf_inst* instructions, uint32_t instruction_count)
{
    std::vector<std::pair<size_t, fd_t>> instruction_offsets; // instruction offsets at which map_fds are referenced.
    std::map<fd_t, uint64_t> map_fds;                         // map_fds and their addresses.

    size_t index = 0;
    for (index = 0; index < instruction_count; index++) {
        ebpf_inst& first_instruction = instructions[index];
        if (first_instruction.opcode != prevail::INST_OP_LDDW_IMM) {
            continue;
        }
        if (index + 1 >= instruction_count) {
            return EBPF_INVALID_ARGUMENT;
        }
        index++;

        // Check for LD_MAP flag
        if (first_instruction.src != 1) {
            continue;
        }

        fd_t map_fd = static_cast<fd_t>(first_instruction.imm);
        instruction_offsets.push_back({index - 1, map_fd});
        map_fds[map_fd] = 0;
    }

    if (map_fds.empty()) {
        return EBPF_SUCCESS;
    }

    ebpf_protocol_buffer_t request_buffer(
        offsetof(ebpf_operation_resolve_map_request_t, map_handle) + sizeof(uint64_t) * map_fds.size());

    ebpf_protocol_buffer_t reply_buffer(
        offsetof(ebpf_operation_resolve_map_reply_t, address) + sizeof(uint64_t) * map_fds.size());

    auto request = reinterpret_cast<ebpf_operation_resolve_map_request_t*>(request_buffer.data());
    auto reply = reinterpret_cast<ebpf_operation_resolve_map_reply_t*>(reply_buffer.data());
    request->header.id = ebpf_operation_id_t::EBPF_OPERATION_RESOLVE_MAP;
    request->header.length = static_cast<uint16_t>(request_buffer.size());
    request->program_handle = program_handle;

    index = 0;
    for (const auto& [map_fd, address] : map_fds) {
        request->map_handle[index++] = get_map_handle(map_fd);
    }

    // Send the request to the kernel, to resolve the map handles to addresses.
    uint32_t result = invoke_ioctl(request_buffer, reply_buffer);
    if (result != ERROR_SUCCESS) {
        return win32_error_code_to_ebpf_result(result);
    }

    // Retrieve the map addresses from the reply.
    index = 0;
    for (auto& [map_fd, address] : map_fds) {
        map_fds[map_fd] = reply->address[index++];
    }

    // Replace the map fds in the instructions with the addresses.
    for (index = 0; index < instruction_offsets.size(); index++) {
        ebpf_inst& first_instruction = instructions[instruction_offsets[index].first];
        ebpf_inst& second_instruction = instructions[instruction_offsets[index].first + 1];

        // Clear LD_MAP flag
        first_instruction.src = 0;

        // Replace handle with address
        uint64_t new_imm = map_fds[instruction_offsets[index].second];
        first_instruction.imm = static_cast<uint32_t>(new_imm);
        second_instruction.imm = static_cast<uint32_t>(new_imm >> 32);
    }

    return EBPF_SUCCESS;
}

static ebpf_result_t
_query_and_cache_map_descriptors(
    _In_reads_(handle_map_count) original_fd_handle_map_t* handle_map, uint32_t handle_map_count)
{
    ebpf_result_t result;
    prevail::EbpfMapDescriptor descriptor;

    if (handle_map_count > 0) {
        for (uint32_t i = 0; i < handle_map_count; i++) {
            descriptor = {0};
            ebpf_id_t id;
            ebpf_id_t inner_map_id;
            result = query_map_definition(
                reinterpret_cast<ebpf_handle_t>(handle_map[i].handle),
                &id,
                &descriptor.type,
                &descriptor.key_size,
                &descriptor.value_size,
                &descriptor.max_entries,
                &inner_map_id);
            if (result != EBPF_SUCCESS) {
                return result;
            }

            cache_map_original_file_descriptor_with_handle(
                handle_map[i].original_fd,
                handle_map[i].id,
                descriptor.type,
                descriptor.key_size,
                descriptor.value_size,
                descriptor.max_entries,
                handle_map[i].inner_map_original_fd,
                handle_map[i].inner_id,
                reinterpret_cast<ebpf_handle_t>(handle_map[i].handle),
                0);
        }
    }

    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_verify_and_load_program(
    _In_ const GUID* program_type,
    ebpf_handle_t program_handle,
    ebpf_execution_context_t execution_context,
    ebpf_execution_type_t execution_type,
    uint32_t handle_map_count,
    _In_reads_(handle_map_count) original_fd_handle_map_t* handle_map,
    uint32_t instruction_count,
    _In_reads_(instruction_count) ebpf_inst* instructions,
    _Outptr_result_maybenull_z_ const char** error_message,
    _Out_ uint32_t* error_message_size) noexcept
{
    ebpf_result_t result = EBPF_SUCCESS;
    int error = 0;
    uint64_t log_function_address;
    struct ubpf_vm* vm = nullptr;
    ebpf_protocol_buffer_t request_buffer;
    ebpf_operation_load_code_request_t* request = nullptr;

    // Only kernel execution context supported currently.
    if (execution_context == execution_context_user_mode) {
        return EBPF_INVALID_ARGUMENT;
    }

    // Set the default execution type to JIT. This will eventually
    // be decided by a system-wide policy. TODO(Issue #288): Configure
    // system-wide execution type.
    if (execution_type == EBPF_EXECUTION_ANY) {
        execution_type = EBPF_EXECUTION_JIT;
    }

    *error_message = nullptr;
    *error_message_size = 0;

    clear_map_descriptors();

    // Query map descriptors from execution context.
    try {
        result = _query_and_cache_map_descriptors(handle_map, handle_map_count);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        std::map<uint32_t, helper_function_address_t> helper_id_to_address;
        result = _resolve_helper_functions(program_handle, instructions, instruction_count, helper_id_to_address);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        // Verify the program.
        result = verify_byte_code(program_type, instructions, instruction_count, error_message, error_message_size);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        result = _resolve_maps_in_byte_code(program_handle, instructions, instruction_count);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        result = _resolve_ec_function(EBPF_EC_FUNCTION_LOG, &log_function_address);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        uint32_t unwind_index;
        result = _build_helper_id_to_address_map(instructions, instruction_count, helper_id_to_address, unwind_index);
        if (result != EBPF_SUCCESS) {
            goto Exit;
        }

        std::vector<uint64_t> helper_id_address;
        for (auto& [helper_id, address] : helper_id_to_address) {
            helper_id_address.push_back(address.address);
        }

        ebpf_code_buffer_t machine_code(MAX_NATIVE_CODE_SIZE_IN_BYTES);
        uint8_t* byte_code_data = (uint8_t*)instructions;
        size_t byte_code_size = instruction_count * sizeof(*instructions);

        if (execution_type == EBPF_EXECUTION_JIT) {
            size_t machine_code_size = machine_code.size();

            // JIT code.
            vm = ubpf_create();
            if (vm == nullptr) {
                result = EBPF_JIT_COMPILATION_FAILED;
                goto Exit;
            }

            for (uint32_t helper_id = 0; (size_t)helper_id < helper_id_address.size(); helper_id++) {
                if (ubpf_register(
                        vm, helper_id, nullptr, reinterpret_cast<external_function_t>(helper_id_address[helper_id])) <
                    0) {
                    result = EBPF_JIT_COMPILATION_FAILED;
                    goto Exit;
                }
            }

            if (unwind_index != MAXUINT32) {
                ubpf_set_unwind_function_index(vm, unwind_index);
            }

            ubpf_set_error_print(
                vm, reinterpret_cast<int (*)(FILE* stream, const char* format, ...)>(log_function_address));

            if (ubpf_load(
                    vm, byte_code_data, static_cast<uint32_t>(byte_code_size), const_cast<char**>(error_message)) < 0) {
                result = EBPF_JIT_COMPILATION_FAILED;
                goto Exit;
            }

            if (ubpf_translate(vm, machine_code.data(), &machine_code_size, const_cast<char**>(error_message))) {
                result = EBPF_JIT_COMPILATION_FAILED;
                goto Exit;
            }
            machine_code.resize(machine_code_size);
            byte_code_data = machine_code.data();
            byte_code_size = machine_code.size();

            if (*error_message != nullptr) {
                *error_message_size = (uint32_t)strlen(*error_message) + 1;
            }
        }

        request_buffer.resize(offsetof(ebpf_operation_load_code_request_t, code) + byte_code_size);
        request = reinterpret_cast<ebpf_operation_load_code_request_t*>(request_buffer.data());
        request->header.id = ebpf_operation_id_t::EBPF_OPERATION_LOAD_CODE;
        request->header.length = static_cast<uint16_t>(request_buffer.size());
        request->program_handle = program_handle;
        request->code_type = execution_type == EBPF_EXECUTION_JIT ? EBPF_CODE_JIT : EBPF_CODE_EBPF;

        memcpy(request->code, byte_code_data, byte_code_size);

        error = invoke_ioctl(request_buffer);

        if (error != ERROR_SUCCESS) {
            result = EBPF_PROGRAM_LOAD_FAILED;
            goto Exit;
        }
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
    } catch (std::runtime_error& err) {
        auto message = err.what();
        *error_message = allocate_string(message, error_message_size);

        result = EBPF_VERIFICATION_FAILED;
    } catch (...) {
        result = EBPF_FAILED;
    }

Exit:
    if (vm) {
        ubpf_destroy(vm);
    }

    return result;
}

#endif

class WinVerifyTrustHelper
{
  public:
    WinVerifyTrustHelper(const wchar_t* path)
    {
        win_trust_data.cbStruct = sizeof(WINTRUST_DATA);
        win_trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
        win_trust_data.dwUIChoice = WTD_UI_NONE;
        win_trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
        win_trust_data.dwUnionChoice = WTD_CHOICE_FILE;

        file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
        file_info.pcwszFilePath = path;

        win_trust_data.pFile = &file_info;

        signature_settings.cbStruct = sizeof(WINTRUST_SIGNATURE_SETTINGS);
        signature_settings.dwFlags = WSS_VERIFY_SPECIFIC | WSS_GET_SECONDARY_SIG_COUNT;
        signature_settings.dwIndex = 0;

        win_trust_data.pSignatureSettings = &signature_settings;

        // Query the number of signatures.
        DWORD error = WinVerifyTrust(nullptr, &generic_action_code, &win_trust_data);
        if (error != ERROR_SUCCESS) {
            SetLastError(error);
            EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, WinVerifyTrust);
            clean_up_win_verify_trust();
            throw std::runtime_error("WinVerifyTrust failed");
        }
    }

    ~WinVerifyTrustHelper() { clean_up_win_verify_trust(); }

    DWORD
    cert_count()
    {
        // The number of signatures is stored in signature_settings.cSecondarySigs.
        // The primary signature is always present, so we add 1 to the count.
        return signature_settings.cSecondarySigs + 1;
    }

    CRYPT_PROVIDER_CERT*
    get_cert(DWORD index)
    {
        // Check if the context currently points to the correct index.
        if (signature_settings.dwIndex != index) {
            clean_up_win_verify_trust();

            win_trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
            win_trust_data.pSignatureSettings->dwIndex = index;

            DWORD error = WinVerifyTrust(nullptr, &generic_action_code, &win_trust_data);
            if (error != ERROR_SUCCESS) {
                SetLastError(error);
                EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, WinVerifyTrust);
                throw std::runtime_error("WinVerifyTrust failed");
            }
        }

        CRYPT_PROVIDER_DATA* provider_data = WTHelperProvDataFromStateData(win_trust_data.hWVTStateData);
        CRYPT_PROVIDER_SGNR* provider_signer = WTHelperGetProvSignerFromChain(provider_data, 0, FALSE, 0);
        CRYPT_PROVIDER_CERT* cert = WTHelperGetProvCertFromChain(provider_signer, 0);

        if (cert == nullptr) {
            EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, WTHelperGetProvCertFromChain);
            throw std::runtime_error("WTHelperGetProvCertFromChain failed");
        }
        return cert;
    }

  private:
    void
    clean_up_win_verify_trust()
    {
        if (win_trust_data.hWVTStateData) {
            win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            // Ignore the return value of WinVerifyTrust on close.
            (void)WinVerifyTrust(nullptr, &generic_action_code, &win_trust_data);
            win_trust_data.hWVTStateData = nullptr;
        }
    }

    GUID generic_action_code = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA win_trust_data = {};
    WINTRUST_FILE_INFO file_info = {};
    WINTRUST_SIGNATURE_SETTINGS signature_settings = {};
};

static std::set<std::string>
_ebpf_extract_eku(_In_ CRYPT_PROVIDER_CERT* cert)
{
    std::set<std::string> eku_set;
    DWORD cb_usage = 0;
    if (!CertGetEnhancedKeyUsage(cert->pCert, 0, nullptr, &cb_usage)) {
        return eku_set;
    }
    std::vector<uint8_t> usage(cb_usage);

    if (!CertGetEnhancedKeyUsage(cert->pCert, 0, reinterpret_cast<PCERT_ENHKEY_USAGE>(usage.data()), &cb_usage)) {
        return eku_set;
    }
    auto pusage = reinterpret_cast<PCERT_ENHKEY_USAGE>(usage.data());
    for (size_t index = 0; index < pusage->cUsageIdentifier; index++) {
        eku_set.insert(pusage->rgpszUsageIdentifier[index]);
    }
    return eku_set;
}

static std::string
_ebpf_extract_issuer(_In_ const CRYPT_PROVIDER_CERT* cert)
{
    DWORD name_cb = CertGetNameStringA(cert->pCert, CERT_NAME_RDN_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, nullptr, 0);

    if (name_cb == 0) {
        return std::string();
    }

    std::vector<char> issuer(name_cb);
    if (CertGetNameStringA(cert->pCert, CERT_NAME_RDN_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, issuer.data(), name_cb) ==
        0) {
        return std::string();
    }
    return std::string(issuer.data());
}

_Must_inspect_result_ ebpf_result_t
ebpf_verify_sys_file_signature(
    _In_z_ const wchar_t* file_name,
    _In_z_ const char* issuer_name,
    size_t eku_count,
    _In_reads_(eku_count) const char** eku_list)
{
    ebpf_result_t result = EBPF_OBJECT_NOT_FOUND;
    EBPF_LOG_ENTRY();
    std::string required_issuer(issuer_name);
    std::set<std::string> required_eku_set;

    if (_ebpf_service_test_signing_enabled) {
        // Test signing is enabled, so we don't verify the signature.
        EBPF_RETURN_RESULT(EBPF_SUCCESS);
    }

    for (size_t i = 0; i < eku_count; i++) {
        required_eku_set.insert(eku_list[i]);
    }

    try {
        WinVerifyTrustHelper wrapper(file_name);

        for (DWORD i = 0; i < wrapper.cert_count(); i++) {

            std::set<std::string> eku_set = _ebpf_extract_eku(wrapper.get_cert(i));
            std::string issuer = _ebpf_extract_issuer(wrapper.get_cert(i));

            if (issuer != required_issuer) {
                EBPF_LOG_MESSAGE_STRING(
                    EBPF_TRACELOG_LEVEL_ERROR,
                    EBPF_TRACELOG_KEYWORD_API,
                    "Certificate issuer mismatch",
                    issuer.c_str());
                continue;
            }

            std::set<std::string> eku_intersection;
            std::set_intersection(
                eku_set.begin(),
                eku_set.end(),
                required_eku_set.begin(),
                required_eku_set.end(),
                std::inserter(eku_intersection, eku_intersection.begin()));

            if (eku_intersection.size() != required_eku_set.size()) {
                EBPF_LOG_MESSAGE_STRING(
                    EBPF_TRACELOG_LEVEL_ERROR,
                    EBPF_TRACELOG_KEYWORD_API,
                    "Certificate EKU mismatch",
                    "Required EKUs not found in certificate");
                continue;
            }

            // The certificate is valid and has the required EKUs.
            result = EBPF_SUCCESS;
            break;
        }
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        EBPF_LOG_MESSAGE_ERROR(
            EBPF_TRACELOG_LEVEL_ERROR,
            EBPF_TRACELOG_KEYWORD_API,
            "Memory allocation failed during signature verification",
            result);
    } catch (const std::runtime_error&) {
        result = EBPF_INVALID_ARGUMENT;
        EBPF_LOG_WIN32_API_FAILURE(EBPF_TRACELOG_KEYWORD_API, WinVerifyTrust);
    }

    EBPF_RETURN_RESULT(result);
}

static const char* _ebpf_required_issuer = EBPF_REQUIRED_ISSUER;
static const char* _ebpf_required_eku_list[] = {
    EBPF_CODE_SIGNING_EKU,
    EBPF_VERIFICATION_EKU,
};

_Must_inspect_result_ ebpf_result_t
ebpf_verify_signature_and_open_file(_In_z_ const char* file_path, _Out_ HANDLE* file_handle) noexcept
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result = EBPF_SUCCESS;
    try {
        std::wstring file_path_wide;
        int file_path_length = MultiByteToWideChar(CP_UTF8, 0, file_path, -1, nullptr, 0);
        if (file_path_length <= 0) {
            result = win32_error_code_to_ebpf_result(GetLastError());
            EBPF_LOG_MESSAGE_ERROR(
                EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "MultiByteToWideChar failed", result);
            EBPF_RETURN_RESULT(result);
        }
        file_path_wide.resize(file_path_length);

        if (MultiByteToWideChar(CP_UTF8, 0, file_path, -1, file_path_wide.data(), file_path_length) <= 0) {
            result = win32_error_code_to_ebpf_result(GetLastError());
            EBPF_LOG_MESSAGE_ERROR(
                EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "MultiByteToWideChar failed", result);
            EBPF_RETURN_RESULT(result);
        }

        *file_handle = CreateFileW(
            file_path_wide.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
            nullptr);

        if (*file_handle == INVALID_HANDLE_VALUE) {
            result = win32_error_code_to_ebpf_result(GetLastError());
            EBPF_LOG_MESSAGE_ERROR(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "CreateFileW failed", result);
            EBPF_RETURN_RESULT(result);
        }

        // Note: Signature verification is done after the file is opened to ensure that the file exists and can not be
        // modified.
        result = ebpf_verify_sys_file_signature(
            file_path_wide.c_str(),
            _ebpf_required_issuer,
            sizeof(_ebpf_required_eku_list) / sizeof(_ebpf_required_eku_list[0]),
            _ebpf_required_eku_list);

        EBPF_RETURN_RESULT(result);
    } catch (const std::bad_alloc&) {
        EBPF_RETURN_RESULT(EBPF_NO_MEMORY);
    } catch (const std::exception&) {
        EBPF_RETURN_RESULT(EBPF_FAILED);
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_authorize_native_module(_In_ const GUID* module_id, _In_ HANDLE native_image_handle) noexcept
{
    EBPF_LOG_ENTRY();

    ebpf_result_t result = EBPF_SUCCESS;
    HANDLE file_mapping_handle = NULL;
    void* file_mapping_view = nullptr;
    size_t file_size = 0;
    ebpf_operation_authorize_native_module_request_t request;
    uint32_t error = ERROR_SUCCESS;

    file_mapping_handle = CreateFileMappingW(native_image_handle, nullptr, PAGE_READONLY, 0, 0, nullptr);

    if (file_mapping_handle == NULL) {
        result = win32_error_code_to_ebpf_result(GetLastError());
        EBPF_LOG_MESSAGE_ERROR(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "CreateFileMappingW failed", result);
        goto Done;
    }

    file_size = GetFileSize(native_image_handle, nullptr);

    if (file_size == INVALID_FILE_SIZE) {
        result = win32_error_code_to_ebpf_result(GetLastError());
        EBPF_LOG_MESSAGE_ERROR(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "GetFileSize failed", result);
        goto Done;
    }

    file_mapping_view = MapViewOfFile(file_mapping_handle, FILE_MAP_READ, 0, 0, file_size);

    if (file_mapping_view == nullptr) {
        result = win32_error_code_to_ebpf_result(GetLastError());
        EBPF_LOG_MESSAGE_ERROR(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "MapViewOfFile failed", result);
        goto Done;
    }

    try {
        // Compute the SHA256 hash of the file.
        hash_t hash("SHA256");
        auto sha256_hash = hash.hash_byte_ranges({{(uint8_t*)file_mapping_view, file_size}});
        std::copy(sha256_hash.begin(), sha256_hash.end(), request.module_hash);
        request.header.id = ebpf_operation_id_t::EBPF_OPERATION_AUTHORIZE_NATIVE_MODULE;
        request.header.length = static_cast<uint16_t>(sizeof(request));
        request.module_id = *module_id;
    } catch (const std::bad_alloc&) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    error = invoke_ioctl(request);
    if (error != ERROR_SUCCESS) {
        result = win32_error_code_to_ebpf_result(error);
        EBPF_LOG_MESSAGE_ERROR(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_API, "invoke_ioctl failed", result);
        goto Done;
    }

Done:
    if (file_mapping_view) {
        UnmapViewOfFile(file_mapping_view);
    }
    if (file_mapping_handle != INVALID_HANDLE_VALUE && file_mapping_handle != 0) {
        CloseHandle(file_mapping_handle);
    }

    EBPF_RETURN_RESULT(result);
}

/**
 * @brief Initialize the test signing state.
 *
 * @retval EBPF_SUCCESS The operation was successful.
 * @retval EBPF_INVALID_ARGUMENT The reply from the driver was invalid.
 * @retval EBPF_NO_MEMORY Insufficient memory to complete the operation.
 */
static _Must_inspect_result_ ebpf_result_t
_initialize_test_signing_state()
{
    _ebpf_service_test_signing_enabled = false;
    _ebpf_service_hypervisor_kernel_mode_code_enforcement_enabled = false;

    ebpf_operation_get_code_integrity_state_request_t request{
        sizeof(ebpf_operation_get_code_integrity_state_request_t),
        ebpf_operation_id_t::EBPF_OPERATION_GET_CODE_INTEGRITY_STATE};
    ebpf_operation_get_code_integrity_state_reply_t reply;

    uint32_t error = invoke_ioctl(request, reply);
    if (error != ERROR_SUCCESS) {
        return win32_error_code_to_ebpf_result(error);
    }

    if (reply.header.id != ebpf_operation_id_t::EBPF_OPERATION_GET_CODE_INTEGRITY_STATE) {
        return EBPF_INVALID_ARGUMENT;
    }

    _ebpf_service_test_signing_enabled = reply.test_signing_enabled;
    _ebpf_service_hypervisor_kernel_mode_code_enforcement_enabled = reply.hypervisor_code_integrity_enabled;

    return EBPF_SUCCESS;
}

uint32_t
ebpf_service_initialize() noexcept
{
    // This is best effort. If device handle does not initialize,
    // it will be re-attempted before an IOCTL call is made.
    // This is needed to ensure the service can successfully start
    // even if the driver is not installed.
    (void)initialize_async_device_handle();

    ebpf_result_t result = _initialize_test_signing_state();
    if (result != EBPF_SUCCESS) {
        switch (result) {
        case EBPF_NO_MEMORY:
            return ERROR_NOT_ENOUGH_MEMORY;
        case EBPF_INVALID_ARGUMENT:
            return ERROR_INVALID_PARAMETER;
        default:
            return ERROR_NOT_SUPPORTED;
        }
    }

    return ERROR_SUCCESS;
}

void
ebpf_service_cleanup() noexcept
{
    clean_up_async_device_handle();
}
