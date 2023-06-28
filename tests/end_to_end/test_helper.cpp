// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "api_common.hpp"
#include "api_internal.h"
#include "bpf/bpf.h"
#include "bpf2c.h"
#include "catch_wrapper.hpp"
#include "ebpf_async.h"
#include "ebpf_core.h"
#include "ebpf_platform.h"
#include "hash.h"
#include "helpers.h"
#include "mock.h"
#include "test_helper.hpp"
#include "usersim/../../src/fault_injection.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <map>
#include <mutex>
#include <sstream>
using namespace std::chrono_literals;

extern "C" bool ebpf_fuzzing_enabled;

bool _ebpf_capture_corpus = false;

extern "C" metadata_table_t*
get_metadata_table();

static bool _expect_native_module_load_failures = false;

#define SERVICE_PATH_PREFIX L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"
#define CREATE_FILE_HANDLE 0x12345678

static GUID _bpf2c_npi_id = {/* c847aac8-a6f2-4b53-aea3-f4a94b9a80cb */
                             0xc847aac8,
                             0xa6f2,
                             0x4b53,
                             {0xae, 0xa3, 0xf4, 0xa9, 0x4b, 0x9a, 0x80, 0xcb}};

static GUID _ebpf_native_provider_id = {/* 5e24d2f5-f799-42c3-a945-87feefd930a7 */
                                        0x5e24d2f5,
                                        0xf799,
                                        0x42c3,
                                        {0xa9, 0x45, 0x87, 0xfe, 0xef, 0xd9, 0x30, 0xa7}};

static NPI_CLIENT_ATTACH_PROVIDER_FN _test_helper_client_attach_provider;
static NPI_CLIENT_DETACH_PROVIDER_FN _test_helper_client_detach_provider;

typedef struct _service_context
{
    std::wstring name;
    std::wstring file_path;
    intptr_t handle{};
    NPI_MODULEID module_id{
        sizeof(NPI_MODULEID),
        MIT_GUID,
    };
    HMODULE dll{};
    bool loaded = false;
    HANDLE nmr_client_handle{};
    NPI_CLIENT_CHARACTERISTICS nmr_client_characteristics = {
        0,
        sizeof(NPI_CLIENT_CHARACTERISTICS),
        _test_helper_client_attach_provider,
        _test_helper_client_detach_provider,
        nullptr,
        {
            0,
            sizeof(NPI_REGISTRATION_INSTANCE),
            &_bpf2c_npi_id,
            &module_id,
            0,
            nullptr,
        },
    };
    bool delete_pending = false;
} service_context_t;

static std::mutex _fd_to_handle_mutex;
static uint64_t _ebpf_file_descriptor_counter = 0;
_Guarded_by_(_fd_to_handle_mutex) static std::map<fd_t, ebpf_handle_t> _fd_to_handle_map;

static std::mutex _service_path_to_context_mutex;
static uint32_t _ebpf_service_handle_counter = 0;
_Guarded_by_(
    _service_path_to_context_mutex) static std::map<std::wstring, service_context_t*> _service_path_to_context_map;

class duplicate_handles_table_t
{
  public:
    duplicate_handles_table_t() : _rundown_in_progress(false), _all_duplicate_handles_closed(nullptr) {}
    ~duplicate_handles_table_t() = default;

    bool
    reference_or_add(ebpf_handle_t handle)
    {
        bool success = true;
        std::unique_lock lock(_lock);
        if (!_rundown_in_progress) {
            std::map<ebpf_handle_t, uint16_t>::iterator it = _duplicate_count_table.find(handle);
            if (it != _duplicate_count_table.end()) {
                it->second++;
            } else {
                try {
                    // The reference count of newly inserted duplicate handle is 2 (for original + first duplicate).
                    _duplicate_count_table.insert(std::pair<ebpf_handle_t, uint16_t>(handle, static_cast<uint16_t>(2)));
                } catch (...) {
                    success = false;
                }
            }
        }
        return success;
    }

    bool
    dereference_if_found(ebpf_handle_t handle)
    {
        bool found = false;

        std::unique_lock lock(_lock);
        std::map<ebpf_handle_t, uint16_t>::iterator it = _duplicate_count_table.find(handle);
        if (it != _duplicate_count_table.end()) {
            found = true;
            // Dereference the handle. If the reference count drops to 0, close the handle.
            if (--it->second == 0) {
                _duplicate_count_table.erase(handle);
                REQUIRE(ebpf_api_close_handle(handle) == EBPF_SUCCESS);
            }
            if (_rundown_in_progress && _duplicate_count_table.size() == 0) {
                // All duplicate handles have been closed. Fulfill the promise.
                REQUIRE(_all_duplicate_handles_closed != nullptr);
                _all_duplicate_handles_closed->set_value();
            }
        }

        return found;
    }

    void
    rundown()
    {
        std::unique_lock lock(_lock);
        std::future<void> all_duplicate_handles_closed_callback;
        bool duplicates_pending = false;
        if (_duplicate_count_table.size() > 0) {
            duplicates_pending = true;
            _all_duplicate_handles_closed = new (std::nothrow) std::promise<void>();
            REQUIRE(_all_duplicate_handles_closed != nullptr);
            all_duplicate_handles_closed_callback = _all_duplicate_handles_closed->get_future();
            _rundown_in_progress = true;
        }
        lock.unlock();
        if (duplicates_pending) {
            // Wait for at most 1 second for all duplicate handles to be closed.
            REQUIRE(all_duplicate_handles_closed_callback.wait_for(1s) == std::future_status::ready);
        }

        lock.lock();
        _rundown_in_progress = false;
        delete _all_duplicate_handles_closed;
        _all_duplicate_handles_closed = nullptr;
    }

  private:
    std::mutex _lock;
    // Map of handles to duplicate count.
    std::map<ebpf_handle_t, uint16_t> _duplicate_count_table;
    bool _rundown_in_progress;
    std::promise<void>* _all_duplicate_handles_closed;
};

static duplicate_handles_table_t _duplicate_handles;

static std::string
_get_environment_variable_as_string(const std::string& name)
{
    std::string value;
    size_t required_size = 0;
    getenv_s(&required_size, nullptr, 0, name.c_str());
    if (required_size > 0) {
        value.resize(required_size);
        getenv_s(&required_size, &value[0], required_size, name.c_str());
        value.resize(required_size - 1);
    }
    return value;
}

/**
 * @brief Get an environment variable as a boolean.
 *
 * @param[in] name Environment variable name.
 * @retval false Environment variable is set to "false", "0", or if it's not set.
 * @retval true Environment variable is set to any other value.
 */
static bool
_get_environment_variable_as_bool(const std::string& name)
{
    std::string value = _get_environment_variable_as_string(name);
    if (value.empty()) {
        return false;
    }

    // Convert value to lower case.
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    if (value == "false") {
        return false;
    }
    if (value == "0") {
        return false;
    }
    return true;
}

HANDLE
GlueCreateFileW(
    _In_z_ const wchar_t* file_name,
    unsigned long desired_access,
    unsigned long share_mode,
    _In_opt_ SECURITY_ATTRIBUTES* security_attributes,
    unsigned long creation_disposition,
    unsigned long flags_and_attributes,
    HANDLE template_file)
{
    UNREFERENCED_PARAMETER(file_name);
    UNREFERENCED_PARAMETER(desired_access);
    UNREFERENCED_PARAMETER(share_mode);
    UNREFERENCED_PARAMETER(security_attributes);
    UNREFERENCED_PARAMETER(creation_disposition);
    UNREFERENCED_PARAMETER(flags_and_attributes);
    UNREFERENCED_PARAMETER(template_file);

    return (HANDLE)CREATE_FILE_HANDLE;
}

bool
GlueCloseHandle(HANDLE object_handle)
{
    if (object_handle == (HANDLE)CREATE_FILE_HANDLE) {
        return TRUE;
    }

    ebpf_handle_t handle = reinterpret_cast<ebpf_handle_t>(object_handle);
    bool found = _duplicate_handles.dereference_if_found(handle);
    if (!found) {
        // No duplicates. Close the handle.
        if (!(ebpf_api_close_handle(handle) == EBPF_SUCCESS || ebpf_fuzzing_enabled)) {
            throw std::runtime_error("ebpf_api_close_handle failed");
        }
    }

    return TRUE;
}

bool
GlueDuplicateHandle(
    HANDLE source_process_handle,
    HANDLE source_handle,
    HANDLE target_process_handle,
    _Out_ HANDLE* target_handle,
    unsigned long desired_access,
    bool inherit_handle,
    unsigned long options)
{
    UNREFERENCED_PARAMETER(source_process_handle);
    UNREFERENCED_PARAMETER(target_process_handle);
    UNREFERENCED_PARAMETER(desired_access);
    UNREFERENCED_PARAMETER(inherit_handle);
    UNREFERENCED_PARAMETER(options);
    // Return the same value for duplicated handle.
    *target_handle = source_handle;
    return !!_duplicate_handles.reference_or_add(reinterpret_cast<ebpf_handle_t>(source_handle));
}

static void
_complete_overlapped(_Inout_ void* context, size_t output_buffer_length, ebpf_result_t result)
{
    UNREFERENCED_PARAMETER(output_buffer_length);
    auto overlapped = reinterpret_cast<OVERLAPPED*>(context);
    overlapped->InternalHigh = static_cast<ULONG_PTR>(output_buffer_length);
    overlapped->Internal = ebpf_result_to_ntstatus(result);
    SetEvent(overlapped->hEvent);
}

bool
GlueCancelIoEx(_In_ HANDLE file_handle, _In_opt_ OVERLAPPED* overlapped)
{
    UNREFERENCED_PARAMETER(file_handle);
    bool return_value = FALSE;
    if (overlapped != nullptr) {
        return_value = ebpf_core_cancel_protocol_handler(overlapped);
    }
    return return_value;
}

#pragma warning(push)
#pragma warning(disable : 6001) // Using uninitialized memory 'context'
_Requires_lock_not_held_(_service_path_to_context_mutex) static void _unload_all_native_modules()
{
    std::unique_lock lock(_service_path_to_context_mutex);
    for (auto& [path, context] : _service_path_to_context_map) {
        if (context->loaded) {
            if (context->nmr_client_handle) {
                NTSTATUS status = NmrDeregisterClient(context->nmr_client_handle);
                if (status == STATUS_PENDING) {
                    // Wait for the deregistration to complete.
                    NmrWaitForClientDeregisterComplete(context->nmr_client_handle);
                } else {
                    REQUIRE(NT_SUCCESS(status));
                }
                context->nmr_client_handle = nullptr;
            }
        }
        // The service should have been marked for deletion till now.
        REQUIRE((context->delete_pending || get_native_module_failures()));
        if (context->dll != nullptr) {
            FreeLibrary(context->dll);
        }
        ebpf_free(context);
    }
    _service_path_to_context_map.clear();
}
#pragma warning(pop)

static struct
{
    int reserved;
} _test_helper_client_dispatch_table;

static NTSTATUS
_test_helper_client_attach_provider(
    _In_ HANDLE nmr_binding_handle,
    _In_ void* client_context,
    _In_ const NPI_REGISTRATION_INSTANCE* provider_registration_instance)
{
    UNREFERENCED_PARAMETER(provider_registration_instance);
    void* provider_binding_context = NULL;
    const void* provider_dispatch_table = NULL;
    return NmrClientAttachProvider(
        nmr_binding_handle,
        client_context,
        &_test_helper_client_dispatch_table,
        &provider_binding_context,
        &provider_dispatch_table);
}

static NTSTATUS
_test_helper_client_detach_provider(_In_ void* client_binding_context)
{
    UNREFERENCED_PARAMETER(client_binding_context);
    return STATUS_SUCCESS;
}

static void
_preprocess_load_native_module(_Inout_ service_context_t* context)
{
    context->dll = LoadLibraryW(context->file_path.c_str());
    REQUIRE(((context->dll != nullptr) || get_native_module_failures()));

    if (context->dll == nullptr) {
        return;
    }

    auto get_function =
        reinterpret_cast<decltype(&get_metadata_table)>(GetProcAddress(context->dll, "get_metadata_table"));
    if (get_function == nullptr) {
        REQUIRE(get_native_module_failures());
        return;
    }

    metadata_table_t* table = get_function();
    REQUIRE(table != nullptr);
    context->nmr_client_characteristics.ClientRegistrationInstance.NpiSpecificCharacteristics = table;

    REQUIRE(NT_SUCCESS(NmrRegisterClient(&context->nmr_client_characteristics, context, &context->nmr_client_handle)));

    context->loaded = true;
}

_Requires_lock_not_held_(_service_path_to_context_mutex) static void _preprocess_ioctl(
    _In_ const ebpf_operation_header_t* user_request)
{
    switch (user_request->id) {
    case EBPF_OPERATION_LOAD_NATIVE_MODULE: {
        try {
            const ebpf_operation_load_native_module_request_t* request =
                (ebpf_operation_load_native_module_request_t*)user_request;
            size_t service_name_length = ((uint8_t*)request) + request->header.length - (uint8_t*)request->data;
            REQUIRE(((service_name_length % 2 == 0) || ebpf_fuzzing_enabled));

            std::wstring service_path;
            service_path.assign((wchar_t*)request->data, service_name_length / 2);

            std::unique_lock lock(_service_path_to_context_mutex);
            auto context = _service_path_to_context_map.find(service_path);
            if (context != _service_path_to_context_map.end()) {
                context->second->module_id.Guid = request->module_id;

                if (context->second->loaded) {
                    REQUIRE(get_native_module_failures());
                } else {
                    _preprocess_load_native_module(context->second);
                }
            }
        } catch (...) {
            // Ignore.
        }
        break;
    }
    default:
        break;
    }
}

bool
GlueDeviceIoControl(
    HANDLE device_handle,
    unsigned long io_control_code,
    _In_reads_bytes_(input_buffer_size) void* input_buffer,
    unsigned long input_buffer_size,
    _Out_writes_bytes_to_(output_buffer_size, *bytes_returned) void* output_buffer,
    unsigned long output_buffer_size,
    _Out_ unsigned long* bytes_returned,
    _Inout_ OVERLAPPED* overlapped)
{
    UNREFERENCED_PARAMETER(device_handle);
    UNREFERENCED_PARAMETER(io_control_code);

    ebpf_result_t result;
    const ebpf_operation_header_t* user_request = reinterpret_cast<decltype(user_request)>(input_buffer);
    ebpf_operation_header_t* user_reply = nullptr;
    *bytes_returned = 0;
    auto request_id = user_request->id;
    size_t minimum_request_size = 0;
    size_t minimum_reply_size = 0;
    bool async = false;
    unsigned long sharedBufferSize = (input_buffer_size > output_buffer_size) ? input_buffer_size : output_buffer_size;
    std::vector<uint8_t> sharedBuffer;
    const void* local_input_buffer = nullptr;
    void* local_output_buffer = nullptr;

    result = ebpf_core_get_protocol_handler_properties(request_id, &minimum_request_size, &minimum_reply_size, &async);
    if (result != EBPF_SUCCESS) {
        goto Fail;
    }

    if (user_request->length < minimum_request_size) {
        result = EBPF_INVALID_ARGUMENT;
        goto Fail;
    }

    if (minimum_reply_size > 0) {
        user_reply = reinterpret_cast<decltype(user_reply)>(output_buffer);
        if (!user_reply) {
            result = EBPF_INVALID_ARGUMENT;
            goto Fail;
        }
        if (output_buffer_size < minimum_reply_size) {
            result = EBPF_INVALID_ARGUMENT;
            goto Fail;
        }
    }

    // Intercept the call to perform any IOCTL specific _pre_ tasks.
    _preprocess_ioctl(user_request);

    if (!async) {
        // In the kernel execution context, the request and reply share
        // the same memory.  So to catch bugs that only show up in that
        // case, we force the same here.
        sharedBuffer.resize(sharedBufferSize);
        memcpy(sharedBuffer.data(), user_request, input_buffer_size);
        local_input_buffer = sharedBuffer.data();
        local_output_buffer = (minimum_reply_size > 0) ? sharedBuffer.data() : nullptr;
    } else {
        local_input_buffer = user_request;
        local_output_buffer = user_reply;
    }

    result = ebpf_core_invoke_protocol_handler(
        request_id,
        local_input_buffer,
        static_cast<uint16_t>(input_buffer_size),
        local_output_buffer,
        static_cast<uint16_t>(output_buffer_size),
        overlapped,
        _complete_overlapped);

    if (!async && minimum_reply_size > 0) {
        memcpy(user_reply, sharedBuffer.data(), output_buffer_size);
    }

    if (result != EBPF_SUCCESS) {
        goto Fail;
    }

    if (user_reply) {
        *bytes_returned = user_reply->length;
    }
    return TRUE;

Fail:
    if (result != EBPF_SUCCESS) {
        SetLastError(ebpf_result_to_win32_error_code(result));
    }

    return FALSE;
}

_Requires_lock_not_held_(_fd_to_handle_mutex) int Glue_open_osfhandle(intptr_t os_file_handle, int flags)
{
    UNREFERENCED_PARAMETER(flags);
    try {
        fd_t fd = static_cast<fd_t>(InterlockedIncrement(&_ebpf_file_descriptor_counter));
        std::unique_lock lock(_fd_to_handle_mutex);
        _fd_to_handle_map.insert(std::pair<fd_t, ebpf_handle_t>(fd, os_file_handle));
        return fd;
    } catch (...) {
        return ebpf_fd_invalid;
    }
}

_Requires_lock_not_held_(_fd_to_handle_mutex) intptr_t Glue_get_osfhandle(int file_descriptor)
{
    if (file_descriptor == ebpf_fd_invalid) {
        errno = EINVAL;
        return ebpf_handle_invalid;
    }

    std::unique_lock lock(_fd_to_handle_mutex);
    std::map<fd_t, ebpf_handle_t>::iterator it = _fd_to_handle_map.find(file_descriptor);
    if (it != _fd_to_handle_map.end()) {
        return it->second;
    }

    errno = EINVAL;
    return ebpf_handle_invalid;
}

_Requires_lock_not_held_(_fd_to_handle_mutex) int Glue_close(int file_descriptor)
{
    if (file_descriptor == ebpf_fd_invalid) {
        errno = EINVAL;
        return ebpf_handle_invalid;
    }

    std::unique_lock lock(_fd_to_handle_mutex);
    std::map<fd_t, ebpf_handle_t>::iterator it = _fd_to_handle_map.find(file_descriptor);
    if (it == _fd_to_handle_map.end()) {
        errno = EINVAL;
        return -1;
    } else {
        GlueCloseHandle(reinterpret_cast<HANDLE>(it->second));
        _fd_to_handle_map.erase(file_descriptor);
        return 0;
    }
}

_Requires_lock_not_held_(_service_path_to_context_mutex) uint32_t Glue_create_service(
    _In_z_ const wchar_t* service_name, _In_z_ const wchar_t* file_path, _Out_ SC_HANDLE* service_handle)
{
    *service_handle = (SC_HANDLE)0;
    try {
        std::wstring service_path(SERVICE_PATH_PREFIX);
        service_path = service_path + service_name;

        service_context_t* context = new (std::nothrow) service_context_t();
        if (context == nullptr) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        context->name.assign(service_name);
        context->file_path.assign(file_path);

        std::unique_lock lock(_service_path_to_context_mutex);
        _service_path_to_context_map.insert(std::pair<std::wstring, service_context_t*>(service_path, context));
        context->handle = InterlockedIncrement64((int64_t*)&_ebpf_service_handle_counter);

        *service_handle = (SC_HANDLE)context->handle;
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    return ERROR_SUCCESS;
}

_Requires_lock_not_held_(_service_path_to_context_mutex) uint32_t Glue_delete_service(SC_HANDLE handle)
{
    std::unique_lock lock(_service_path_to_context_mutex);
    for (auto& [path, context] : _service_path_to_context_map) {
        if (context->handle == (intptr_t)handle) {
            // Delete the service if it has not been loaded yet. Otherwise
            // mark it pending for delete.
            if (!context->loaded) {
                ebpf_free(context);
                _service_path_to_context_map.erase(path);
            } else {
                context->delete_pending = true;
            }
            break;
        }
    }

    return ERROR_SUCCESS;
}

_test_helper_end_to_end::_test_helper_end_to_end()
{
    if (_get_environment_variable_as_bool("EBPF_GENERATE_CORPUS")) {
        device_io_control_handler = [](HANDLE hDevice,
                                       unsigned long dwIoControlCode,
                                       void* lpInBuffer,
                                       unsigned long nInBufferSize,
                                       void* lpOutBuffer,
                                       unsigned long nOutBufferSize,
                                       unsigned long* lpBytesReturned,
                                       OVERLAPPED* lpOverlapped) -> bool {
            UNREFERENCED_PARAMETER(hDevice);
            UNREFERENCED_PARAMETER(dwIoControlCode);
            UNREFERENCED_PARAMETER(lpOutBuffer);
            UNREFERENCED_PARAMETER(nOutBufferSize);
            UNREFERENCED_PARAMETER(lpBytesReturned);
            UNREFERENCED_PARAMETER(lpOverlapped);

            // Generate SHA1 of the input buffer and write it to an output file.
            hash_t hash("SHA1");

            auto sha1_hash = hash.hash_byte_ranges({{(uint8_t*)lpInBuffer, nInBufferSize}});

            // Convert the hash to a string.
            std::ostringstream hash_string;
            hash_string << std::hex << std::setfill('0');
            for (auto byte : sha1_hash) {
                hash_string << std::setw(2) << (int)byte;
            }

            if (!std::filesystem::exists("corpus\\" + hash_string.str())) {

                // Write the hash to a file.
                std::ofstream output_file("corpus\\" + hash_string.str(), std::ios::binary);
                output_file.write((char*)lpInBuffer, nInBufferSize);
                output_file.close();
            }

            return GlueDeviceIoControl(
                hDevice,
                dwIoControlCode,
                lpInBuffer,
                nInBufferSize,
                lpOutBuffer,
                nOutBufferSize,
                lpBytesReturned,
                lpOverlapped);
        };
    } else {
        device_io_control_handler = GlueDeviceIoControl;
    }
    cancel_io_ex_handler = GlueCancelIoEx;
    create_file_handler = GlueCreateFileW;
    close_handle_handler = GlueCloseHandle;
    duplicate_handle_handler = GlueDuplicateHandle;
    open_osfhandle_handler = Glue_open_osfhandle;
    get_osfhandle_handler = Glue_get_osfhandle;
    close_handler = Glue_close;
    create_service_handler = Glue_create_service;
    delete_service_handler = Glue_delete_service;
    REQUIRE(ebpf_core_initiate() == EBPF_SUCCESS);
    ec_initialized = true;
    REQUIRE(ebpf_api_initiate() == EBPF_SUCCESS);
    api_initialized = true;
}

_test_handle_helper::~_test_handle_helper()
{
    if (handle != ebpf_handle_invalid) {
        GlueCloseHandle((HANDLE)handle);
    }
}

_Requires_lock_not_held_(_fd_to_handle_mutex) static void _rundown_osfhandles()
{
    std::vector<int> fds_to_close;

    // Scoping the lock for automatic destructor call
    {
        std::unique_lock lock(_fd_to_handle_mutex);
        for (auto [fd, handle] : _fd_to_handle_map) {
            fds_to_close.push_back(fd);
        }
    }

    for (auto fd : fds_to_close) {
        Glue_close(fd);
    }
}

void
clear_program_info_cache();

_test_helper_end_to_end::~_test_helper_end_to_end()
{
    try {
        _rundown_osfhandles();

        // Run down duplicate handles, if any.
        _duplicate_handles.rundown();

        // Detach all the native module clients.
        _unload_all_native_modules();

        clear_program_info_cache();
        if (api_initialized) {
            ebpf_api_terminate();
        }
        if (ec_initialized) {
            ebpf_core_terminate();
        }

        device_io_control_handler = nullptr;
        cancel_io_ex_handler = nullptr;
        create_file_handler = nullptr;
        close_handle_handler = nullptr;
        duplicate_handle_handler = nullptr;

        _expect_native_module_load_failures = false;

        set_verification_in_progress(false);
    } catch (Catch::TestFailureException&) {
    }
}

_test_helper_libbpf::_test_helper_libbpf()
{
    ebpf_clear_thread_local_storage();

    try {
        xdp_program_info = new program_info_provider_t(EBPF_PROGRAM_TYPE_XDP);
        xdp_hook = new single_instance_hook_t(EBPF_PROGRAM_TYPE_XDP, EBPF_ATTACH_TYPE_XDP);

        bind_program_info = new program_info_provider_t(EBPF_PROGRAM_TYPE_BIND);
        bind_hook = new single_instance_hook_t(EBPF_PROGRAM_TYPE_BIND, EBPF_ATTACH_TYPE_BIND);

        cgroup_sock_addr_program_info = new program_info_provider_t(EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR);
        cgroup_inet4_connect_hook =
            new single_instance_hook_t(EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR, EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT);
    } catch (...) {
        delete xdp_hook;
        delete xdp_program_info;

        delete bind_hook;
        delete bind_program_info;

        delete cgroup_inet4_connect_hook;
        delete cgroup_sock_addr_program_info;

        throw;
    }
}

_test_helper_libbpf::~_test_helper_libbpf()
{
    delete xdp_hook;
    delete xdp_program_info;

    delete bind_hook;
    delete bind_program_info;

    delete cgroup_inet4_connect_hook;
    delete cgroup_sock_addr_program_info;
}

void
set_native_module_failures(bool expected)
{
    _expect_native_module_load_failures = expected;
}

bool
get_native_module_failures()
{
    return _expect_native_module_load_failures || usersim_fault_injection_is_enabled();
}

_Must_inspect_result_ ebpf_result_t
get_service_details_for_file(
    _In_ const std::wstring& file_path, _Out_ const wchar_t** service_name, _Out_ GUID* provider_guid)
{
    std::unique_lock lock(_service_path_to_context_mutex);
    for (auto& [path, context] : _service_path_to_context_map) {
        if (context->file_path == file_path) {
            *service_name = context->name.c_str();
            *provider_guid = context->module_id.Guid;
            return EBPF_SUCCESS;
        }
    }

    return EBPF_OBJECT_NOT_FOUND;
}