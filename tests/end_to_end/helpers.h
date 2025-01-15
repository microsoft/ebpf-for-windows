// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT
#pragma once

#include "ebpf_api.h"
#include "ebpf_extension_uuids.h"
#include "ebpf_nethooks.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "net_ebpf_ext_program_info.h"
#include "net_ebpf_ext_xdp_hooks.h"
#include "sample_ext_program_info.h"
#include "usersim/ke.h"

// We need the NET_BUFFER typedefs without the other NT kernel defines that
// ndis.h might pull in and conflict with user-mode headers.
#ifndef _NDIS_
typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;
#pragma warning(disable : 4324) // structure was padded due to alignment specifier
#include <ndis/nbl.h>
#endif
#include <vector>

typedef struct _sample_program_context_header
{
    EBPF_CONTEXT_HEADER;
    sample_program_context_t context;
} sample_program_context_header_t;

typedef struct _bind_context_header
{
    uint64_t context_header[8];
    bind_md_t context;
} bind_context_header_t;

#define INITIALIZE_BIND_CONTEXT      \
    bind_context_header_t header{0}; \
    bind_md_t* ctx = &header.context;

#define INITIALIZE_SAMPLE_CONTEXT              \
    sample_program_context_header_t header{0}; \
    sample_program_context_t* ctx = &header.context;

bpf_attach_type_t
ebpf_get_bpf_attach_type(_In_ const ebpf_attach_type_t* ebpf_attach_type) noexcept;

typedef struct _ebpf_free_memory
{
    void
    operator()(uint8_t* memory)
    {
        ebpf_free(memory);
    }
} ebpf_free_memory_t;

typedef std::unique_ptr<uint8_t, ebpf_free_memory_t> ebpf_memory_t;

typedef struct _close_bpf_link
{
    void
    operator()(_In_opt_ _Post_invalid_ bpf_link* link)
    {
        if (link != nullptr) {
            if (ebpf_link_detach(link) != EBPF_SUCCESS) {
                throw std::runtime_error("ebpf_link_detach failed");
            }
            ebpf_link_close(link);
        }
    }
} close_bpf_link_t;

typedef std::unique_ptr<bpf_link, close_bpf_link_t> bpf_link_ptr;

typedef class _emulate_dpc
{
  public:
    _emulate_dpc(uint32_t cpu_id)
    {
        ebpf_assert_success(ebpf_set_current_thread_cpu_affinity(cpu_id, &old_thread_affinity_mask));
        KeRaiseIrql(DISPATCH_LEVEL, &old_irql);
    }
    ~_emulate_dpc()
    {
        KeLowerIrql(old_irql);

        ebpf_restore_current_thread_cpu_affinity(&old_thread_affinity_mask);
    }

  private:
    GROUP_AFFINITY old_thread_affinity_mask;
    KIRQL old_irql;

} emulate_dpc_t;

typedef class _hook_helper
{
  public:
    _hook_helper(ebpf_attach_type_t attach_type) : _attach_type(attach_type) {}

    _Must_inspect_result_ ebpf_result_t
    attach_link(
        fd_t program_fd,
        _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
        size_t attach_parameters_size,
        _Out_ bpf_link_ptr* unique_link)
    {
        bpf_link* link = nullptr;
        ebpf_result_t result;

        result = ebpf_program_attach_by_fd(program_fd, &_attach_type, attach_parameters, attach_parameters_size, &link);
        if (result == EBPF_SUCCESS) {
            unique_link->reset(link);
        }

        return result;
    }

    _Must_inspect_result_ ebpf_result_t
    attach_link(
        fd_t program_fd,
        _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
        size_t attach_parameters_size,
        _Outptr_ bpf_link** link)
    {
        return ebpf_program_attach_by_fd(program_fd, &_attach_type, attach_parameters, attach_parameters_size, link);
    }

  private:
    ebpf_attach_type_t _attach_type;
} hook_helper_t;

typedef class _single_instance_hook : public _hook_helper
{
  public:
    _single_instance_hook(ebpf_program_type_t program_type, ebpf_attach_type_t attach_type)
        : _hook_helper{attach_type}, client_binding_context(nullptr), client_data(nullptr),
          client_dispatch_table(nullptr), link_object(nullptr), client_registration_instance(nullptr),
          nmr_binding_handle(nullptr), nmr_provider_handle(nullptr)
    {
        attach_provider_data.header = EBPF_ATTACH_PROVIDER_DATA_HEADER;
        attach_provider_data.supported_program_type = program_type;
        attach_provider_data.bpf_attach_type = ebpf_get_bpf_attach_type(&attach_type);
        this->attach_type = attach_type;
        module_id.Guid = attach_type;
    }
    ebpf_result_t
    initialize()
    {
        NTSTATUS status = NmrRegisterProvider(&provider_characteristics, this, &nmr_provider_handle);
        return (status == STATUS_SUCCESS) ? EBPF_SUCCESS : EBPF_FAILED;
    }
    ~_single_instance_hook()
    {
        // Best effort cleanup. Ignore errors.
        if (link_object) {
            (void)ebpf_link_detach(link_object);
            (void)ebpf_link_close(link_object);
        }
        if (nmr_provider_handle != NULL) {
            NTSTATUS status = NmrDeregisterProvider(nmr_provider_handle);
            if (status == STATUS_PENDING) {
                NmrWaitForProviderDeregisterComplete(nmr_provider_handle);
            } else {
                ebpf_assert(status == STATUS_SUCCESS);
            }
        }
    }

    uint32_t
    attach(bpf_program* program)
    {
        return ebpf_program_attach(program, &attach_type, nullptr, 0, &link_object);
    }

    uint32_t
    attach(
        _In_ const bpf_program* program,
        _In_reads_bytes_(attach_parameters_size) void* attach_parameters,
        size_t attach_parameters_size)
    {
        return ebpf_program_attach(program, &attach_type, attach_parameters, attach_parameters_size, &link_object);
    }

    void
    detach()
    {
        if (link_object != nullptr) {
            if (ebpf_link_detach(link_object) == EBPF_SUCCESS) {
                throw std::runtime_error("ebpf_link_detach failed");
            }
            ebpf_link_close(link_object);
            link_object = nullptr;
        }
    }

    _Must_inspect_result_ ebpf_result_t
    detach(
        fd_t program_fd, _In_reads_bytes_(attach_parameter_size) void* attach_parameter, size_t attach_parameter_size)
    {
        ebpf_result_t result = ebpf_program_detach(program_fd, &attach_type, attach_parameter, attach_parameter_size);
        if (result == EBPF_SUCCESS) {
            ebpf_link_close(link_object);
            link_object = nullptr;
        }
        return result;
    }

    void
    detach_link(bpf_link* link)
    {
        if (ebpf_link_detach(link) != EBPF_SUCCESS) {
            throw std::runtime_error("ebpf_link_detach failed");
        }
    }

    void
    close_link(bpf_link* link)
    {
#pragma warning(push)
#pragma warning(disable : 6001) // Using uninitialized memory '*link'.
        ebpf_link_close(link);
#pragma warning(pop)
    }

    void
    detach_and_close_link(_Inout_ bpf_link_ptr* unique_link)
    {
        bpf_link* link = unique_link->release();
        detach_link(link);
        close_link(link);
    }

    _Must_inspect_result_ ebpf_result_t
    fire(_Inout_ void* context, _Out_ uint32_t* result)
    {
        if (client_binding_context == nullptr) {
            return EBPF_EXTENSION_FAILED_TO_LOAD;
        }
        ebpf_result_t (*invoke_program)(_In_ const void* link, _Inout_ void* context, _Out_ uint32_t* result) =
            reinterpret_cast<decltype(invoke_program)>(client_dispatch_table->function[0]);

        return invoke_program(client_binding_context, context, result);
    }

    _Must_inspect_result_ ebpf_result_t
    batch_begin(size_t state_size, _Out_writes_(state_size) void* state)
    {
        if (client_binding_context == nullptr) {
            return EBPF_EXTENSION_FAILED_TO_LOAD;
        }

        ebpf_program_batch_begin_invoke_function_t batch_begin_function;
        batch_begin_function = reinterpret_cast<decltype(batch_begin_function)>(client_dispatch_table->function[1]);

        return batch_begin_function(state_size, state);
    }

    _Must_inspect_result_ ebpf_result_t
    batch_invoke(_Inout_ void* program_context, _Out_ uint32_t* result, _In_ const void* state)
    {
        if (client_binding_context == nullptr) {
            return EBPF_EXTENSION_FAILED_TO_LOAD;
        }

        ebpf_program_batch_invoke_function_t batch_invoke_function;
        batch_invoke_function = reinterpret_cast<decltype(batch_invoke_function)>(client_dispatch_table->function[2]);
        return batch_invoke_function(client_binding_context, program_context, result, state);
    }

    _Must_inspect_result_ ebpf_result_t
    batch_end(_In_ void* state)
    {
        if (client_binding_context == nullptr) {
            return EBPF_EXTENSION_FAILED_TO_LOAD;
        }

        ebpf_program_batch_end_invoke_function_t batch_end_function;
        batch_end_function = reinterpret_cast<decltype(batch_end_function)>(client_dispatch_table->function[3]);
        return batch_end_function(state);
    }

  private:
    static NTSTATUS
    provider_attach_client_callback(
        HANDLE nmr_binding_handle,
        _Inout_ void* provider_context,
        _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
        _In_ const void* client_binding_context,
        _In_ const void* client_dispatch,
        _Out_ void** provider_binding_context,
        _Out_ const void** provider_dispatch)
    {
        auto hook = reinterpret_cast<_single_instance_hook*>(provider_context);

        if (hook->client_binding_context != nullptr) {
            // Can't attach a single-instance provider to a second client.
            return STATUS_NOINTERFACE;
        }
        UNREFERENCED_PARAMETER(nmr_binding_handle);
        hook->client_registration_instance = client_registration_instance;
        hook->client_binding_context = client_binding_context;
        hook->nmr_binding_handle = nmr_binding_handle;
        hook->client_dispatch_table = (ebpf_extension_dispatch_table_t*)client_dispatch;
        *provider_binding_context = provider_context;
        *provider_dispatch = NULL;
        return STATUS_SUCCESS;
    };

    static NTSTATUS
    provider_detach_client_callback(_Inout_ void* provider_binding_context)
    {
        auto hook = reinterpret_cast<_single_instance_hook*>(provider_binding_context);
        hook->client_binding_context = nullptr;
        hook->client_data = nullptr;
        hook->client_dispatch_table = nullptr;

        // There should be no in-progress calls to any client functions,
        // we we can return success rather than pending.
        return EBPF_SUCCESS;
    };
    ebpf_attach_type_t attach_type;
    ebpf_attach_provider_data_t attach_provider_data;

    NPI_MODULEID module_id = {
        sizeof(NPI_MODULEID),
        MIT_GUID,
    };
    const NPI_PROVIDER_CHARACTERISTICS provider_characteristics = {
        0,
        sizeof(provider_characteristics),
        (NPI_PROVIDER_ATTACH_CLIENT_FN*)provider_attach_client_callback,
        (NPI_PROVIDER_DETACH_CLIENT_FN*)provider_detach_client_callback,
        NULL,
        {
            0,
            sizeof(NPI_REGISTRATION_INSTANCE),
            &EBPF_HOOK_EXTENSION_IID,
            &module_id,
            0,
            &attach_provider_data,
        },
    };
    HANDLE nmr_provider_handle;

    PNPI_REGISTRATION_INSTANCE client_registration_instance = nullptr;
    const void* client_binding_context = nullptr;
    const ebpf_extension_data_t* client_data = nullptr;
    const ebpf_extension_dispatch_table_t* client_dispatch_table = nullptr;
    HANDLE nmr_binding_handle = nullptr;
    bpf_link* link_object = nullptr;
} single_instance_hook_t;

typedef class xdp_md_helper : public xdp_md_t
{
  public:
    xdp_md_helper(std::vector<uint8_t>& packet)
        : xdp_md_t{packet.data(), packet.data() + packet.size()}, _packet(&packet), _begin(0), _end(packet.size()),
          cloned_nbl(nullptr)
    {
        original_nbl = &_original_nbl_storage;
        _original_nbl_storage.FirstNetBuffer = &_original_nb;
        _original_nb.DataLength = (unsigned long)packet.size();
        _original_nb.MdlChain = &_original_mdl;
        _original_mdl.byte_count = (unsigned long)packet.size();
        _original_mdl.start_va = packet.data();
    }

    int
    adjust_head(int delta)
    {
        int return_value = 0;
        if (delta == 0)
            // Nothing changes.
            goto Done;

        if (delta > 0) {
            if (_begin + delta > _end) {
                return_value = -1;
                goto Done;
            }
            _begin += delta;
        } else {
            int abs_delta = -delta;
            if (_begin >= abs_delta)
                _begin -= abs_delta;
            else {
                size_t additional_space_needed = abs_delta - _begin;
                const size_t MAX_ADDITIONAL_BYTES = 65536;
                if (additional_space_needed > MAX_ADDITIONAL_BYTES) {
                    return_value = -1;
                    goto Done;
                }
                // Prepend _packet with additional_space_needed count of 0.
                _packet->insert(_packet->begin(), additional_space_needed, 0);
                _begin = 0;
                _end += additional_space_needed;
            }
        }
        // Adjust xdp_md data pointers.
        data = _packet->data() + _begin;
        data_end = _packet->data() + _end;
    Done:
        return return_value;
    }
    NET_BUFFER_LIST* original_nbl;
    NET_BUFFER_LIST* cloned_nbl;

  private:
    NET_BUFFER_LIST _original_nbl_storage;
    NET_BUFFER _original_nb;
    MDL _original_mdl;
    std::vector<uint8_t>* _packet;
    size_t _begin;
    size_t _end;
} xdp_md_helper_t;

typedef class _test_xdp_helper
{
  public:
    static int
    adjust_head(_In_ const xdp_md_t* ctx, int delta)
    {
        return ((xdp_md_helper_t*)ctx)->adjust_head(delta);
    }
} test_xdp_helper_t;

// These are test xdp context creation functions.
static ebpf_result_t
_xdp_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    _In_ size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    _In_ size_t context_size_in,
    _Outptr_ void** context)
{
    ebpf_result_t retval = EBPF_FAILED;
    *context = nullptr;

    xdp_md_t* xdp_context = reinterpret_cast<xdp_md_t*>(malloc(sizeof(xdp_md_t)));
    if (xdp_context == nullptr) {
        goto Done;
    }

    if (context_in) {
        if (context_size_in < sizeof(xdp_md_t)) {
            goto Done;
        }
        xdp_md_t* provided_context = (xdp_md_t*)context_in;
        xdp_context->ingress_ifindex = provided_context->ingress_ifindex;
        xdp_context->data_meta = provided_context->data_meta;
    }

    xdp_context->data = (void*)data_in;
    xdp_context->data_end = (void*)(data_in + data_size_in);

    *context = xdp_context;
    xdp_context = nullptr;
    retval = EBPF_SUCCESS;
Done:
    free(xdp_context);
    xdp_context = nullptr;
    return retval;
}

static void
_xdp_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    if (!context) {
        return;
    }

    xdp_md_t* xdp_context = reinterpret_cast<xdp_md_t*>(context);
    uint8_t* data = reinterpret_cast<uint8_t*>(xdp_context->data);
    uint8_t* data_end = reinterpret_cast<uint8_t*>(xdp_context->data_end);
    size_t data_length = data_end - data;
    if (data_length <= *data_size_out) {
        memmove(data_out, data, data_length);
        *data_size_out = data_length;
    } else {
        *data_size_out = 0;
    }

    if (context_out && *context_size_out >= sizeof(xdp_md_t)) {
        xdp_md_t* provided_context = (xdp_md_t*)context_out;
        provided_context->ingress_ifindex = xdp_context->ingress_ifindex;
        provided_context->data_meta = xdp_context->data_meta;
        *context_size_out = sizeof(xdp_md_t);
    }

    free(context);
}

typedef class _test_global_helper
{
  public:
    static uint64_t
    _sample_get_pid_tgid()
    {
        return 9999;
    }
} test_global_helper_t;

typedef class _test_sample_helper
{
  public:
    static int64_t
    _sample_ebpf_extension_helper_function1(_In_ const sample_program_context_t* context)
    {
        UNREFERENCED_PARAMETER(context);
        return 0;
    }

    static int64_t
    _sample_ebpf_extension_find(_In_ const void* buffer, uint32_t size, _In_ const void* find, uint32_t arg_size)
    {
        UNREFERENCED_PARAMETER(size);
        UNREFERENCED_PARAMETER(arg_size);
        return strstr((char*)buffer, (char*)find) - (char*)buffer;
    }

    static int64_t
    _sample_ebpf_extension_replace(
        _In_ const void* buffer, uint32_t size, int64_t position, _In_ const void* replace, uint32_t arg_size)
    {
        int64_t result = 0;
        char* dest;
        char* end = (char*)buffer + size - 1;
        char* source = (char*)replace;
        UNREFERENCED_PARAMETER(arg_size);

        if (position < 0) {
            result = -1;
            goto Exit;
        }

        if (position >= size) {
            result = -1;
            goto Exit;
        }

        dest = (char*)buffer + position;
        while (dest != end) {
            if (*source == '\0') {
                break;
            }
            *dest++ = *source++;
        }

    Exit:
        return result;
    }

    static int64_t
    _sample_ebpf_extension_helper_implicit_1(
        uint64_t dummy_param1,
        uint64_t dummy_param2,
        uint64_t dummy_param3,
        uint64_t dummy_param4,
        uint64_t dummy_param5,
        _In_ const sample_program_context_t* context)
    {
        UNREFERENCED_PARAMETER(dummy_param1);
        UNREFERENCED_PARAMETER(dummy_param2);
        UNREFERENCED_PARAMETER(dummy_param3);
        UNREFERENCED_PARAMETER(dummy_param4);
        UNREFERENCED_PARAMETER(dummy_param5);
        sample_program_context_t* sample_context = (sample_program_context_t*)context;
        return sample_context->helper_data_1;
    }

    static int64_t
    _sample_ebpf_extension_helper_implicit_2(
        uint32_t arg,
        uint64_t dummy_param1,
        uint64_t dummy_param2,
        uint64_t dummy_param3,
        uint64_t dummy_param4,
        _In_ const sample_program_context_t* context)
    {
        UNREFERENCED_PARAMETER(dummy_param1);
        UNREFERENCED_PARAMETER(dummy_param2);
        UNREFERENCED_PARAMETER(dummy_param3);
        UNREFERENCED_PARAMETER(dummy_param4);
        sample_program_context_t* sample_context = (sample_program_context_t*)context;
        return ((uint64_t)sample_context->helper_data_2 + arg);
    }
} test_sample_helper_t;

// These are test sample context creation functions.
static ebpf_result_t
_sample_test_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    _In_ size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    _In_ size_t context_size_in,
    _Outptr_ void** context)
{
    ebpf_result_t retval = EBPF_FAILED;
    sample_program_context_header_t* context_header = nullptr;
    sample_program_context_t* sample_context = nullptr;
    *context = nullptr;

    // Context is required.
    if (!context_in || context_size_in < sizeof(sample_program_context_t)) {
        retval = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    context_header =
        reinterpret_cast<sample_program_context_header_t*>(malloc(sizeof(sample_program_context_header_t)));
    if (!context_header) {
        goto Done;
    }
    sample_context = &context_header->context;

    memcpy(sample_context, context_in, sizeof(sample_program_context_t));

    if (data_in) {
        sample_context->data_start = (uint8_t*)data_in;
        sample_context->data_end = (uint8_t*)data_in + data_size_in;
    } else {
        sample_context->data_start = nullptr;
        sample_context->data_end = nullptr;
    }

    *context = sample_context;
    context_header = nullptr;
    retval = EBPF_SUCCESS;

Done:
    free(context_header);
    context_header = nullptr;
    return retval;
}

static void
_sample_test_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    UNREFERENCED_PARAMETER(data_out);
    if (!context) {
        return;
    }
    sample_program_context_header_t* context_header =
        CONTAINING_RECORD(context, sample_program_context_header_t, context);

    // Data is not supported.
    *data_size_out = 0;

    if (context_out && *context_size_out >= sizeof(sample_program_context_t)) {
        memcpy(context_out, context, sizeof(sample_program_context_t));
        *context_size_out = sizeof(sample_program_context_t);
    } else {
        *context_size_out = 0;
    }

    free(context_header);
}

#define TEST_NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION 0

// program info provider data for various program types.

// Mock implementation of XDP.
static const void* _mock_xdp_helper_functions[] = {(void*)&test_xdp_helper_t::adjust_head};

static ebpf_helper_function_addresses_t _mock_xdp_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_mock_xdp_helper_functions),
    (uint64_t*)_mock_xdp_helper_functions};

static const ebpf_program_type_descriptor_t _mock_xdp_program_type_descriptor = {
    EBPF_PROGRAM_TYPE_DESCRIPTOR_HEADER,
    "xdp",
    &_ebpf_xdp_test_context_descriptor,
    EBPF_PROGRAM_TYPE_XDP_GUID,
    BPF_PROG_TYPE_XDP,
    0};
static const ebpf_program_info_t _mock_xdp_program_info = {
    EBPF_PROGRAM_INFORMATION_HEADER,
    &_mock_xdp_program_type_descriptor,
    EBPF_COUNT_OF(_xdp_test_ebpf_extension_helper_function_prototype),
    _xdp_test_ebpf_extension_helper_function_prototype};

static ebpf_program_data_t _mock_xdp_program_data = {
    EBPF_PROGRAM_DATA_HEADER,
    &_mock_xdp_program_info,
    &_mock_xdp_helper_function_address_table,
    nullptr,
    _xdp_context_create,
    _xdp_context_destroy};

// XDP_TEST.
static ebpf_program_data_t _ebpf_xdp_test_program_data = {
    EBPF_PROGRAM_DATA_HEADER,
    &_ebpf_xdp_test_program_info,
    &_mock_xdp_helper_function_address_table,
    nullptr,
    _xdp_context_create,
    _xdp_context_destroy};

// Bind.
static ebpf_result_t
_ebpf_bind_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    ebpf_result_t retval;
    *context = nullptr;

    bind_md_t* bind_context = reinterpret_cast<bind_md_t*>(ebpf_allocate(sizeof(bind_md_t)));
    if (bind_context == nullptr) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    if (context_in) {
        if (context_size_in < sizeof(bind_md_t)) {
            retval = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        bind_md_t* provided_context = (bind_md_t*)context_in;
        *bind_context = *provided_context;
    }

    bind_context->app_id_start = 0;
    bind_context->app_id_end = 0;

    if (data_in) {
        bind_context->app_id_start = (uint8_t*)data_in;
        bind_context->app_id_end = (uint8_t*)data_in + data_size_in;
    }

    *context = bind_context;
    bind_context = nullptr;
    retval = EBPF_SUCCESS;
Done:
    ebpf_free(bind_context);
    bind_context = nullptr;
    return retval;
}

static void
_ebpf_bind_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    UNREFERENCED_PARAMETER(data_out);
    if (!context) {
        return;
    }

    bind_md_t* bind_context = reinterpret_cast<bind_md_t*>(context);
    if (context_out && *context_size_out >= sizeof(bind_md_t)) {
        bind_md_t* provided_context = (bind_md_t*)context_out;
        *provided_context = *bind_context;
        *context_size_out = sizeof(bind_md_t);
    }

    ebpf_free(bind_context);
    bind_context = nullptr;

    *data_size_out = 0;
    return;
}

static ebpf_program_data_t _ebpf_bind_program_data = {
    .header = EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_ebpf_bind_program_info,
    .context_create = _ebpf_bind_context_create,
    .context_destroy = _ebpf_bind_context_destroy,
    .capabilities = {.supports_context_header = true},
};

// SOCK_ADDR.
static int
_ebpf_sock_addr_get_current_pid_tgid(_In_ const bpf_sock_addr_t* ctx)
{
    UNREFERENCED_PARAMETER(ctx);
    return -ENOTSUP;
}

static int
_ebpf_sock_addr_set_redirect_context(_In_ const bpf_sock_addr_t* ctx, _In_ void* data, _In_ uint32_t data_size)
{
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(data_size);
    return -ENOTSUP;
}

static uint64_t
_ebpf_sock_addr_get_current_pid_tgid_implicit(
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    uint64_t dummy_param5,
    _In_ const bpf_sock_addr_t* ctx)
{
    UNREFERENCED_PARAMETER(dummy_param1);
    UNREFERENCED_PARAMETER(dummy_param2);
    UNREFERENCED_PARAMETER(dummy_param3);
    UNREFERENCED_PARAMETER(dummy_param4);
    UNREFERENCED_PARAMETER(dummy_param5);
    UNREFERENCED_PARAMETER(ctx);
    return 0;
}

static int
_ebpf_sock_addr_get_current_logon_id(_In_ const bpf_sock_addr_t* ctx)
{
    UNREFERENCED_PARAMETER(ctx);
    return -ENOTSUP;
}

static int
_ebpf_sock_addr_is_current_admin(_In_ const bpf_sock_addr_t* ctx)
{
    UNREFERENCED_PARAMETER(ctx);
    return -ENOTSUP;
}

static uint64_t
_ebpf_sock_addr_get_socket_cookie(_In_ const bpf_sock_addr_t* ctx)
{
    UNREFERENCED_PARAMETER(ctx);
    return 0;
}

static ebpf_result_t
_ebpf_sock_addr_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    UNREFERENCED_PARAMETER(data_in);
    UNREFERENCED_PARAMETER(data_size_in);

    ebpf_result_t retval;
    *context = nullptr;

    bpf_sock_addr_t* sock_addr_context = reinterpret_cast<bpf_sock_addr_t*>(ebpf_allocate(sizeof(bpf_sock_addr_t)));
    if (sock_addr_context == nullptr) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    if (context_in) {
        if (context_size_in < sizeof(bpf_sock_addr_t)) {
            retval = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        bpf_sock_addr_t* provided_context = (bpf_sock_addr_t*)context_in;
        *sock_addr_context = *provided_context;
    }

    *context = sock_addr_context;
    sock_addr_context = nullptr;
    retval = EBPF_SUCCESS;
Done:
    ebpf_free(sock_addr_context);
    sock_addr_context = nullptr;
    return retval;
}

static void
_ebpf_sock_addr_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    UNREFERENCED_PARAMETER(data_out);
    if (!context) {
        return;
    }

    bpf_sock_addr_t* sock_addr_context = reinterpret_cast<bpf_sock_addr_t*>(context);
    if (context_out && *context_size_out >= sizeof(bpf_sock_addr_t)) {
        bpf_sock_addr_t* provided_context = (bpf_sock_addr_t*)context_out;
        *provided_context = *sock_addr_context;
        *context_size_out = sizeof(bpf_sock_addr_t);
    }

    ebpf_free(sock_addr_context);
    sock_addr_context = nullptr;

    *data_size_out = 0;
    return;
}

static const void* _ebpf_sock_addr_specific_helper_functions[] = {
    (void*)_ebpf_sock_addr_get_current_pid_tgid, (void*)_ebpf_sock_addr_set_redirect_context};

static ebpf_helper_function_addresses_t _ebpf_sock_addr_specific_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_ebpf_sock_addr_specific_helper_functions),
    (uint64_t*)_ebpf_sock_addr_specific_helper_functions};

static const void* _ebpf_sock_addr_global_helper_functions[] = {
    (void*)_ebpf_sock_addr_get_current_pid_tgid_implicit,
    (void*)_ebpf_sock_addr_get_current_logon_id,
    (void*)_ebpf_sock_addr_is_current_admin,
    (void*)_ebpf_sock_addr_get_socket_cookie};

static ebpf_helper_function_addresses_t _ebpf_sock_addr_global_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_ebpf_sock_addr_global_helper_functions),
    (uint64_t*)_ebpf_sock_addr_global_helper_functions};

static ebpf_program_data_t _ebpf_sock_addr_program_data = {
    .header = EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_ebpf_sock_addr_program_info,
    .program_type_specific_helper_function_addresses = &_ebpf_sock_addr_specific_helper_function_address_table,
    .global_helper_function_addresses = &_ebpf_sock_addr_global_helper_function_address_table,
    .context_create = &_ebpf_sock_addr_context_create,
    .context_destroy = &_ebpf_sock_addr_context_destroy,
    .required_irql = DISPATCH_LEVEL,
};

// SOCK_OPS.
static uint64_t
_ebpf_sock_ops_get_current_pid_tgid(
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    uint64_t dummy_param5,
    _In_ const bpf_sock_addr_t* ctx)
{
    UNREFERENCED_PARAMETER(dummy_param1);
    UNREFERENCED_PARAMETER(dummy_param2);
    UNREFERENCED_PARAMETER(dummy_param3);
    UNREFERENCED_PARAMETER(dummy_param4);
    UNREFERENCED_PARAMETER(dummy_param5);
    UNREFERENCED_PARAMETER(ctx);
    return 0;
}

static const void* _ebpf_sock_ops_global_helper_functions[] = {(void*)_ebpf_sock_ops_get_current_pid_tgid};

static ebpf_helper_function_addresses_t _ebpf_sock_ops_global_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_ebpf_sock_ops_global_helper_functions),
    (uint64_t*)_ebpf_sock_ops_global_helper_functions};

static ebpf_result_t
_ebpf_sock_ops_context_create(
    _In_reads_bytes_opt_(data_size_in) const uint8_t* data_in,
    size_t data_size_in,
    _In_reads_bytes_opt_(context_size_in) const uint8_t* context_in,
    size_t context_size_in,
    _Outptr_ void** context)
{
    UNREFERENCED_PARAMETER(data_in);
    UNREFERENCED_PARAMETER(data_size_in);
    ebpf_result_t retval;
    *context = nullptr;

    bpf_sock_ops_t* sock_ops_context = reinterpret_cast<bpf_sock_ops_t*>(ebpf_allocate(sizeof(bpf_sock_ops_t)));
    if (sock_ops_context == nullptr) {
        retval = EBPF_NO_MEMORY;
        goto Done;
    }

    if (context_in) {
        if (context_size_in < sizeof(bpf_sock_ops_t)) {
            retval = EBPF_INVALID_ARGUMENT;
            goto Done;
        }
        bpf_sock_ops_t* provided_context = (bpf_sock_ops_t*)context_in;
        *sock_ops_context = *provided_context;
    }

    *context = sock_ops_context;
    sock_ops_context = nullptr;
    retval = EBPF_SUCCESS;
Done:
    ebpf_free(sock_ops_context);
    sock_ops_context = nullptr;
    return retval;
}

static void
_ebpf_sock_ops_context_destroy(
    _In_opt_ void* context,
    _Out_writes_bytes_to_(*data_size_out, *data_size_out) uint8_t* data_out,
    _Inout_ size_t* data_size_out,
    _Out_writes_bytes_to_(*context_size_out, *context_size_out) uint8_t* context_out,
    _Inout_ size_t* context_size_out)
{
    UNREFERENCED_PARAMETER(data_out);
    if (!context) {
        return;
    }

    bpf_sock_ops_t* sock_ops_context = reinterpret_cast<bpf_sock_ops_t*>(context);
    if (context_out && *context_size_out >= sizeof(bpf_sock_ops_t)) {
        bpf_sock_ops_t* provided_context = (bpf_sock_ops_t*)context_out;
        *provided_context = *sock_ops_context;
        *context_size_out = sizeof(bpf_sock_ops_t);
    }

    ebpf_free(sock_ops_context);

    *data_size_out = 0;
    return;
}

static ebpf_program_data_t _ebpf_sock_ops_program_data = {
    .header = EBPF_PROGRAM_DATA_HEADER,
    .program_info = &_ebpf_sock_ops_program_info,
    .global_helper_function_addresses = &_ebpf_sock_ops_global_helper_function_address_table,
    .context_create = &_ebpf_sock_ops_context_create,
    .context_destroy = &_ebpf_sock_ops_context_destroy,
    .required_irql = DISPATCH_LEVEL,
};

// Sample extension.
static const void* _sample_ebpf_ext_helper_functions[] = {
    test_sample_helper_t::_sample_ebpf_extension_helper_function1,
    test_sample_helper_t::_sample_ebpf_extension_find,
    test_sample_helper_t::_sample_ebpf_extension_replace,
    test_sample_helper_t::_sample_ebpf_extension_helper_implicit_1,
    test_sample_helper_t::_sample_ebpf_extension_helper_implicit_2};

static ebpf_helper_function_addresses_t _sample_ebpf_ext_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_sample_ebpf_ext_helper_functions),
    (uint64_t*)_sample_ebpf_ext_helper_functions};

static const void* _test_global_helper_functions[] = {test_global_helper_t::_sample_get_pid_tgid};

static ebpf_helper_function_addresses_t _test_global_helper_function_address_table = {
    EBPF_HELPER_FUNCTION_ADDRESSES_HEADER,
    EBPF_COUNT_OF(_test_global_helper_functions),
    (uint64_t*)_test_global_helper_functions};

static ebpf_program_data_t _test_ebpf_sample_extension_program_data = {
    EBPF_PROGRAM_DATA_HEADER,
    &_sample_ebpf_extension_program_info,
    &_sample_ebpf_ext_helper_function_address_table,
    &_test_global_helper_function_address_table,
    _sample_test_context_create,
    _sample_test_context_destroy,
    0,
    {.supports_context_header = true}};

#define TEST_EBPF_SAMPLE_EXTENSION_NPI_PROVIDER_VERSION 0

typedef class _program_info_provider
{
  public:
    _program_info_provider() : program_data(nullptr), nmr_provider_handle(INVALID_HANDLE_VALUE)
    {
        memset(&_program_type, 0, sizeof(_program_type));
    }

    ebpf_result_t
    initialize(ebpf_program_type_t program_type, ebpf_program_data_t* custom_program_data = nullptr)
    {
        this->_program_type = program_type;

        if (custom_program_data != nullptr) {
            program_data = custom_program_data;
        } else if (program_type == EBPF_PROGRAM_TYPE_XDP) {
            program_data = &_mock_xdp_program_data;
        } else if (program_type == EBPF_PROGRAM_TYPE_XDP_TEST) {
            program_data = &_ebpf_xdp_test_program_data;
        } else if (program_type == EBPF_PROGRAM_TYPE_BIND) {
            program_data = &_ebpf_bind_program_data;
        } else if (program_type == EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR) {
            program_data = &_ebpf_sock_addr_program_data;
        } else if (program_type == EBPF_PROGRAM_TYPE_SOCK_OPS) {
            program_data = &_ebpf_sock_ops_program_data;
        } else if (program_type == EBPF_PROGRAM_TYPE_SAMPLE) {
            program_data = &_test_ebpf_sample_extension_program_data;
        } else {
            // Unsupported program type.
            return EBPF_INVALID_ARGUMENT;
        }

        module_id.Guid = program_data->program_info->program_type_descriptor->program_type;
        provider_characteristics.ProviderRegistrationInstance.NpiSpecificCharacteristics = program_data;

        NTSTATUS status = NmrRegisterProvider(&provider_characteristics, this, &nmr_provider_handle);
        return (NT_SUCCESS(status)) ? EBPF_SUCCESS : EBPF_FAILED;
    }
    ~_program_info_provider()
    {
        if (nmr_provider_handle != INVALID_HANDLE_VALUE) {
            NTSTATUS status = NmrDeregisterProvider(nmr_provider_handle);
            if (status == STATUS_PENDING) {
                NmrWaitForProviderDeregisterComplete(nmr_provider_handle);
            } else {
                ebpf_assert(status == STATUS_SUCCESS);
            }
        }
    }

  private:
    static NTSTATUS
    provider_attach_client_callback(
        HANDLE nmr_binding_handle,
        _Inout_ void* provider_context,
        _In_ const NPI_REGISTRATION_INSTANCE* client_registration_instance,
        _In_ const void* client_binding_context,
        _In_ const void* client_dispatch,
        _Out_ void** provider_binding_context,
        _Out_ const void** provider_dispatch)
    {
        auto hook = reinterpret_cast<_program_info_provider*>(provider_context);
        UNREFERENCED_PARAMETER(nmr_binding_handle);
        UNREFERENCED_PARAMETER(client_dispatch);
        UNREFERENCED_PARAMETER(client_binding_context);
        UNREFERENCED_PARAMETER(client_registration_instance);
        UNREFERENCED_PARAMETER(hook);
        *provider_binding_context = provider_context;
        *provider_dispatch = NULL;
        return STATUS_SUCCESS;
    };

    static NTSTATUS
    provider_detach_client_callback(_Inout_ void* provider_binding_context)
    {
        auto hook = reinterpret_cast<_program_info_provider*>(provider_binding_context);
        UNREFERENCED_PARAMETER(hook);

        // There should be no in-progress calls to any client functions,
        // we we can return success rather than pending.
        return EBPF_SUCCESS;
    };

    ebpf_program_type_t _program_type;
    const ebpf_program_data_t* program_data;

    NPI_MODULEID module_id = {
        sizeof(NPI_MODULEID),
        MIT_GUID,
    };

    NPI_PROVIDER_CHARACTERISTICS provider_characteristics{
        0,
        sizeof(NPI_PROVIDER_CHARACTERISTICS),
        (NPI_PROVIDER_ATTACH_CLIENT_FN*)provider_attach_client_callback,
        (NPI_PROVIDER_DETACH_CLIENT_FN*)provider_detach_client_callback,
        NULL,
        {
            0,
            sizeof(NPI_REGISTRATION_INSTANCE),
            &EBPF_PROGRAM_INFO_EXTENSION_IID,
            &module_id,
            0,
            NULL,
        },
    };
    HANDLE nmr_provider_handle;
} program_info_provider_t;

#define ETHERNET_TYPE_IPV4 0x0800
std::vector<uint8_t>
prepare_udp_packet(uint16_t udp_length, uint16_t ethertype);
