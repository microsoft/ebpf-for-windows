/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */
#pragma once
#include "ebpf_api.h"
#include "ebpf_nethooks.h"
#include "ebpf_platform.h"
#include "ebpf_program_types.h"
#include "net_ebpf_ext_program_info.h"
#include "sample_ext_program_info.h"

bpf_attach_type_t
get_bpf_attach_type(_In_ const ebpf_attach_type_t* ebpf_attach_type) noexcept;

typedef struct _ebpf_free_memory
{
    void
    operator()(uint8_t* memory)
    {
        ebpf_free(memory);
    }
} ebpf_free_memory_t;

typedef std::unique_ptr<uint8_t, ebpf_free_memory_t> ebpf_memory_t;

extern bool _ebpf_platform_is_preemptible;

#ifdef __cplusplus
extern "C"
{
#endif
    extern GUID ebpf_program_information_extension_interface_id;
    extern GUID ebpf_hook_extension_interface_id;
#ifdef __cplusplus
}
#endif

typedef class _emulate_dpc
{
  public:
    _emulate_dpc(uint32_t cpu_id)
    {
        uintptr_t new_process_affinity_mask = 1ull << cpu_id;
        if (!GetProcessAffinityMask(GetCurrentProcess(), &old_process_affinity_mask, &old_system_affinity_mask)) {
            throw new std::runtime_error("GetProcessAffinityMask failed");
        }
        if (!SetProcessAffinityMask(GetCurrentProcess(), new_process_affinity_mask)) {
            throw new std::runtime_error("SetProcessAffinityMask failed");
        }
        _ebpf_platform_is_preemptible = false;
    }
    ~_emulate_dpc()
    {
        _ebpf_platform_is_preemptible = true;

        if (!SetProcessAffinityMask(GetCurrentProcess(), old_process_affinity_mask)) {
            std::abort();
        }
    }

  private:
    uintptr_t old_process_affinity_mask;
    uintptr_t old_system_affinity_mask;

} emulate_dpc_t;

typedef class _hook_helper
{
  public:
    _hook_helper(ebpf_attach_type_t attach_type) : _attach_type(attach_type) {}

    ebpf_result_t
    attach_link(
        fd_t program_fd,
        _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
        _In_ size_t attach_parameters_size,
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
        : _hook_helper{attach_type}, provider(nullptr), client_binding_context(nullptr), client_data(nullptr),
          client_dispatch_table(nullptr), link_handle(ebpf_handle_invalid), link_object(nullptr)
    {
        ebpf_guid_create(&client_id);
        attach_provider_data.supported_program_type = program_type;
        attach_provider_data.bpf_attach_type = get_bpf_attach_type(&attach_type);
        this->attach_type = attach_type;

        REQUIRE(
            ebpf_provider_load(
                &provider,
                &ebpf_hook_extension_interface_id,
                &attach_type,
                nullptr,
                &provider_data,
                nullptr,
                this,
                client_attach_callback,
                client_detach_callback) == EBPF_SUCCESS);
    }
    ~_single_instance_hook()
    {
        detach();
        ebpf_provider_unload(provider);
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
        if (link_handle != ebpf_handle_invalid) {
            ebpf_api_unlink_program(link_handle);
            ebpf_api_close_handle(link_handle);
            link_handle = ebpf_handle_invalid;
        }
        if (link_object != nullptr) {
            ebpf_link_detach(link_object);
            ebpf_link_close(link_object);
            link_object = nullptr;
        }
    }

    ebpf_result_t
    detach(
        fd_t program_fd,
        _In_reads_bytes_(attach_parameter_size) void* attach_parameter,
        _In_ size_t attach_parameter_size)
    {
        return ebpf_program_detach(program_fd, &attach_type, attach_parameter, attach_parameter_size);
    }

    void
    detach_link(bpf_link* link)
    {
        ebpf_link_detach(link);
    }

    void
    close_link(bpf_link* link)
    {
        ebpf_link_close(link);
    }

    void
    close_handle()
    {
        ebpf_api_close_handle(link_handle);
    }

    ebpf_result_t
    fire(void* context, int* result)
    {
        ebpf_result_t (*invoke_program)(void* link, void* context, int* result) =
            reinterpret_cast<decltype(invoke_program)>(client_dispatch_table->function[0]);

        return invoke_program(client_binding_context, context, result);
    }

  private:
    static ebpf_result_t
    client_attach_callback(
        ebpf_handle_t nmr_binding_handle,
        void* context,
        const GUID* client_id,
        void* client_binding_context,
        const ebpf_extension_data_t* client_data,
        const ebpf_extension_dispatch_table_t* client_dispatch_table)
    {
        auto hook = reinterpret_cast<_single_instance_hook*>(context);
        if (hook->client_binding_context != nullptr) {
            return EBPF_OPERATION_NOT_SUPPORTED;
        }
        UNREFERENCED_PARAMETER(nmr_binding_handle);
        hook->client_id = *client_id;
        hook->client_binding_context = client_binding_context;
        hook->client_data = client_data;
        hook->client_dispatch_table = client_dispatch_table;
        return EBPF_SUCCESS;
    };

    static ebpf_result_t
    client_detach_callback(void* context, const GUID* client_id)
    {
        auto hook = reinterpret_cast<_single_instance_hook*>(context);
        hook->client_binding_context = nullptr;
        hook->client_data = nullptr;
        hook->client_dispatch_table = nullptr;
        UNREFERENCED_PARAMETER(client_id);
        return EBPF_SUCCESS;
    };
    ebpf_attach_type_t attach_type;
    ebpf_attach_provider_data_t attach_provider_data;

    ebpf_extension_data_t provider_data = {
        EBPF_ATTACH_PROVIDER_DATA_VERSION, sizeof(attach_provider_data), &attach_provider_data};
    ebpf_extension_provider_t* provider;
    GUID client_id;
    void* client_binding_context;
    const ebpf_extension_data_t* client_data;
    const ebpf_extension_dispatch_table_t* client_dispatch_table;
    ebpf_handle_t link_handle;
    bpf_link* link_object;
} single_instance_hook_t;

typedef class xdp_md_helper : public xdp_md_t
{
  public:
    xdp_md_helper(std::vector<uint8_t>& packet)
        : xdp_md_t{packet.data(), packet.data() + packet.size()}, _packet(&packet), _begin(0), _end(packet.size()){};
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

  private:
    std::vector<uint8_t>* _packet;
    size_t _begin;
    size_t _end;
} xdp_md_helper_t;

typedef class _test_xdp_helper
{
  public:
    static int
    adjust_head(_In_ xdp_md_t* ctx, int delta)
    {
        return ((xdp_md_helper_t*)ctx)->adjust_head(delta);
    }
} test_xdp_helper_t;

#define TEST_NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION 0

// program info provider data for various program types.

// XDP.
static const void* _test_ebpf_xdp_helper_functions[] = {(void*)&test_xdp_helper_t::adjust_head};

static ebpf_helper_function_addresses_t _test_ebpf_xdp_helper_function_address_table = {
    EBPF_COUNT_OF(_test_ebpf_xdp_helper_functions), (uint64_t*)_test_ebpf_xdp_helper_functions};

static ebpf_program_data_t _ebpf_xdp_program_data = {
    &_ebpf_xdp_program_info, &_test_ebpf_xdp_helper_function_address_table};

static ebpf_extension_data_t _ebpf_xdp_program_info_provider_data = {
    TEST_NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_xdp_program_data), &_ebpf_xdp_program_data};

// Bind.
static ebpf_program_data_t _ebpf_bind_program_data = {&_ebpf_bind_program_info, NULL};

static ebpf_extension_data_t _ebpf_bind_program_info_provider_data = {
    TEST_NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_bind_program_data), &_ebpf_bind_program_data};

// CGROUP_SOCK_ADDR.
static ebpf_program_data_t _ebpf_sock_addr_program_data = {&_ebpf_sock_addr_program_info, NULL};

static ebpf_extension_data_t _ebpf_sock_addr_program_info_provider_data = {
    TEST_NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_sock_addr_program_data), &_ebpf_sock_addr_program_data};

// SOCK_OPS.
static ebpf_program_data_t _ebpf_sock_ops_program_data = {&_ebpf_sock_ops_program_info, NULL};

static ebpf_extension_data_t _ebpf_sock_ops_program_info_provider_data = {
    TEST_NET_EBPF_EXTENSION_NPI_PROVIDER_VERSION, sizeof(_ebpf_sock_ops_program_data), &_ebpf_sock_ops_program_data};

// Sample extension.
static ebpf_program_data_t _test_ebpf_sample_extension_program_data = {&_sample_ebpf_extension_program_info, NULL};

#define TEST_EBPF_SAMPLE_EXTENSION_NPI_PROVIDER_VERSION 0

static ebpf_extension_data_t _test_ebpf_sample_extension_program_info_provider_data = {
    TEST_EBPF_SAMPLE_EXTENSION_NPI_PROVIDER_VERSION,
    sizeof(_test_ebpf_sample_extension_program_data),
    &_test_ebpf_sample_extension_program_data};

typedef class _program_info_provider
{
  public:
    _program_info_provider(ebpf_program_type_t program_type) : program_type(program_type)
    {
        if (program_type == EBPF_PROGRAM_TYPE_XDP) {
            provider_data = &_ebpf_xdp_program_info_provider_data;
        } else if (program_type == EBPF_PROGRAM_TYPE_BIND) {
            provider_data = &_ebpf_bind_program_info_provider_data;
        } else if (program_type == EBPF_PROGRAM_TYPE_CGROUP_SOCK_ADDR) {
            provider_data = &_ebpf_sock_addr_program_info_provider_data;
        } else if (program_type == EBPF_PROGRAM_TYPE_SOCK_OPS) {
            provider_data = &_ebpf_sock_ops_program_info_provider_data;
        } else if (program_type == EBPF_PROGRAM_TYPE_SAMPLE) {
            provider_data = &_test_ebpf_sample_extension_program_info_provider_data;
        }
        ebpf_program_data_t* program_data = (ebpf_program_data_t*)provider_data->data;
        program_data->program_info->program_type_descriptor.program_type = program_type;

        REQUIRE(
            ebpf_provider_load(
                &provider,
                &ebpf_program_information_extension_interface_id,
                &program_type,
                nullptr,
                provider_data,
                nullptr,
                nullptr,
                nullptr,
                nullptr) == EBPF_SUCCESS);
    }
    ~_program_info_provider() { ebpf_provider_unload(provider); }

  private:
    ebpf_program_type_t program_type;

    ebpf_extension_data_t* provider_data;
    ebpf_extension_provider_t* provider;
} program_info_provider_t;

#define ETHERNET_TYPE_IPV4 0x0800
std::vector<uint8_t>
prepare_udp_packet(uint16_t udp_length, uint16_t ethertype);
