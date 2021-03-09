/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "api.h"
#include "ebpf_core.h"
#include "ebpf_protocol.h"
#include "mock.h"
#include "tlv.h"
namespace ebpf {
#pragma warning(push)
#pragma warning(                                                               \
    disable : 4201) // nonstandard extension used : nameless struct/union
#include "../sample/ebpf.h"
#pragma warning(pop)
}; // namespace ebpf

#include "unwind_helper.h"
#include <WinSock2.h>

static const struct {
  ebpf_error_code_t (*protocol_handler)(_In_ const void *input_buffer,
                                        void *output_buffer);
  size_t minimum_request_size;
  size_t minimum_reply_size;
} EbpfProtocolHandlers[] = {
    {NULL,
     sizeof(struct _ebpf_operation_eidence_request)}, // EBPF_OPERATION_EVIDENCE
    {reinterpret_cast<ebpf_error_code_t (*)(_In_ const void *input_buffer,
                                            void *output_buffer)>(
         ebpf_core_protocol_resolve_helper),
     sizeof(struct _ebpf_operation_resolve_helper_request),
     sizeof(struct _ebpf_operation_resolve_helper_reply)},
    {reinterpret_cast<ebpf_error_code_t (*)(_In_ const void *input_buffer,
                                            void *output_buffer)>(
         ebpf_core_protocol_resolve_map),
     sizeof(struct _ebpf_operation_resolve_map_request),
     sizeof(struct _ebpf_operation_resolve_map_reply)},
    {reinterpret_cast<ebpf_error_code_t (*)(_In_ const void *input_buffer,
                                            void *output_buffer)>(
         ebpf_core_protocol_load_code),
     sizeof(struct _ebpf_operation_load_code_request),
     sizeof(struct _ebpf_operation_load_code_reply)},
    {reinterpret_cast<ebpf_error_code_t (*)(_In_ const void *input_buffer,
                                            void *output_buffer)>(
         ebpf_core_protocol_unload_code),
     sizeof(struct _ebpf_operation_unload_code_request), 0},
    {reinterpret_cast<ebpf_error_code_t (*)(_In_ const void *input_buffer,
                                            void *output_buffer)>(
         ebpf_core_protocol_attach_code),
     sizeof(struct _ebpf_operation_attach_detach_request), 0},
    {reinterpret_cast<ebpf_error_code_t (*)(_In_ const void *input_buffer,
                                            void *output_buffer)>(
         ebpf_core_protocol_detach_code),
     sizeof(struct _ebpf_operation_attach_detach_request), 0},
    {reinterpret_cast<ebpf_error_code_t (*)(_In_ const void *input_buffer,
                                            void *output_buffer)>(
         ebpf_core_protocol_create_map),
     sizeof(struct _ebpf_operation_create_map_request),
     sizeof(struct _ebpf_operation_create_map_reply)},
    {reinterpret_cast<ebpf_error_code_t (*)(_In_ const void *input_buffer,
                                            void *output_buffer)>(
         ebpf_core_protocol_map_lookup_element),
     sizeof(struct _ebpf_operation_map_lookup_element_request),
     sizeof(struct _ebpf_operation_map_lookup_element_reply)},
    {reinterpret_cast<ebpf_error_code_t (*)(_In_ const void *input_buffer,
                                            void *output_buffer)>(
         ebpf_core_protocol_map_update_element),
     sizeof(struct _ebpf_operation_map_update_element_request), 0},
    {reinterpret_cast<ebpf_error_code_t (*)(_In_ const void *input_buffer,
                                            void *output_buffer)>(
         ebpf_core_protocol_map_delete_element),
     sizeof(struct _ebpf_operation_map_delete_element_request), 0},
    {reinterpret_cast<ebpf_error_code_t (*)(_In_ const void *input_buffer,
                                            void *output_buffer)>(
         ebpf_core_protocol_map_get_next_key),
     offsetof(ebpf_operation_map_next_key_request_t, previous_key),
     sizeof(ebpf_operation_map_next_key_reply_t)},
    {reinterpret_cast<ebpf_error_code_t (*)(_In_ const void *input_buffer,
                                            void *output_buffer)>(
         ebpf_core_protocol_enumerate_maps),
     sizeof(struct _ebpf_operation_enumerate_maps_request),
     sizeof(struct _ebpf_operation_enumerate_maps_reply)},
    {reinterpret_cast<ebpf_error_code_t (*)(_In_ const void *input_buffer,
                                            void *output_buffer)>(
         ebpf_core_protocol_query_map_definition),
     sizeof(struct _ebpf_operation_query_map_definition_request),
     sizeof(struct _ebpf_operation_query_map_definition_reply)},
};

ebpf_handle_t GlueCreateFileW(PCWSTR lpFileName, DWORD dwDesiredAccess,
                              DWORD dwShareMode,
                              PSECURITY_ATTRIBUTES lpSecurityAttributes,
                              DWORD dwCreationDisposition,
                              DWORD dwFlagsAndAttributes,
                              ebpf_handle_t hTemplateFile) {
  UNREFERENCED_PARAMETER(lpFileName);
  UNREFERENCED_PARAMETER(dwDesiredAccess);
  UNREFERENCED_PARAMETER(dwShareMode);
  UNREFERENCED_PARAMETER(lpSecurityAttributes);
  UNREFERENCED_PARAMETER(dwCreationDisposition);
  UNREFERENCED_PARAMETER(dwFlagsAndAttributes);
  UNREFERENCED_PARAMETER(hTemplateFile);

  return (ebpf_handle_t)0x12345678;
}

BOOL GlueCloseHandle(ebpf_handle_t hObject) {
  UNREFERENCED_PARAMETER(hObject);
  return TRUE;
}

BOOL GlueDeviceIoControl(ebpf_handle_t hDevice, DWORD dwIoControlCode,
                         PVOID lpInBuffer, DWORD nInBufferSize,
                         LPVOID lpOutBuffer, DWORD nOutBufferSize,
                         PDWORD lpBytesReturned, OVERLAPPED *lpOverlapped) {
  UNREFERENCED_PARAMETER(hDevice);
  UNREFERENCED_PARAMETER(nInBufferSize);
  UNREFERENCED_PARAMETER(dwIoControlCode);
  UNREFERENCED_PARAMETER(lpOverlapped);

  ebpf_error_code_t retval;
  const ebpf_operation_header_t *user_request =
      reinterpret_cast<decltype(user_request)>(lpInBuffer);
  ebpf_operation_header_t *user_reply = nullptr;
  *lpBytesReturned = 0;
  auto request_id = user_request->id;
  if (request_id >= _countof(EbpfProtocolHandlers)) {
    goto Fail;
  }

  if (user_request->length <
      EbpfProtocolHandlers[request_id].minimum_request_size) {
    goto Fail;
  }

  if (EbpfProtocolHandlers[request_id].minimum_reply_size > 0) {
    user_reply = reinterpret_cast<decltype(user_reply)>(lpOutBuffer);
    if (!user_reply) {
      goto Fail;
    }
    if (nOutBufferSize < EbpfProtocolHandlers[request_id].minimum_reply_size) {
      goto Fail;
    }
    user_reply->length = static_cast<uint16_t>(nOutBufferSize);
    user_reply->id = user_request->id;
    *lpBytesReturned = user_reply->length;
  }
  retval = EbpfProtocolHandlers[request_id].protocol_handler(user_request,
                                                             user_reply);
  if (retval != EBPF_ERROR_SUCCESS) {
    switch (retval) {
    case EBPF_ERROR_OUT_OF_RESOURCES:
      SetLastError(ERROR_OUTOFMEMORY);
      break;
    case EBPF_ERROR_NOT_FOUND:
      SetLastError(ERROR_NOT_FOUND);
      break;
    case EBPF_ERROR_INVALID_PARAMETER:
      SetLastError(ERROR_INVALID_PARAMETER);
      break;
    case EBPF_ERROR_NO_MORE_KEYS:
      SetLastError(ERROR_NO_MORE_ITEMS);
      break;
    default:
      SetLastError(ERROR_INVALID_PARAMETER);
      break;
    }
    goto Fail;
  }

  return TRUE;

Fail:

  return FALSE;
}

std::vector<uint8_t> prepare_udp_packet(uint16_t udp_length) {
  std::vector<uint8_t> packet(sizeof(ebpf::IPV4_HEADER) +
                              sizeof(ebpf::UDP_HEADER));
  auto ipv4 = reinterpret_cast<ebpf::IPV4_HEADER *>(packet.data());
  auto udp = reinterpret_cast<ebpf::UDP_HEADER *>(ipv4 + 1);

  ipv4->Protocol = 17;

  udp->length = udp_length;

  return packet;
}

#define SAMPLE_PATH "..\\sample\\"

TEST_CASE("droppacket-jit", "[droppacket_jit]") {
  device_io_control_handler = GlueDeviceIoControl;
  create_file_handler = GlueCreateFileW;
  close_handle_handler = GlueCloseHandle;

  ebpf_handle_t program_handle;
  ebpf_handle_t map_handle;
  uint32_t count_of_map_handle = 1;
  uint32_t result = 0;
  const char *error_message = NULL;
  bool ec_initialized = false;
  bool api_initialized = false;
  _unwind_helper on_exit([&] {
    ebpf_api_free_error_message(error_message);
    if (api_initialized)
      ebpf_api_terminate();
    if (ec_initialized)
      ebpf_core_terminate();
  });

  REQUIRE(ebpf_core_initialize() == EBPF_ERROR_SUCCESS);
  ec_initialized = true;

  REQUIRE(ebpf_api_initiate() == ERROR_SUCCESS);
  api_initialized = true;

  REQUIRE(ebpf_api_load_program(SAMPLE_PATH "droppacket.o", "xdp",
                                EBPF_EXECUTION_JIT, &program_handle,
                                &count_of_map_handle, &map_handle,
                                &error_message) == ERROR_SUCCESS);

  REQUIRE(ebpf_api_attach_program(program_handle, EBPF_PROGRAM_TYPE_XDP) ==
          ERROR_SUCCESS);

  auto packet = prepare_udp_packet(0);

  uint32_t key = 0;
  uint64_t value = 1000;
  REQUIRE(ebpf_api_map_update_element(map_handle, sizeof(key), (uint8_t *)&key,
                                      sizeof(value),
                                      (uint8_t *)&value) == ERROR_SUCCESS);

  // Test that we drop the packet and increment the map
  ebpf::xdp_md_t ctx{packet.data(), packet.data() + packet.size()};
  REQUIRE(ebpf_core_invoke_hook(EBPF_PROGRAM_TYPE_XDP, &ctx, &result) ==
          EBPF_ERROR_SUCCESS);
  REQUIRE(result == 2);

  REQUIRE(ebpf_api_map_lookup_element(map_handle, sizeof(key), (uint8_t *)&key,
                                      sizeof(value),
                                      (uint8_t *)&value) == ERROR_SUCCESS);
  REQUIRE(value == 1001);

  REQUIRE(ebpf_api_map_delete_element(map_handle, sizeof(key),
                                      (uint8_t *)&key) == ERROR_SUCCESS);

  REQUIRE(ebpf_api_map_lookup_element(map_handle, sizeof(key), (uint8_t *)&key,
                                      sizeof(value),
                                      (uint8_t *)&value) == ERROR_SUCCESS);
  REQUIRE(value == 0);

  packet = prepare_udp_packet(10);
  ebpf::xdp_md_t ctx2{packet.data(), packet.data() + packet.size()};

  REQUIRE(ebpf_core_invoke_hook(EBPF_PROGRAM_TYPE_XDP, &ctx2, &result) ==
          EBPF_ERROR_SUCCESS);
  REQUIRE(result == 1);

  REQUIRE(ebpf_api_map_lookup_element(map_handle, sizeof(key), (uint8_t *)&key,
                                      sizeof(value),
                                      (uint8_t *)&value) == ERROR_SUCCESS);
  REQUIRE(value == 0);
}

TEST_CASE("droppacket-interpret", "[droppacket_interpret]") {
  device_io_control_handler = GlueDeviceIoControl;
  create_file_handler = GlueCreateFileW;
  close_handle_handler = GlueCloseHandle;

  ebpf_handle_t program_handle;
  const char *error_message = NULL;
  bool ec_initialized = false;
  bool api_initialized = false;
  ebpf_handle_t map_handle;
  uint32_t count_of_map_handle = 1;
  _unwind_helper on_exit([&] {
    ebpf_api_free_error_message(error_message);
    if (api_initialized)
      ebpf_api_terminate();
    if (ec_initialized)
      ebpf_core_terminate();
  });
  uint32_t result = 0;

  REQUIRE(ebpf_core_initialize() == EBPF_ERROR_SUCCESS);
  ec_initialized = true;

  REQUIRE(ebpf_api_initiate() == ERROR_SUCCESS);
  api_initialized = true;

  REQUIRE(ebpf_api_load_program(SAMPLE_PATH "droppacket.o", "xdp",
                                EBPF_EXECUTION_INTERPRET, &program_handle,
                                &count_of_map_handle, &map_handle,
                                &error_message) == ERROR_SUCCESS);

  REQUIRE(ebpf_api_attach_program(program_handle, EBPF_PROGRAM_TYPE_XDP) ==
          ERROR_SUCCESS);

  auto packet = prepare_udp_packet(0);

  uint32_t key = 0;
  uint64_t value = 1000;
  REQUIRE(ebpf_api_map_update_element((ebpf_handle_t)1, sizeof(key),
                                      (uint8_t *)&key, sizeof(value),
                                      (uint8_t *)&value) == ERROR_SUCCESS);

  // Test that we drop the packet and increment the map
  ebpf::xdp_md_t ctx{packet.data(), packet.data() + packet.size()};
  REQUIRE(ebpf_core_invoke_hook(EBPF_PROGRAM_TYPE_XDP, &ctx, &result) ==
          EBPF_ERROR_SUCCESS);
  REQUIRE(result == 2);

  REQUIRE(ebpf_api_map_lookup_element((ebpf_handle_t)1, sizeof(key),
                                      (uint8_t *)&key, sizeof(value),
                                      (uint8_t *)&value) == ERROR_SUCCESS);
  REQUIRE(value == 1001);

  REQUIRE(ebpf_api_map_delete_element((ebpf_handle_t)1, sizeof(key),
                                      (uint8_t *)&key) == ERROR_SUCCESS);

  REQUIRE(ebpf_api_map_lookup_element((ebpf_handle_t)1, sizeof(key),
                                      (uint8_t *)&key, sizeof(value),
                                      (uint8_t *)&value) == ERROR_SUCCESS);
  REQUIRE(value == 0);

  packet = prepare_udp_packet(10);
  ebpf::xdp_md_t ctx2{packet.data(), packet.data() + packet.size()};

  REQUIRE(ebpf_core_invoke_hook(EBPF_PROGRAM_TYPE_XDP, &ctx2, &result) ==
          EBPF_ERROR_SUCCESS);
  REQUIRE(result == 1);

  REQUIRE(ebpf_api_map_lookup_element((ebpf_handle_t)1, sizeof(key),
                                      (uint8_t *)&key, sizeof(value),
                                      (uint8_t *)&value) == ERROR_SUCCESS);
  REQUIRE(value == 0);
}

TEST_CASE("enum section", "[enum sections]") {
  const char *error_message = nullptr;
  const tlv_type_length_value_t *section_data = nullptr;
  bool ec_initialized = false;
  bool api_initialized = false;
  _unwind_helper on_exit([&] {
    ebpf_api_free_error_message(error_message);
    ebpf_api_elf_free(section_data);
    if (api_initialized)
      ebpf_api_terminate();
    if (ec_initialized)
      ebpf_core_terminate();
  });

  REQUIRE(ebpf_core_initialize() == EBPF_ERROR_SUCCESS);
  ec_initialized = true;
  REQUIRE(ebpf_api_initiate() == ERROR_SUCCESS);
  api_initialized = true;

  REQUIRE(ebpf_api_elf_enumerate_sections(SAMPLE_PATH "droppacket.o", nullptr,
                                          true, &section_data,
                                          &error_message) == 0);
  for (auto current_section = tlv_child(section_data);
       current_section != tlv_next(section_data);
       current_section = tlv_next(current_section)) {
    auto section_name = tlv_child(current_section);
    auto type = tlv_next(section_name);
    auto map_count = tlv_next(type);
    auto program_bytes = tlv_next(map_count);
    auto stats_secton = tlv_next(program_bytes);

    REQUIRE(static_cast<tlv_type_t>(section_name->type) == tlv_type_t::STRING);
    REQUIRE(static_cast<tlv_type_t>(type->type) == tlv_type_t::UINT);
    REQUIRE(static_cast<tlv_type_t>(map_count->type) == tlv_type_t::UINT);
    REQUIRE(static_cast<tlv_type_t>(program_bytes->type) == tlv_type_t::BLOB);
    REQUIRE(static_cast<tlv_type_t>(stats_secton->type) ==
            tlv_type_t::SEQUENCE);

    for (auto current_stat = tlv_child(stats_secton);
         current_stat != tlv_next(stats_secton);
         current_stat = tlv_next(current_stat)) {
      auto name = tlv_child(current_stat);
      auto value = tlv_next(name);
      REQUIRE(static_cast<tlv_type_t>(name->type) == tlv_type_t::STRING);
      REQUIRE(static_cast<tlv_type_t>(value->type) == tlv_type_t::UINT);
    }
  }
}

TEST_CASE("verify section", "[verify section]") {

  const char *error_message = nullptr;
  const char *report = nullptr;
  bool ec_initialized = false;
  bool api_initialized = false;
  _unwind_helper on_exit([&] {
    ebpf_api_free_error_message(error_message);
    ebpf_api_free_error_message(report);
    if (api_initialized)
      ebpf_api_terminate();
    if (ec_initialized)
      ebpf_core_terminate();
  });

  REQUIRE(ebpf_core_initialize() == EBPF_ERROR_SUCCESS);
  api_initialized = true;
  REQUIRE(ebpf_api_initiate() == ERROR_SUCCESS);
  ec_initialized = true;

  REQUIRE(ebpf_api_elf_verify_section(SAMPLE_PATH "droppacket.o", "xdp",
                                      &report, &error_message) == 0);
  REQUIRE(report != nullptr);
  REQUIRE(error_message == nullptr);
}

typedef struct _process_entry {
  uint32_t count;
  uint8_t name[64];
  uint64_t appid_length;
} process_entry_t;

uint32_t get_bind_count_for_pid(ebpf_handle_t handle, uint64_t pid) {
  process_entry_t entry{};
  REQUIRE(ebpf_api_map_lookup_element(handle, sizeof(pid), (uint8_t *)&pid,
                                      sizeof(entry),
                                      (uint8_t *)&entry) == ERROR_SUCCESS);

  return entry.count;
}

ebpf::bind_action_t emulate_bind(uint64_t pid, const char *appid) {
  uint32_t result;
  std::string app_id = appid;
  ebpf::bind_md_t ctx{0};
  ctx.app_id_start = const_cast<char *>(app_id.c_str());
  ctx.app_id_end = const_cast<char *>(app_id.c_str()) + app_id.size();
  ctx.process_id = pid;
  ctx.operation = ebpf::BIND_OPERATION_BIND;
  REQUIRE(ebpf_core_invoke_hook(EBPF_PROGRAM_TYPE_BIND, &ctx, &result) ==
          EBPF_ERROR_SUCCESS);
  return static_cast<ebpf::bind_action_t>(result);
}

void emulate_unbind(uint64_t pid, const char *appid) {
  uint32_t result;
  std::string app_id = appid;
  ebpf::bind_md_t ctx{0};
  ctx.process_id = pid;
  ctx.operation = ebpf::BIND_OPERATION_UNBIND;
  REQUIRE(ebpf_core_invoke_hook(EBPF_PROGRAM_TYPE_BIND, &ctx, &result) ==
          EBPF_ERROR_SUCCESS);
}

void set_bind_limit(ebpf_handle_t handle, uint32_t limit) {
  uint32_t limit_key = 0;
  REQUIRE(ebpf_api_map_update_element(handle, sizeof(limit_key),
                                      (uint8_t *)&limit_key, sizeof(limit),
                                      (uint8_t *)&limit) == ERROR_SUCCESS);
}

TEST_CASE("bindmonitor-interpret", "[bindmonitor_interpret]") {
  device_io_control_handler = GlueDeviceIoControl;
  create_file_handler = GlueCreateFileW;
  close_handle_handler = GlueCloseHandle;

  ebpf_handle_t program_handle;
  const char *error_message = NULL;
  bool ec_initialized = false;
  bool api_initialized = false;
  ebpf_handle_t map_handles[2];
  uint32_t count_of_map_handles = 2;
  uint64_t fake_pid = 12345;

  _unwind_helper on_exit([&] {
    ebpf_api_free_error_message(error_message);
    if (api_initialized)
      ebpf_api_terminate();
    if (ec_initialized)
      ebpf_core_terminate();
  });

  REQUIRE(ebpf_core_initialize() == EBPF_ERROR_SUCCESS);
  ec_initialized = true;

  REQUIRE(ebpf_api_initiate() == ERROR_SUCCESS);
  api_initialized = true;

  REQUIRE(ebpf_api_load_program(SAMPLE_PATH "bindmonitor.o", "bind",
                                EBPF_EXECUTION_INTERPRET, &program_handle,
                                &count_of_map_handles, map_handles,
                                &error_message) == ERROR_SUCCESS);
  REQUIRE(error_message == NULL);

  REQUIRE(ebpf_api_attach_program(program_handle, EBPF_PROGRAM_TYPE_BIND) ==
          ERROR_SUCCESS);

  // Apply policy of maximum 2 binds per process
  set_bind_limit(map_handles[1], 2);

  // Bind first port - success
  REQUIRE(emulate_bind(fake_pid, "fake_app_1") == ebpf::BIND_PERMIT);
  REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 1);

  // Bind second port - success
  REQUIRE(emulate_bind(fake_pid, "fake_app_1") == ebpf::BIND_PERMIT);
  REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 2);

  // Bind third port - blocked
  REQUIRE(emulate_bind(fake_pid, "fake_app_1") == ebpf::BIND_DENY);
  REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 2);

  // Unbind second port
  emulate_unbind(fake_pid, "fake_app_1");
  REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 1);

  // Unbind first port
  emulate_unbind(fake_pid, "fake_app_1");
  REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 0);

  // Unbind a port we don't own
  emulate_unbind(fake_pid, "fake_app_1");
  REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 0);

  fake_pid = 54321;
  REQUIRE(emulate_bind(fake_pid, "fake_app_2") == ebpf::BIND_PERMIT);
  REQUIRE(get_bind_count_for_pid(map_handles[0], fake_pid) == 1);

  uint64_t pid;
  REQUIRE(ebpf_api_map_next_key(map_handles[0], sizeof(uint64_t), NULL,
                                reinterpret_cast<uint8_t *>(&pid)) ==
          ERROR_SUCCESS);
  REQUIRE(pid != 0);
  REQUIRE(ebpf_api_map_next_key(map_handles[0], sizeof(uint64_t),
                                reinterpret_cast<uint8_t *>(&pid),
                                reinterpret_cast<uint8_t *>(&pid)) ==
          ERROR_SUCCESS);
  REQUIRE(pid != 0);
  REQUIRE(ebpf_api_map_next_key(map_handles[0], sizeof(uint64_t),
                                reinterpret_cast<uint8_t *>(&pid),
                                reinterpret_cast<uint8_t *>(&pid)) ==
          ERROR_NO_MORE_ITEMS);
}