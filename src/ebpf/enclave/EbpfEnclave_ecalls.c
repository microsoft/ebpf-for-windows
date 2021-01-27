/*
 *  Copyright (C) 2020, Microsoft Corporation, All Rights Reserved
 *  SPDX-License-Identifier: MIT
*/

#include "EbpfEnclave_t.h"
#include "secure_channel.h"
#include "log.h"
#include <stdio.h>
#include <stdarg.h>
#include <ubpf.h>

#define HEAP_SIZE_BYTES (2 * 1024 * 1024) /* 2 MB */
#define STACK_SIZE_BYTES (24 * 1024)      /* 24 KB */

#define SGX_PAGE_SIZE (4 * 1024) /* 4 KB */

#define TA_UUID /* 729242ad-3250-47d5-adda-651dac658f65 */ {0x729242ad,0x3250,0x47d5,{0xad,0xda,0x65,0x1d,0xac,0x65,0x8f,0x65}}

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,               /* UUID */
    HEAP_SIZE_BYTES,       /* HEAP_SIZE */
    STACK_SIZE_BYTES,      /* STACK_SIZE */
    TA_FLAG_MULTI_SESSION, /* FLAGS */
    "1.0.0",               /* VERSION */
    "EbpfEnclave TA");   /* DESCRIPTION */

OE_SET_ENCLAVE_SGX(
    1, /* ProductID */
    1, /* SecurityVersion */
#ifdef _DEBUG
    1, /* Debug */
#else
    0, /* Debug */
#endif
    HEAP_SIZE_BYTES / SGX_PAGE_SIZE,  /* NumHeapPages */
    STACK_SIZE_BYTES / SGX_PAGE_SIZE, /* NumStackPages */
    1);                               /* NumTCS */


static uint64_t map_resolver(void* context, uint64_t fd)
{
    size_t return_value;
    unsigned char message[MAX_LOG_MESSAGE_SIZE];
    int message_size = 0;
    unsigned char reply[MAX_LOG_MESSAGE_SIZE];
    int reply_size = 0;
    struct secure_channel_state * state = (struct secure_channel_state *)context;

    // TODO: Encode message

    return_value = secure_channel_send_receive_message(state, message, message_size, reply, reply_size);

    // TODO: Decode response

    return return_value;
}

void ebpf_enclave_log(log_level level, const char* format, ...)
{
    char buffer[MAX_LOG_MESSAGE_SIZE];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    ocall_ebpf_enclave_log(level, buffer);
}


int send_helper(void* context, const unsigned char* buffer, size_t length)
{
    size_t return_value;
    oe_result_t oe_result;
    oe_result = ocall_write_execution_context(&return_value, context, buffer, length);
    if (oe_result != OE_OK)
    {
        return -1;
    }

    // mbedtls send function assumes this always returns int not size_t
    return (int)return_value;
}

int recv_helper(void* context, unsigned char* buffer, size_t length)
{
    size_t return_value;
    oe_result_t oe_result;
    oe_result = ocall_read_execution_context(&return_value, context, buffer, length);
    if (oe_result != OE_OK)
    {
        return -1;
    }

    // mbedtls receive function assumes this always returns int not size_t
    return (int)return_value;
}

size_t ecall_verify_and_jit(unsigned char* byte_code,
    size_t byte_code_size,
    unsigned char* machine_code,
    size_t machine_code_size)
{
    int result = 0;
    struct ubpf_vm* vm = NULL;
    char* errmsg = NULL;
    struct secure_channel_state  * state = NULL;
    uint64_t execution_context = 0;

    ocall_open_execution_context(&execution_context);

    result = secure_channel_init(&state);
    if (result != 0)
    {
        result = -1;
        goto cleanup;
    }

    result = secure_channel_open(state, execution_context, &send_helper, &recv_helper);
    if (result != 0)
    {
        result = -1;
        goto cleanup;
    }

    vm = ubpf_create();
    if (vm == NULL)
    {
        result = -1;
        goto cleanup;
    }

    result = ubpf_register_map_resolver(vm, &state, map_resolver);
    if (result != 0)
    {
        goto cleanup;
    }

    result = ubpf_load(vm, byte_code, byte_code_size, &errmsg);
    if (result != 0)
    {
        goto cleanup;
    }

    result = ubpf_translate(vm, machine_code, machine_code_size, &errmsg);
    if (result != 0)
    {
        goto cleanup;
    }

cleanup:
    if (execution_context != 0)
    {
        ocall_close_execution_context(execution_context);
    }
    if (vm != NULL)
    {
        ubpf_destroy(vm);
    }
    return result;
}

