/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
*/

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include "..\EbpfCore\types.h"
#include "protocol.h"

// Device type 
#define EBPF_IOCTL_TYPE FILE_DEVICE_NETWORK

// Function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_EBPFCTL_METHOD_BUFFERED \
    CTL_CODE( EBPF_IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS  )

int main(
    _In_ ULONG argc,
    _In_reads_(argc) PCHAR argv[]
)
{
    HANDLE device_handle = INVALID_HANDLE_VALUE;
    DWORD error = NO_ERROR;
    LPCWSTR ebpf_device_name = L"\\\\.\\EbpfIoDevice";
    ULONG bytes_returned;
    void* input_buffer = NULL;
    struct _ebpf_operation_header* header = NULL;
    int action = 0;
    UINT64 input_handle;
    DWORD input_bufferLength;
    struct _ebpf_operation_load_code_request* load_request;
    struct _ebpf_operation_load_code_reply output_buffer = { 0 };
    DWORD output_buffer_length = sizeof(struct _ebpf_operation_load_code_reply);
    UINT64 handle = 0;

    if (argc < 2)
    {
        printf("usage: ebpftool.exe <load(0)/EBPF_OPERATION_ATTACH_CODE(1)/unload(2)> <handle>\n");
        return;
    }

    action = atoi(argv[1]);
    if (action != 0 )
    {
        if (argc < 3)
        {
            printf("handle required for EBPF_OPERATION_ATTACH_CODE and unload.\n");
            return;
        }
        input_handle = atoi(argv[2]);
    }    
        
    device_handle = CreateFile(ebpf_device_name,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (device_handle == INVALID_HANDLE_VALUE) 
    {
        error = GetLastError();
        printf("Error: CreatFile Failed : %d\n", error);
        goto Exit;
    }

    /*
    * Read code from file later.
llvm-objdump -d dropjit.o

dropjit.o:      file format coff-x86-64


Disassembly of section :

0000000000000000 <DropPacket>:
       0: 48 8b 01                      movq    (%rcx), %rax
       3: 48 8b 49 08                   movq    8(%rcx), %rcx
       7: 48 8d 50 1c                   leaq    28(%rax), %rdx
       b: 48 39 ca                      cmpq    %rcx, %rdx
       e: 77 1d                         ja      0x2d <DropPacket+0x2d>
      10: 48 8d 50 08                   leaq    8(%rax), %rdx
      14: 48 39 ca                      cmpq    %rcx, %rdx
      17: 77 14                         ja      0x2d <DropPacket+0x2d>
      19: 80 78 09 11                   cmpb    $17, 9(%rax)
      1d: 75 0e                         jne     0x2d <DropPacket+0x2d>
      1f: 66 83 78 18 01                cmpw    $1, 24(%rax)
      24: b8 01 00 00 00                movl    $1, %eax
      29: 83 d0 00                      adcl    $0, %eax
      2c: c3                            retq
      2d: b8 01 00 00 00                movl    $1, %eax
      32: c3                            retq

    */
    char code[100] =
    {
    0x48, 0x8b, 0x1,
    0x48, 0x8b, 0x49, 0x8,
    0x48, 0x8d, 0x50, 0x1c,
    0x48, 0x39, 0xca,
    0x77, 0x1d,
    0x48, 0x8d, 0x50, 0x08,
    0x48, 0x39, 0xca,
    0x77, 0x14,
    0x80, 0x78, 0x09, 0x11,
    0x75, 0x0e,
    0x66, 0x83 ,0x78 ,0x18 ,0x01,
    0xb8, 0x01, 00, 00, 00,
    0x83, 0xd0, 0x0,
    0xc3,
    0xb8, 0x01, 00, 00, 00,
    0xc3
    };
    input_bufferLength = sizeof(code) + sizeof(struct _ebpf_operation_load_code_request);

    input_buffer = malloc(input_bufferLength);
    if (input_buffer == NULL)
    {
        error = ERROR_OUTOFMEMORY;
        goto Exit;
    }

    if (action == 0) //load
    {
        load_request = input_buffer;
        load_request->header.id = EBPF_OPERATION_LOAD_CODE;
        load_request->header.length = input_bufferLength;
        RtlCopyMemory(&load_request->machine_code, code, sizeof(code));


        error = DeviceIoControl(
            device_handle,
            (DWORD)IOCTL_EBPFCTL_METHOD_BUFFERED,
            input_buffer,
            (DWORD)input_bufferLength,
            &output_buffer,
            output_buffer_length,
            &bytes_returned,
            NULL);
        if (!error)
        {
            error = GetLastError();
            printf("Error in DeviceIoControl : %d", error);
            goto Exit;
        }

        handle = output_buffer.handle;
        printf("Load succeeded. Program handle %lld\n", handle);

    }
    else if (action == 1) // EBPF_OPERATION_ATTACH_CODE
    {
        // EBPF_OPERATION_ATTACH_CODE.
        header = (struct _ebpf_operation_header*)input_buffer;
        header->id = EBPF_OPERATION_ATTACH_CODE;
        struct _ebpf_operation_attach_detach_request* attachRequest = input_buffer;
        attachRequest->handle = input_handle;
        attachRequest->hook = 1;

        error = DeviceIoControl(
            device_handle,
            (DWORD)IOCTL_EBPFCTL_METHOD_BUFFERED,
            input_buffer,
            (DWORD)input_bufferLength,
            &output_buffer,
            output_buffer_length,
            &bytes_returned,
            NULL);
        if (!error)
        {
            error = GetLastError();
            printf("Error in DeviceIoControl : %d", error);
            goto Exit;
        }

        printf("Attach succeeded\n");
    }
    else if (action == 2) // unload
    {
        header = (struct _ebpf_operation_header*)input_buffer;
        struct _ebpf_operation_unload_code_request* unloadRequest = input_buffer;
        header->id = EBPF_OPERATION_UNLOAD_CODE;
        unloadRequest->handle = input_handle;

        error = DeviceIoControl(
            device_handle,
            (DWORD)IOCTL_EBPFCTL_METHOD_BUFFERED,
            input_buffer,
            (DWORD)input_bufferLength,
            &output_buffer,
            output_buffer_length,
            &bytes_returned,
            NULL);
        if (!error)
        {
            error = GetLastError();
            printf("Error in DeviceIoControl : %d", error);
            goto Exit;
        }

        printf("Unload succeeded\n");
    }
Exit:
    free(input_buffer);

    if (device_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(device_handle);
    }

    return error;
}