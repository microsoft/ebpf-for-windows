#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>

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
    HANDLE deviceHandle;
    DWORD error = NO_ERROR;
    LPCWSTR ebpfDeviceName = L"\\\\.\\EbpfIoDevice";
    ULONG bytesReturned;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    deviceHandle = CreateFile(ebpfDeviceName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (deviceHandle == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        printf("Error: CreatFile Failed : %d\n", error);
        goto Exit;
    }
    /*
    * 
0000000000000000 <DropPacket>:
       0: 89 4c 24 08                   movl    %ecx, 8(%rsp)
       4: 83 7c 24 08 11                cmpl    $17, 8(%rsp)
       9: 75 06                         jne     0x11 <DropPacket+0x11>
       b: 33 c0                         xorl    %eax, %eax
       d: eb 07                         jmp     0x16 <DropPacket+0x16>
       f: eb 05                         jmp     0x16 <DropPacket+0x16>
      11: b8 01 00 00 00                movl    $1, %eax
      16: c3                            retq

    */
    char inputBuffer[100] = 
        { 
        0x89, 0x4c, 0x24, 0x08,
        0x83, 0x7c, 0x24, 0x08, 0x11,
        0x75,0x06,
        0x33, 0xc0,
        0xeb,0x07,
        0xeb, 0x05,
        0xb8, 0x01, 00, 00, 00,
        0xc3
        };

    DWORD inputBufferLength = 0x17;
    printf("InputBuffer Pointer = %p, BufLength = %Iu\n", inputBuffer,
        sizeof(inputBuffer));

    error = DeviceIoControl(
        deviceHandle,
        (DWORD)IOCTL_EBPFCTL_METHOD_BUFFERED,
        &inputBuffer,
        (DWORD)inputBufferLength,
        NULL,
        0,
        &bytesReturned,
        NULL);
    if (!error)
    {
        error = GetLastError();
        printf("Error in DeviceIoControl : %d", error);
        goto Exit;
    }

Exit:
    return error;
}