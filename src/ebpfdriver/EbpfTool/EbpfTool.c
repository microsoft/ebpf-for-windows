#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>

// Globals
char OutputBuffer[100];
char InputBuffer[100];


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

    printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
        sizeof(InputBuffer));
    StringCbCopy(InputBuffer, sizeof(InputBuffer),
        L"This String is from User Application; using METHOD_BUFFERED");

    printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
        sizeof(OutputBuffer));
    memset(OutputBuffer, 0, sizeof(OutputBuffer));

    error = DeviceIoControl(
        deviceHandle,
        (DWORD)IOCTL_EBPFCTL_METHOD_BUFFERED,
        &InputBuffer,
        (DWORD)strlen(InputBuffer) + 1,
        &OutputBuffer,
        sizeof(OutputBuffer),
        &bytesReturned,
        NULL);
    if (!error)
    {
        error = GetLastError();
        printf("Error in DeviceIoControl : %d", error);
        goto Exit;
    }

    printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);

Exit:
    return error;
}