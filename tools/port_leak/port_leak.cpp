// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include <WinSock2.h>
#include <Windows.h>
#include <iostream>

int
main()
{
    WSADATA wsa_data;
    if (WSAStartup(2, &wsa_data) != 0) {
        printf("WSAStartup failed\n");
        exit(1);
    }

    int leaked_ports = 0;

    for (;;) {

        auto s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) {
            continue;
        }
        sockaddr_in addr;
        addr.sin_addr.S_un.S_addr = 0;
        addr.sin_port = 0;
        addr.sin_family = AF_INET;
        if (bind(s, (sockaddr*)&addr, sizeof(addr)) != SOCKET_ERROR) {
            leaked_ports++;
            if (leaked_ports % 100 == 0) {
                printf("Leaked %d ports\n", leaked_ports);
                Sleep(10);
            }
        } else {
            unsigned long error_value = WSAGetLastError();
            wchar_t* error_string = NULL;
            FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                error_value,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (_Null_terminated_ wchar_t*)&s,
                0,
                NULL);
            printf("bind failed: %S\t%d\n", error_string, error_value);
            LocalFree(error_string);
            Sleep(1000);
        }
    }
}
