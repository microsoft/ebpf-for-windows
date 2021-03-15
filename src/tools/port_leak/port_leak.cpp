/*
 *  Copyright (c) Microsoft Corporation
 *  SPDX-License-Identifier: MIT
 */

#include <WinSock2.h>
#include <iostream>
#include <Windows.h>

int
main()
{
    WSADATA wsa_data;
    WSAStartup(2, &wsa_data);
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
            DWORD err = WSAGetLastError();
            wchar_t* s = NULL;
            FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                WSAGetLastError(),
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPWSTR)&s,
                0,
                NULL);
            printf("bind failed: %S\t%d\n", s, WSAGetLastError());
            LocalFree(s);
            Sleep(1000);
        }
    }
}