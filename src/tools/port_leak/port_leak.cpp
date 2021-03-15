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

    for (;;) {
        Sleep(10);

        auto s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) {
            continue;
        }
        sockaddr_in addr;
        addr.sin_addr.S_un.S_addr = 0;
        addr.sin_port = 0;
        addr.sin_family = AF_INET;
        bind(s, (sockaddr*)&addr, sizeof(addr));
    }
}