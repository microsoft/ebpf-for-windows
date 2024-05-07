// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <thread>
#include <vector>
#pragma comment(lib, "ws2_32.lib")

struct _address_info
{
    _address_info(_In_ const ADDRINFOA* addrinfo) : _addrinfo(const_cast<ADDRINFO*>(addrinfo)) {}
    ~_address_info() { freeaddrinfo(_addrinfo); }
    ADDRINFOA* _addrinfo;
};

int
main(int argc, const char** argv)
{
    WSAData data;

    if (argc != 2) {
        printf("Usage: %s target_ip\n", argv[0]);
        return 1;
    }

    if (WSAStartup(2, &data) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    unsigned short us = 0x1234;
    us = us >> 8 | us << 8;
    printf("%.2X\n", us);
    Sleep(10000);

    auto socket = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, 0);
    if (socket == INVALID_SOCKET) {
        printf("WSASocket failed\n");
        return 1;
    }
    ADDRINFOA* addrinfo = nullptr;

    if (getaddrinfo(argv[1], "53", nullptr, &addrinfo) != 0) {
        printf("getaddrinfo failed \n");
        return 1;
    }

    _address_info _address_information(const_cast<const ADDRINFOA*>(addrinfo));

    if (connect(socket, addrinfo->ai_addr, static_cast<int>(addrinfo->ai_addrlen)) != 0) {
        printf("connect failed \n");
        return 1;
    }

    std::vector<WSABUF> buffers(1024);
    char a = 'A';
    for (auto& b : buffers) {
        b.buf = &a;
        b.len = 0;
    }
    unsigned long bytes_sent;

    volatile long packet_sent = 0;
    std::vector<std::thread> threads(4);

    for (auto& t : threads) {
        t = std::thread([&] {
            for (;;) {
                if (WSASend(
                        socket,
                        buffers.data(),
                        static_cast<unsigned long>(buffers.size()),
                        &bytes_sent,
                        0,
                        nullptr,
                        nullptr) != 0) {
                    printf("WSASend failed\n");
                    return 1;
                }
                InterlockedAdd(&packet_sent, static_cast<long>(buffers.size()));
            }
        });
    }

    for (;;) {
        long old = packet_sent;
        Sleep(1000);
        printf("%d\n", packet_sent - old);
    }
}
