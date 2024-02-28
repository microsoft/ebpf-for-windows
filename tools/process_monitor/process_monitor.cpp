// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Windows.h needs to be the first include to prevent failures in subsequent headers.
#include <windows.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <condition_variable>
#include <ebpf_api.h>
#include <iostream>
#include <mutex>
#include <string>

#pragma comment(lib, "ebpfapi.lib")

extern "C"
{
    int
    process_monitor_history_callback(void* ctx, void* data, size_t size);
}

typedef struct
{
    uint64_t parent_process_id;
    uint8_t command_line[256];
} proces_entry_t;

typedef struct
{
    uint64_t process_id;
    proces_entry_t entry;
} process_create_event_t;

typedef struct
{
    uint64_t process_id;
} process_delete_event_t;

int
process_monitor_history_callback(void* ctx, void* data, size_t size)
{
    UNREFERENCED_PARAMETER(ctx);

    switch (size) {
    case sizeof(process_create_event_t): {
        process_create_event_t* event = (process_create_event_t*)data;
        std::wcout << L"Process created: " << event->process_id << L" "
                   << reinterpret_cast<wchar_t*>(event->entry.command_line) << std::endl;
        break;
    }
    case sizeof(process_delete_event_t): {
        process_delete_event_t* event = (process_delete_event_t*)data;
        std::wcout << L"Process deleted: " << event->process_id << std::endl;
        break;
    }
    default:
        std::wcout << L"Unknown event size: " << size << std::endl;
        break;
    }

    return 0;
}

bool _shutdown = false;
std::condition_variable _wait_for_shutdown;
std::mutex _wait_for_shutdown_mutex;

int
control_handler(unsigned long control_type)
{
    if (control_type != CTRL_C_EVENT) {
        return false;
    }
    std::unique_lock lock(_wait_for_shutdown_mutex);
    _shutdown = true;
    _wait_for_shutdown.notify_all();
    return true;
}

int
main(int argc, char** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    if (!SetConsoleCtrlHandler(control_handler, true)) {
        std::cerr << "SetConsoleCtrlHandler: " << GetLastError() << std::endl;
        return 1;
    }

    std::cerr << "Press Ctrl-C to shutdown" << std::endl;

    // Load process_monitor.sys BPF program.
    struct bpf_object* object = bpf_object__open("process_monitor.sys");
    if (!object) {
        std::cerr << "bpf_object__open for process_monitor.sys failed: " << errno << std::endl;
        return 1;
    }

    if (bpf_object__load(object) < 0) {
        std::cerr << "bpf_object__load for process_monitor.sys failed: " << errno << std::endl;
        return 1;
    }

    auto process_monitor = bpf_object__find_program_by_name(object, "ProcessMonitor");
    if (!process_monitor) {
        std::cerr << "bpf_object__find_program_by_name for \"connection_tracker\" failed: " << errno << std::endl;
        return 1;
    }

    auto process_monitor_link = bpf_program__attach(process_monitor);
    if (!process_monitor_link) {
        std::cerr << "BPF program process_monitor.sys failed to attach: " << errno << std::endl;
        return 1;
    }

    // Attach to ring buffer.
    bpf_map* map = bpf_object__find_map_by_name(object, "process_ringbuf");
    if (!map) {
        std::cerr << "Unable to locate history map: " << errno << std::endl;
        return 1;
    }
    auto ring = ring_buffer__new(bpf_map__fd(map), process_monitor_history_callback, nullptr, nullptr);
    if (!ring) {
        std::cerr << "Unable to create ring buffer: " << errno << std::endl;
        return 1;
    }

    // Wait for Ctrl-C.
    {
        std::unique_lock lock(_wait_for_shutdown_mutex);
        _wait_for_shutdown.wait(lock, []() { return _shutdown; });
    }

    // Detach from the attach point.
    int link_fd = bpf_link__fd(process_monitor_link);
    bpf_link_detach(link_fd);
    bpf_link__destroy(process_monitor_link);

    // Close ring buffer.
    ring_buffer__free(ring);

    // Free the BPF object.
    bpf_object__close(object);
    return 0;
}