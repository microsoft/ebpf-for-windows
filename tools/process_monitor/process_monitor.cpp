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
typedef enum _process_operation
{
    PROCESS_OPERATION_CREATE, ///< Process creation.
    PROCESS_OPERATION_DELETE, ///< Process deletion.
} process_operation_t;

typedef struct
{
    uint64_t process_id;
    uint64_t parent_process_id;
    uint64_t creating_process_id;
    uint64_t creating_thread_id;
    uint64_t operation;
} process_info_t;

struct bpf_map* process_map;
struct bpf_map* command_map;

int
process_monitor_history_callback(void* ctx, void* data, size_t size)
{
    UNREFERENCED_PARAMETER(ctx);
    if (size != sizeof(process_info_t)) {
        return 0;
    }
    process_info_t* event = (process_info_t*)data;
    std::string file_name;
    std::string command_line;

    file_name.resize(1024);
    command_line.resize(1024);

    // Get the process name.
    bpf_map_lookup_elem(bpf_map__fd(process_map), &event->process_id, file_name.data());
    bpf_map_lookup_elem(bpf_map__fd(command_map), &event->process_id, command_line.data());

    // Trim the strings.
    file_name.resize(strlen(file_name.c_str()));
    command_line.resize(strlen(command_line.c_str()));

    switch (event->operation) {
    case PROCESS_OPERATION_CREATE: {
        std::cout << "Process created: " << event->process_id << "\n" << file_name << "\n" << command_line << std::endl;
        break;
    }
    case PROCESS_OPERATION_DELETE: {
        std::cout << "Process deleted: " << event->process_id << "\n" << file_name << std::endl;
        break;
    }
    default:
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

    // Command line and image path are UTF8.
    SetConsoleOutputCP(CP_UTF8);

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

    process_map = bpf_object__find_map_by_name(object, "process_map");
    if (!process_map) {
        std::cerr << "bpf_object__find_map_by_name for \"process_map\" failed: " << errno << std::endl;
        return 1;
    }

    command_map = bpf_object__find_map_by_name(object, "command_map");
    if (!command_map) {
        std::cerr << "bpf_object__find_map_by_name for \"command_map\" failed: " << errno << std::endl;
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