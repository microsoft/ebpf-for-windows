// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/**
 * @file
 * @brief Child process helper for eBPF core restart stress test.
 * This process loads ebpfapi.dll and operates in different modes to test driver restart scenarios.
 */

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"
#include <windows.h>
#include <iostream>
#include <string>

#define PIN_PATH_MAP "/ebpf/test/restart_map"
#define PIN_PATH_PROGRAM "/ebpf/test/restart_prog"

// Signal names for IPC with controller process
#define SIGNAL_READY_HANDLES_OPEN "Global\\EBPF_RESTART_TEST_HANDLES_OPEN"
#define SIGNAL_READY_PINNED_OBJECTS "Global\\EBPF_RESTART_TEST_PINNED_OBJECTS"
#define SIGNAL_CONTROLLER_DONE "Global\\EBPF_RESTART_TEST_CONTROLLER_DONE"

enum class OperationMode
{
    OPEN_HANDLES,    // Create objects, keep handles open, wait for signal
    PIN_OBJECTS,     // Create objects, pin them, release handles, exit
    UNPIN_OBJECTS    // Unpin objects and exit
};

static void
signal_controller(const char* signal_name)
{
    HANDLE event = CreateEventA(nullptr, TRUE, FALSE, signal_name);
    if (event == nullptr) {
        std::cerr << "Failed to create event: " << signal_name << ", error: " << GetLastError() << std::endl;
        return;
    }
    SetEvent(event);
    CloseHandle(event);
}

static void
wait_for_controller()
{
    HANDLE event = CreateEventA(nullptr, TRUE, FALSE, SIGNAL_CONTROLLER_DONE);
    if (event == nullptr) {
        std::cerr << "Failed to create event for waiting, error: " << GetLastError() << std::endl;
        return;
    }
    WaitForSingleObject(event, INFINITE);
    CloseHandle(event);
}

static int
create_test_map()
{
    // Create a simple array map
    return bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, sizeof(uint32_t), sizeof(uint64_t), 10, nullptr);
}

static int
load_test_program(int& program_fd)
{
    const char* program_path = "cgroup_sock_addr.o";
    struct bpf_object* object = nullptr;
    struct bpf_program* program = nullptr;
    int result;

    // Try to open and load the program
    object = bpf_object__open(program_path);
    if (object == nullptr) {
        std::cerr << "Failed to open program: " << program_path << std::endl;
        return -1;
    }

    result = bpf_object__load(object);
    if (result < 0) {
        std::cerr << "Failed to load program: " << program_path << ", error: " << result << std::endl;
        bpf_object__close(object);
        return result;
    }

    // Get the first program
    program = bpf_object__next_program(object, nullptr);
    if (program == nullptr) {
        std::cerr << "Failed to get program from object" << std::endl;
        bpf_object__close(object);
        return -1;
    }

    program_fd = bpf_program__fd(program);
    if (program_fd < 0) {
        std::cerr << "Failed to get program fd" << std::endl;
        bpf_object__close(object);
        return -1;
    }

    // Don't close the object yet - keep it alive
    return 0;
}

static int
mode_open_handles()
{
    std::cout << "Mode: OPEN_HANDLES - Creating objects and keeping handles open" << std::endl;

    // Create a map
    int map_fd = create_test_map();
    if (map_fd < 0) {
        std::cerr << "Failed to create map, error: " << map_fd << std::endl;
        return 1;
    }

    std::cout << "Created map with fd: " << map_fd << std::endl;

    // Try to load a program (optional - may not be available)
    int program_fd = -1;
    load_test_program(program_fd);
    if (program_fd > 0) {
        std::cout << "Loaded program with fd: " << program_fd << std::endl;
    }

    // Signal that we're ready with handles open
    signal_controller(SIGNAL_READY_HANDLES_OPEN);
    std::cout << "Signaled controller: handles are open" << std::endl;

    // Wait for controller to signal us to exit
    std::cout << "Waiting for controller signal..." << std::endl;
    wait_for_controller();

    std::cout << "Controller signaled, exiting..." << std::endl;
    // Handles will be automatically closed on process exit
    return 0;
}

static int
mode_pin_objects()
{
    std::cout << "Mode: PIN_OBJECTS - Creating, pinning, and releasing objects" << std::endl;

    // Create a map
    int map_fd = create_test_map();
    if (map_fd < 0) {
        std::cerr << "Failed to create map, error: " << map_fd << std::endl;
        return 1;
    }

    std::cout << "Created map with fd: " << map_fd << std::endl;

    // Pin the map
    int result = bpf_obj_pin(map_fd, PIN_PATH_MAP);
    if (result < 0) {
        std::cerr << "Failed to pin map, error: " << result << std::endl;
        _close(map_fd);
        return 1;
    }

    std::cout << "Pinned map at: " << PIN_PATH_MAP << std::endl;

    // Try to load and pin a program (optional)
    int program_fd = -1;
    if (load_test_program(program_fd) == 0 && program_fd > 0) {
        result = bpf_obj_pin(program_fd, PIN_PATH_PROGRAM);
        if (result < 0) {
            std::cerr << "Failed to pin program, error: " << result << std::endl;
        } else {
            std::cout << "Pinned program at: " << PIN_PATH_PROGRAM << std::endl;
        }
        _close(program_fd);
    }

    // Close the map handle
    _close(map_fd);
    std::cout << "Released handles" << std::endl;

    // Signal that we're ready with pinned objects
    signal_controller(SIGNAL_READY_PINNED_OBJECTS);
    std::cout << "Signaled controller: objects are pinned and handles released" << std::endl;

    // Exit immediately - pinned objects should survive
    return 0;
}

static int
mode_unpin_objects()
{
    std::cout << "Mode: UNPIN_OBJECTS - Unpinning objects" << std::endl;

    // Unpin the map
    int result = bpf_obj_unpin(PIN_PATH_MAP);
    if (result < 0) {
        std::cerr << "Failed to unpin map at " << PIN_PATH_MAP << ", error: " << result << std::endl;
        // Continue anyway to try unpinning program
    } else {
        std::cout << "Unpinned map at: " << PIN_PATH_MAP << std::endl;
    }

    // Unpin the program
    result = bpf_obj_unpin(PIN_PATH_PROGRAM);
    if (result < 0) {
        std::cerr << "Failed to unpin program at " << PIN_PATH_PROGRAM << ", error: " << result << std::endl;
    } else {
        std::cout << "Unpinned program at: " << PIN_PATH_PROGRAM << std::endl;
    }

    std::cout << "Unpin operation completed" << std::endl;
    return 0;
}

int
main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <mode>" << std::endl;
        std::cerr << "Modes:" << std::endl;
        std::cerr << "  open-handles  : Create objects and keep handles open" << std::endl;
        std::cerr << "  pin-objects   : Create and pin objects, then release handles" << std::endl;
        std::cerr << "  unpin-objects : Unpin objects" << std::endl;
        return 1;
    }

    std::string mode_str = argv[1];
    OperationMode mode;

    if (mode_str == "open-handles") {
        mode = OperationMode::OPEN_HANDLES;
    } else if (mode_str == "pin-objects") {
        mode = OperationMode::PIN_OBJECTS;
    } else if (mode_str == "unpin-objects") {
        mode = OperationMode::UNPIN_OBJECTS;
    } else {
        std::cerr << "Unknown mode: " << mode_str << std::endl;
        return 1;
    }

    int result = 0;
    switch (mode) {
    case OperationMode::OPEN_HANDLES:
        result = mode_open_handles();
        break;
    case OperationMode::PIN_OBJECTS:
        result = mode_pin_objects();
        break;
    case OperationMode::UNPIN_OBJECTS:
        result = mode_unpin_objects();
        break;
    }

    return result;
}
