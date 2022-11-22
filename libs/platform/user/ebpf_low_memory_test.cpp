// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_low_memory_test.h"

#include <DbgHelp.h>
#include <sstream>
#include <string>

// Link with DbgHelp.lib
#pragma comment(lib, "dbghelp.lib")

/**
 * @brief Approximate size in bytes of the image being tested.
 *
 */
#define EBPF_MODULE_SIZE_IN_BYTES (10 * 1024 * 1024)

/**
 * @brief The number of stack frames to write to the human readable log.
 */
#define EBPF_ALLOCATION_STACK_CAPTURE_FRAME_COUNT 16

/**
 * @brief The number of stack frames to capture to uniquely identify an allocation stack.
 *
 */
#define EBPF_ALLOCATION_STACK_CAPTURE_FRAME_COUNT_FOR_HASH 4

#define EBPF_MODULE_SIZE_IN_BYTES (10 * 1024 * 1024)

/**
 * @brief Thread local storage to track recursing from the low memory callback.
 */
static thread_local int _ebpf_low_memory_test_recursion = 0;

/**
 * @brief Class to automatically increment and decrement the recursion count.
 */
class ebpf_low_memory_test_recursion_guard
{
  public:
    ebpf_low_memory_test_recursion_guard() { _ebpf_low_memory_test_recursion++; }
    ~ebpf_low_memory_test_recursion_guard() { _ebpf_low_memory_test_recursion--; }
    /**
     * @brief Return true if the current thread is recursing from the low memory callback.
     * @retval true
     * @retval false
     */
    bool
    is_recursing()
    {
        return (_ebpf_low_memory_test_recursion > 1);
    }
};

_ebpf_low_memory_test::_ebpf_low_memory_test(size_t stack_depth = EBPF_ALLOCATION_STACK_CAPTURE_FRAME_COUNT_FOR_HASH)
    : _stack_depth(stack_depth)
{
    _base_address = (uintptr_t)(GetModuleHandle(nullptr));
    load_allocation_log();
}

_ebpf_low_memory_test::~_ebpf_low_memory_test()
{
    _log_file.flush();
    _log_file.close();
}

bool
_ebpf_low_memory_test::fail_stack_allocation()
{
    std::unique_lock lock(_mutex);
    return is_new_stack();
}

bool
_ebpf_low_memory_test::is_new_stack()
{
    // Prevent infinite recursion during allocation.
    ebpf_low_memory_test_recursion_guard recursion_guard;
    if (recursion_guard.is_recursing()) {
        return false;
    }
    std::vector<uintptr_t> stack(EBPF_ALLOCATION_STACK_CAPTURE_FRAME_COUNT);
    std::vector<uintptr_t> canonical_stack(_stack_depth);

    DWORD hash;
    // Capture EBPF_ALLOCATION_STACK_CAPTURE_FRAME_COUNT_FOR_HASH frames of the current stack trace.
    if (CaptureStackBackTrace(
            1, static_cast<unsigned int>(stack.size()), reinterpret_cast<void**>(stack.data()), &hash) > 0) {
        // Form the canonical stack
        for (size_t i = 0; i < _stack_depth; i++) {
            uintptr_t frame = stack[i];
            if (frame < _base_address || frame > (_base_address + EBPF_MODULE_SIZE_IN_BYTES)) {
                frame = 0;
            } else {
                frame -= _base_address;
            }
            canonical_stack[i] = frame;
        }

        // Check if the stack trace is already in the hash.
        if (_allocation_hash.contains(canonical_stack)) {
            // Stack is already in the hash, allow the allocation.
            return false;
        } else {
            // Stack is not in the hash, add it to the hash, write it to the log file and fail the allocation.
            _allocation_hash.insert(canonical_stack);
            log_stack_trace(canonical_stack, stack);
            return true;
        }
    }
    return false;
}

void
_ebpf_low_memory_test::log_stack_trace(
    const std::vector<uintptr_t>& canonical_stack, const std::vector<uintptr_t>& stack)
{
    for (auto i : canonical_stack) {
        _log_file << std::hex << i << " ";
    }
    _log_file << std::endl;

    _last_failure_stack.resize(0);

    std::vector<uint8_t> symbol_buffer(sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR));
    SYMBOL_INFO* symbol = reinterpret_cast<SYMBOL_INFO*>(symbol_buffer.data());
    IMAGEHLP_LINE64 line;
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = MAX_SYM_NAME;
    for (auto frame : stack) {
        std::string string_stack_frame;
        if (frame == 0) {
            break;
        }
        DWORD64 displacement = 0;
        _log_file << "# ";
        if (SymFromAddr(GetCurrentProcess(), frame, &displacement, symbol)) {
            _log_file << std::hex << frame << " " << symbol->Name << " + " << displacement;
            string_stack_frame = std::string(symbol->Name) + " + " + std::to_string(displacement);
            DWORD displacement32 = (DWORD)displacement;
            if (SymGetLineFromAddr64(GetCurrentProcess(), frame, &displacement32, &line)) {
                _log_file << " " << line.FileName << std::dec << " " << line.LineNumber;
                string_stack_frame += " " + std::string(line.FileName) + " " + std::to_string(line.LineNumber);
            }
            _log_file << std::endl;
        } else {
            _log_file << std::hex << frame << std::endl;
            string_stack_frame = std::to_string(frame);
        }
        _last_failure_stack.push_back(string_stack_frame);
    }
    _log_file << std::endl;
    // Flush the file after every write to prevent loss on crash.
    _log_file.flush();
}

void
_ebpf_low_memory_test::load_allocation_log()
{
    // Get the path to the executable being run.
    char process_name[MAX_PATH];
    GetModuleFileNameA(nullptr, process_name, MAX_PATH);

    // Read back the list of allocations that have been failed in the previous runs.
    std::string allocation_log_file = process_name;
    allocation_log_file += ".allocation.log";
    {
        std::ifstream allocation_log(allocation_log_file);
        std::string line;
        std::string frame;
        while (std::getline(allocation_log, line)) {
            // Count the iterations to correlate crashes with the last failed allocation.
            if (line.starts_with("# Iteration: ")) {
                _iteration++;
                continue;
            }
            // Skip the stack trace.
            if (line.starts_with("#")) {
                continue;
            }
            // Parse the stack frame.
            std::vector<uintptr_t> stack;
            auto stream = std::istringstream(line);
            while (std::getline(stream, frame, ' ')) {
                stack.push_back(std::stoull(frame, nullptr, 16));
            }
            _allocation_hash.insert(stack);
        }
        allocation_log.close();
    }

    // Re-open the log file in append mode to record the allocations that are failed in this run.
    _log_file.open(allocation_log_file, std::ios_base::app);

    // Add the current iteration number to the log file.
    _log_file << "# Iteration: " << ++_iteration << std::endl;

    // Initialize DbgHelp.dll.
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    SymInitialize(GetCurrentProcess(), nullptr, TRUE);
    SymSetOptions(SYMOPT_LOAD_LINES);
}
