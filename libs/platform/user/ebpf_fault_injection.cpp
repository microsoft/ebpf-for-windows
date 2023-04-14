// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "ebpf_fault_injection.h"
#include "ebpf_symbol_decoder.h"

#include <DbgHelp.h>
#include <cstddef>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

/**
 * @brief This class is used to track potential fault points and fail them in
 * a deterministic manner. Increasing the number of stack frames examined will
 * increase the accuracy of the test, but also increase the time it takes to run
 * the test.
 */
typedef class _ebpf_fault_injection
{
  public:
    /**
     * @brief Construct a new ebpf fault injection object.
     * @param[in] stack_depth The number of stack frames to compare when tracking faults.
     */
    _ebpf_fault_injection(size_t stack_depth);

    /**
     * @brief Destroy the ebpf fault injection object.
     */
    ~_ebpf_fault_injection();

    bool
    inject_fault();

  private:
    /**
     * @brief Compute a hash over the current stack.
     */
    struct _stack_hasher
    {
        size_t
        operator()(const std::vector<uintptr_t>& key) const
        {
            size_t hash_value = 0;
            for (const auto value : key) {
                hash_value ^= std::hash<uintptr_t>{}(value);
            }
            return hash_value;
        }
    };

    /**
     * @brief Determine if this path is new.
     * If it is new, then inject the fault, add it to the set of known
     * fault paths and return true.
     */
    bool
    is_new_stack();

    /**
     * @brief Write the current stack to the log file.
     */
    void
    log_stack_trace(const std::vector<uintptr_t>& canonical_stack, const std::vector<uintptr_t>& stack);

    /**
     * @brief Load the list of known faults from the log file.
     */
    void
    load_fault_log();

    /**
     * @brief The base address of the current process.
     */
    uintptr_t _base_address = 0;

    /**
     * @brief The iteration number of the current test pass.
     */
    size_t _iteration = 0;

    /**
     * @brief The log file for faults that have been injected.
     */
    _Guarded_by_(_mutex) std::ofstream _log_file;

    /**
     * @brief The set of known fault paths.
     */
    _Guarded_by_(_mutex) std::unordered_set<std::vector<uintptr_t>, _stack_hasher> _fault_hash;

    /**
     * @brief The mutex to protect the set of known fault paths.
     */
    std::mutex _mutex;

    size_t _stack_depth;
    _Guarded_by_(_mutex) std::vector<std::string> _last_fault_stack;

} ebpf_fault_injection_t;

static std::unique_ptr<ebpf_fault_injection_t> _ebpf_fault_injection_singleton;

// Link with DbgHelp.lib
#pragma comment(lib, "dbghelp.lib")

/**
 * @brief Approximate size in bytes of the image being tested.
 */
#define EBPF_MODULE_SIZE_IN_BYTES (10 * 1024 * 1024)

/**
 * @brief The number of stack frames to write to the human readable log.
 */
#define EBPF_FAULT_STACK_CAPTURE_FRAME_COUNT 16

/**
 * @brief The number of stack frames to capture to uniquely identify an fault path.
 */
#define EBPF_FAULT_STACK_CAPTURE_FRAME_COUNT_FOR_HASH 4

#define EBPF_MODULE_SIZE_IN_BYTES (10 * 1024 * 1024)

#define EBPF_FAULT_STACK_CAPTURE_FRAMES_TO_SKIP 3

/**
 * @brief Thread local storage to track recursing from the fault injection callback.
 */
static thread_local int _ebpf_fault_injection_recursion = 0;

/**
 * @brief Class to automatically increment and decrement the recursion count.
 */
class ebpf_fault_injection_recursion_guard
{
  public:
    ebpf_fault_injection_recursion_guard() { _ebpf_fault_injection_recursion++; }
    ~ebpf_fault_injection_recursion_guard() { _ebpf_fault_injection_recursion--; }
    /**
     * @brief Return true if the current thread is recursing from the fault injection callback.
     * @retval true The current thread is recursing from the fault injection callback.
     * @retval false The current thread is not recursing from the fault injection callback.
     */
    bool
    is_recursing()
    {
        return (_ebpf_fault_injection_recursion > 1);
    }
};

_ebpf_fault_injection::_ebpf_fault_injection(size_t stack_depth = EBPF_FAULT_STACK_CAPTURE_FRAME_COUNT_FOR_HASH)
    : _stack_depth(stack_depth)
{
    _base_address = (uintptr_t)(GetModuleHandle(nullptr));
    load_fault_log();
}

_ebpf_fault_injection::~_ebpf_fault_injection()
{
    _log_file.flush();
    _log_file.close();
}

bool
_ebpf_fault_injection::inject_fault()
{
    return is_new_stack();
}

bool
_ebpf_fault_injection::is_new_stack()
{
    // Prevent infinite recursion during fault injection.
    ebpf_fault_injection_recursion_guard recursion_guard;
    if (recursion_guard.is_recursing()) {
        return false;
    }
    bool new_stack = false;

    std::vector<uintptr_t> stack(EBPF_FAULT_STACK_CAPTURE_FRAME_COUNT);
    std::vector<uintptr_t> canonical_stack(_stack_depth);

    unsigned long hash;
    // Capture EBPF_FAULT_STACK_CAPTURE_FRAME_COUNT_FOR_HASH frames of the current stack trace.
    // The first EBPF_FAULT_STACK_CAPTURE_FRAMES_TO_SKIP frames are skipped to avoid
    // capturing the fault injection code.
    if (CaptureStackBackTrace(
            EBPF_FAULT_STACK_CAPTURE_FRAMES_TO_SKIP,
            static_cast<unsigned int>(stack.size()),
            reinterpret_cast<void**>(stack.data()),
            &hash) > 0) {
        // Form the canonical stack.
        for (size_t i = 0; i < _stack_depth; i++) {
            uintptr_t frame = stack[i];
            if (frame < _base_address || frame > (_base_address + EBPF_MODULE_SIZE_IN_BYTES)) {
                frame = 0;
            } else {
                frame -= _base_address;
            }
            canonical_stack[i] = frame;
        }

        std::unique_lock lock(_mutex);
        // Check if the stack trace is already in the hash.
        if (!_fault_hash.contains(canonical_stack)) {
            _fault_hash.insert(canonical_stack);
            new_stack = true;
        }
    }
    if (new_stack) {
        log_stack_trace(canonical_stack, stack);
    }

    return new_stack;
}

void
_ebpf_fault_injection::log_stack_trace(
    const std::vector<uintptr_t>& canonical_stack, const std::vector<uintptr_t>& stack)
{
    // Decode stack trace outside of the lock.
    std::ostringstream log_record;
    for (auto i : canonical_stack) {
        log_record << std::hex << i << " ";
    }
    log_record << std::endl;

    std::vector<std::string> local_last_fault_stack;

    for (auto frame : stack) {
        std::string name;
        std::string string_stack_frame;
        uint64_t displacement;
        std::optional<uint32_t> line_number;
        std::optional<std::string> file_name;
        if (frame == 0) {
            break;
        }
        log_record << "# ";
        if (_ebpf_decode_symbol(frame, name, displacement, line_number, file_name) == EBPF_SUCCESS) {
            log_record << std::hex << frame << " " << name << " + " << displacement;
            string_stack_frame = name + " + " + std::to_string(displacement);
            if (line_number.has_value() && file_name.has_value()) {
                log_record << " " << file_name.value() << " " << line_number.value();
                string_stack_frame += " " + file_name.value() + " " + std::to_string(line_number.value());
            }
        }
        log_record << std::endl;
        local_last_fault_stack.push_back(string_stack_frame);
    }
    log_record << std::endl;

    {
        std::unique_lock lock(_mutex);
        _last_fault_stack = local_last_fault_stack;
        _log_file << log_record.str();
        // Flush the file after every write to prevent loss on crash.
        _log_file.flush();
    }
}

void
_ebpf_fault_injection::load_fault_log()
{
    // Get the path to the executable being run.
    char process_name[MAX_PATH];
    GetModuleFileNameA(nullptr, process_name, MAX_PATH);

    // Read back the list of faults that have been failed in the previous runs.
    std::string fault_log_file = process_name;
    fault_log_file += ".fault.log";
    {
        std::ifstream fault_log(fault_log_file);
        std::string line;
        std::string frame;
        while (std::getline(fault_log, line)) {
            // Count the iterations to correlate crashes with the last failed fault.
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
            _fault_hash.insert(stack);
        }
        fault_log.close();
    }

    // Re-open the log file in append mode to record the faults that are failed in this run.
    _log_file.open(fault_log_file, std::ios_base::app);

    // Add the current iteration number to the log file.
    _log_file << "# Iteration: " << ++_iteration << std::endl;
}

ebpf_result_t
ebpf_fault_injection_initialize(size_t stack_depth) noexcept
{
    try {
        _ebpf_fault_injection_singleton = std::make_unique<_ebpf_fault_injection>(stack_depth);
    } catch (...) {
        return EBPF_NO_MEMORY;
    }
    return EBPF_SUCCESS;
}

void
ebpf_fault_injection_uninitialize() noexcept
{
    _ebpf_fault_injection_singleton.reset();
}

bool
ebpf_fault_injection_inject_fault() noexcept
{
    try {
        if (_ebpf_fault_injection_singleton) {
            return _ebpf_fault_injection_singleton->inject_fault();
        }
        return false;
    } catch (...) {
        return false;
    }
}

bool
ebpf_fault_injection_is_enabled() noexcept
{
    return _ebpf_fault_injection_singleton != nullptr;
}