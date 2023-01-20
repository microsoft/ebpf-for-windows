// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <iostream>

#include "ebpf_leak_detector.h"
#include "ebpf_symbol_decoder.h"

void
_ebpf_leak_detector::register_allocation(uintptr_t address, size_t size)
{
    std::unique_lock<std::mutex> lock(_mutex);
    allocation_t allocation = {address, size, 0};
    std::vector<uintptr_t> stack(1 + _stack_depth);
    if (CaptureStackBackTrace(
            1,
            static_cast<unsigned int>(stack.size()),
            reinterpret_cast<void**>(stack.data()),
            &allocation.stack_hash) == 0) {
        allocation.stack_hash = 0;
    }
    _allocations[address] = allocation;
    if (!_stack_hashes.contains(allocation.stack_hash)) {
        _stack_hashes[allocation.stack_hash] = stack;
    }
}

void
_ebpf_leak_detector::unregister_allocation(uintptr_t address)
{
    std::unique_lock<std::mutex> lock(_mutex);
    _allocations.erase(address);
}

void
_ebpf_leak_detector::dump_leaks()
{
    std::unique_lock<std::mutex> lock(_mutex);
    for (auto& allocation : _allocations) {
        std::vector<uintptr_t> stack = _stack_hashes[allocation.second.stack_hash];
        std::cout << "Leak of " << allocation.second.size << " bytes at " << allocation.second.address << std::endl;
        std::string name;
        uint64_t displacement;
        std::optional<uint32_t> line_number;
        std::optional<std::string> file_name;
        for (auto address : stack) {
            if (_ebpf_decode_symbol(address, name, displacement, line_number, file_name) == EBPF_SUCCESS) {
                std::cout << "    " << name << " + " << displacement;
                if (line_number.has_value() && file_name.has_value()) {
                    std::cout << " (" << file_name.value() << ":" << line_number.value() << ")";
                }
                std::cout << std::endl;
            }
        }
        std::cout << std::endl;
    }

    _allocations.clear();
    _stack_hashes.clear();
}
