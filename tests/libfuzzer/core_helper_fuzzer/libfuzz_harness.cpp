// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <chrono>
#include <cstdlib>
#include "libfuzzer.h"
#include "ebpf_program.h"
#include "ubpf.h"

static ebpf_result_t
_ebpf_program_load_byte_code(
    _Inout_ ebpf_program_t* program, _In_ const ebpf_instruction_t* instructions, size_t instruction_count)
{
    ebpf_result_t return_value;
    char* error_message = NULL;

    if (program->parameters.code_type != EBPF_CODE_EBPF) {
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    program->code_or_vm.vm = ubpf_create();
    if (!program->code_or_vm.vm) {
        return_value = EBPF_NO_MEMORY;
        goto Done;
    }

    // https://github.com/iovisor/ubpf/issues/68
    // BUG - ubpf implements bounds checking to detect interpreted code accessing
    // memory out of bounds. Currently this is flagging valid access checks and
    // failing.
    ubpf_toggle_bounds_check(program->code_or_vm.vm, false);

    ubpf_set_error_print(program->code_or_vm.vm, ebpf_log_function);

    return_value = _ebpf_program_register_helpers(program);
    if (return_value != EBPF_SUCCESS)
        goto Done;

    if (ubpf_load(
            program->code_or_vm.vm,
            instructions,
            (uint32_t)(instruction_count * sizeof(ebpf_instruction_t)),
            &error_message) != 0) {
        ebpf_free(error_message);
        return_value = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

Done:
    if (return_value != EBPF_SUCCESS) {
        ubpf_destroy(program->code_or_vm.vm);
        program->code_or_vm.vm = NULL;
    }

    return return_value;
}

static void
_fuzz_helper(_In_reads_(size) const uint8_t* data, size_t size)
{
    // TODO: Call into a helper the same way the interpreter would.
}

FUZZ_EXPORT int __cdecl LLVMFuzzerInitialize(int*, char***) { return 0; }

FUZZ_EXPORT int __cdecl LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    try {
        _fuzz_helper(data, size);
    } catch (std::runtime_error&) {
    }

    return 0; // Non-zero return values are reserved for future use.
}
