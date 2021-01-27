#pragma once
// This is for the demo only. Contract will change once the secure channel is 
// created. ebpf_verify_jit accepts a block of eBPF byte code, invokes the 
// jitter and returns a block of machine code. 
//
//  byte_code/byte_code_size [in] 
//    Pointer to a block of memory containing the eBPF byte code.
//  machine_code [out]
//      Pointer to a block of memory that contains the machine code on success.
//  machine_code_size [in/out]
//      Contains maximum size of machine_code on entry and valid size on return.
// Return:
//   0 on success.
//   1 on failure.
int ebpf_verify_jit(
    unsigned char* byte_code,
    size_t byte_code_size,
    unsigned char* machine_code,
    size_t* machine_code_size);
