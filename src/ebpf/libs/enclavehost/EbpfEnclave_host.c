#include "EbpfEnclave_u.h"

static oe_result_t create_EbpfEnclave_enclave(
    const char* enclave_name,
    oe_enclave_t** out_enclave)
{
    oe_enclave_t* enclave = NULL;
    uint32_t enclave_flags = 0;
    oe_result_t result;

    *out_enclave = NULL;

    // Create the enclave
#ifdef _DEBUG
    enclave_flags |= OE_ENCLAVE_FLAG_DEBUG;
#endif
    result = oe_create_EbpfEnclave_enclave(
        enclave_name, OE_ENCLAVE_TYPE_AUTO, enclave_flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        enclave_flags |= OE_ENCLAVE_FLAG_SIMULATE;
        result = oe_create_EbpfEnclave_enclave(
            enclave_name,
            OE_ENCLAVE_TYPE_AUTO,
            enclave_flags,
            NULL,
            0,
            &enclave);
    }
    if (result != OE_OK)
    {
        return result;
    }

    *out_enclave = enclave;
    return OE_OK;
}

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
    size_t* machine_code_size)
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result = create_EbpfEnclave_enclave(
#ifdef OE_USE_OPTEE
        "FILL THIS IN",
#else
        "EbpfEnclave.elf.signed",
#endif
        & enclave);
    if (result != OE_OK)
    {
        goto exit;
    }

    size_t retval;
    result = ecall_verify_and_jit(enclave, &retval, byte_code, byte_code_size, machine_code, *machine_code_size, machine_code_size);
    if (result != OE_OK)
    {
        goto exit;
    }

exit:
    /* Clean up the enclave if we created one. */
    if (enclave != NULL)
    {
        oe_terminate_enclave(enclave);
    }
    if (result == OE_OK)
    {
        return 0;
    }
    else
    {
        return 1;
    }

}

/* Add implementations of any OCALLs here. */


// This is for the demo only. Contract will change once the secure channel is 
// created. resolve_helper accepts a eBPF function call # and returns the 
// kernel address of the function.
//
// helper_id - The # assigned to the eBPF helper function.
// Returns - The kernel address of that helper function.
uint64_t resolve_helper(uint64_t helper_id)
{
    // TODO:
    // Make IOCTL to ebpfcore.sys to lookup helper function.
    return -1;
}

// This is for the demo only. Contract will change once the secure channel is 
// created. resolve_handle accepts a handle and returns the 
// kernel address of the object associated with it
//
// handle - The handle assigned to the map or other kernel object.
// Returns - The kernel address of that object.
uint64_t resolve_handle(uint64_t handle)
{
    // TODO:
    // Make IOCTL to ebpfcore.sys to lookup helper function.
    return -1;
}
