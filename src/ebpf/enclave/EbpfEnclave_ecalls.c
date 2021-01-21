#include "EbpfEnclave_t.h"
#include <ubpf.h>

#define HEAP_SIZE_BYTES (2 * 1024 * 1024) /* 2 MB */
#define STACK_SIZE_BYTES (24 * 1024)      /* 24 KB */

#define SGX_PAGE_SIZE (4 * 1024) /* 4 KB */

#define TA_UUID /* 729242ad-3250-47d5-adda-651dac658f65 */ {0x729242ad,0x3250,0x47d5,{0xad,0xda,0x65,0x1d,0xac,0x65,0x8f,0x65}}

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,               /* UUID */
    HEAP_SIZE_BYTES,       /* HEAP_SIZE */
    STACK_SIZE_BYTES,      /* STACK_SIZE */
    TA_FLAG_MULTI_SESSION, /* FLAGS */
    "1.0.0",               /* VERSION */
    "EbpfEnclave TA");   /* DESCRIPTION */

OE_SET_ENCLAVE_SGX(
    1, /* ProductID */
    1, /* SecurityVersion */
#ifdef _DEBUG
    1, /* Debug */
#else
    0, /* Debug */
#endif
    HEAP_SIZE_BYTES / SGX_PAGE_SIZE,  /* NumHeapPages */
    STACK_SIZE_BYTES / SGX_PAGE_SIZE, /* NumStackPages */
    1);                               /* NumTCS */

// This is for the demo only. Contract will change once the secure channel is 
// created. Call back into the host to resolve fd -> kernel address
static uint64_t map_resolver(void* context, uint64_t fd)
{
    size_t retval;
    oe_result_t result = resolve_handle(&retval, fd);
    if (result != OE_OK)
    {
        return -1;
    }
    return retval;
}

size_t verify_and_jit(unsigned char* byte_code,
    size_t byte_code_size,
    unsigned char* machine_code,
    size_t machine_code_size)
{
    int result = 0;
    struct ubpf_vm* vm = NULL;
    char* errmsg = NULL;
    vm = ubpf_create();
    if (vm == NULL)
    {
        result = -1;
        goto cleanup;
    }

    result = ubpf_register_map_resolver(vm, NULL, map_resolver);
    if (result != 0)
    {
        goto cleanup;
    }

    result = ubpf_load(vm, byte_code, byte_code_size, &errmsg);
    if (result != 0)
    {
        goto cleanup;
    }

    result = ubpf_translate(vm, machine_code, machine_code_size, &errmsg);
    if (result != 0)
    {
        goto cleanup;
    }


cleanup:
    if (vm != NULL)
    {
        ubpf_destroy(vm);
    }
    return result;
}


