#include <stdio.h>
#include "Verifier.h"
#include "ebpf_t.h"

#define HEAP_SIZE_BYTES (2 * 1024 * 1024) /* 2 MB */
#define STACK_SIZE_BYTES (240 * 1024)     /* 240 KB */

#define SGX_PAGE_SIZE (4 * 1024) /* 4 KB */

#define TA_UUID /* ce14558f-c740-417e-ae19-bc361fa9beeb */ {0xce14558f,0xc740,0x417e,{0xae,0x19,0xbc,0x36,0x1f,0xa9,0xbe,0xeb}}

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,                 /* UUID */
    HEAP_SIZE_BYTES,         /* HEAP_SIZE */
    STACK_SIZE_BYTES,        /* STACK_SIZE */
    TA_FLAG_MULTI_SESSION,   /* FLAGS */
    "1.0.0",                 /* VERSION */
    "EbpfVerifier Enclave"); /* DESCRIPTION */

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

int ecall_verify(const char* filename, const char* sectionname)
{
    return Verify(filename, sectionname);
}

/* Add implementations of any other ECALLs here. */
