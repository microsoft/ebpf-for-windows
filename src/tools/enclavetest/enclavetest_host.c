#include <windows.h>
#include <openenclave/host.h>
#include "ebpf_u.h"

oe_result_t create_ebpf_enclave(
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
    result = oe_create_ebpf_enclave(
        enclave_name, OE_ENCLAVE_TYPE_AUTO, enclave_flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        printf(
            "Error %d creating enclave, trying simulation mode...\n", result);
        enclave_flags |= OE_ENCLAVE_FLAG_SIMULATE;
        result = oe_create_ebpf_enclave(
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

void test_verify(const char* filename, const char* sectionname)
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result = create_ebpf_enclave(
#ifdef OE_USE_OPTEE
        "FILL THIS IN",
#else
        "ebpfenclave.elf.signed",
#endif
        &enclave);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "oe_create_enclave(): result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }

    printf("Reading %s section %s...\n", filename, sectionname);

    /* Make calls into the enclave... */
    int retval;
    result = ecall_verify(enclave, &retval, filename, sectionname);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "calling into ecall_DoWorkInEnclave failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }
    if (retval == NO_ERROR) {
        printf("The specified eBPF program passed verification\n");
    } else {
        printf("The specified eBPF program failed verification with error %d\n", retval);
    }

exit:
    /* Clean up the enclave if we created one. */
    if (enclave != NULL)
    {
        oe_terminate_enclave(enclave);
    }
}

/* OCALL implementations of any OCALLs here. */

int getrusage(int who, struct oe_rusage* usage)
{
    FILETIME creation_time, exit_time, kernel_time, user_time;
    if (!GetProcessTimes(GetCurrentProcess(), &creation_time, &exit_time, &kernel_time, &user_time)) {
        return -1;
    }

    // Convert from 100ns intervals to microseconds.
    uint64_t total_us = (((uint64_t)user_time.dwHighDateTime << 32) | (uint64_t)user_time.dwLowDateTime) / 10;

    memset(usage, 0, sizeof(*usage));
    usage->ru_utime.tv_sec = total_us / 1000000L;
    usage->ru_utime.tv_usec = total_us % 1000000L;

    return 0;
}
