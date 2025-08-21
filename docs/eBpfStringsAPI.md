# eBPF Strings Library API proposal

## Overview

A majority of use cases and examples of eBPF functions are focused on operating on fixed fields in buffers; network
structures with known sizes and offsets, bit-fields, and the like. The programs we can write with the available tooling
are powerful, but fall short of the needs of Application-layer customers like HTTP servers, where string operations are
mandatory to interact with HTTP requests and responses.

This has precedent; in [`ebpf_core_helper_function_prototype_array`](../libs/execution_context/ebpf_general_helpers.c)
there are `bpf_memcmp_s()`, `bpf_memcpy_s()`, `bpf_memmove_s()`, and `bpf_memset()` -- all of which are also derived from
`<string.h>` functions. As has been pointed out, there are also limited examples

## Scenarios

### Finding a token in a header

Assuming an appropriate extension existed to interact with an in-flight HTTP request, a developer wants to search
through the Accept-Encoding header, because some older application can't handle gzip appropriately. (I'm sure this is a
real use case somewhere.) Error handling is elided in this example for brevity.

```C
char accept_encoding[] = "Accept-Encoding";
int ae_len = sizeof(accept_encoding);
char gzip_name[] = "gzip";
int gzip_len = sizeof(gzip_name) - 1; // exclude terminal null
char *header_body = NULL;
int header_length = ebpfHttpLoadHeader(ctx, accept_encoding, ae_len, &header_body);

char *gzip_location = ebpf_strstr(header_body, header_length, gzip_name, gzip_len);
// if gzip isn't first, copy everything before it back to the header, then copy everything after it back to the header.
if (gzip_location > header_body)
{
    ebpfHttpSetHeader(ctx, accept_encoding, ae_len, header_body, (gzip_location - header_body));
}

char *after_header = gzip_location + gzip_len;
int after_size = header_length - ((gzip_location - header_body) + gzip_len);
while (after_size > 1)
{
    // This loop has to check for at least a terminal null, so it requires a length > 1
    if (*after_header == ',' || *after_header == ' ')
    {
        after_size--;
        after_header++;
        continue;
    }
    else
    {
        break;
    }
}

if (after_size > 1)
{
    ebpfHttpAppendHeader(ctx, accept_encoding, ae_len, after_header, after_size);
}
```

## Functions of interest

We should aim to have sufficient coverage of the core C string functions. The functions that are of interest in
particular are listed here; their eBPF counterparts will necessarily need to be somewhat different, especially an
example like `strstr()`.

```C
errno_t strncpy_s(char *restrict dest, size_t dest_size, const char *restrict src, size_t count);
errno_t strncat_s(char *restrict dest, size_t dest_size, const char *restrict src, size_t count);
size_t strnlen_s(const char *str, size_t str_size);
int strncmp(const char *lhs, const char *rhs, size_t count);
char *strchr(const char *str, int ch);
char *strstr(const char *str, const char *substr);
```

Barring a strong requirement, this proposal is limited to 8-bit and UTF-8 strings. Wide strings would follow a similar
pattern, but are not considered necessary here.

While there is an upstream `bpf_strncmp()`, its argument pattern is inconsistent with the C stdlib `strncmp()`, and the
lack of an argument for the second string's length makes it not fit the pattern of our eBPF extension functions. That
appears to be implemented as another type of argument that our runtime doesn't allow for currently. As such, our
implementation will not be compatible with upstream's `bpf_strncmp()` but will instead use `bpf_strcmp()` so as to not
cause an uncomfortable name collision.

## Proposed names & prototypes

```C
errno_t bpf_strcpy_s(char *restrict dest, size_t dest_size, const char *restrict src, size_t count);
errno_t bpf_strcat_s(char *restrict dest, size_t dest_size, const char *restrict src, size_t count);
size_t bpf_strlen_s(const char *str, size_t str_size);
int bpf_strncmp_s(const char *lhs, size_t lhs_size, const char *rhs, size_t rhs_size, size_t count);
char *bpf_strchr_s(const char *str, size_t str_size, char ch);
char *bpf_strstr_s(const char *str, size_t str_size, const char *substr, size_t substr_size);
long bpf_strtol(const char *str, unsigned long str_len, uint64_t flags, long *res); // Note
long bpf_strtoul(const char *str, unsigned long str_len, uint64_t flags, unsigned long *res); // Note
```

Note: This list of proposed functions includes two additional functions that are in upstream eBPF, and which make sense
to include: [bpf_strtoul](https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_strtoul/) and
[bpf_strtol](https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_strtol/); these functions are only supported
on the `CGROUP_SYSCTL` program type, but seem broadly applicable for us. Their return values will be documented in the
header, negative return values have a particular meaning for them.

There are some key differences between the C and BPF versions of these functions, mostly because the C definitions
depend on the sentinel terminal null. Note that a string may be shorter than its buffer in the eBPF functions, but will
be considered terminated at the first null. For example:

```C
char *input = { 'a', 'l', 'p', 'h', 'a', '\0', 'b', 'r', 'a', 'v', 'o', '\0' };
char search = 'b';

char *found = bpf_strchr(input, sizeof input, search);
// found == NULL because the first 'b' is after a null

size_t string_len = bpf_strlen(input, sizeof input);
// string_len == 5 while sizeof input == 12

```
