# eBPF Strings Library API proposal

## Overview

A majority of use cases and examples of eBPF functions are focused on operating on fixed fields in buffers; network structures with known sizes and offsets, bit-fields, and the like. The programs we can write with the available tooling are powerful, but fall short of the needs of Application-layer customers like HTTP servers, where string operations are mandatory to interact with HTTP requests and responses.

This has precedent; in [`ebpf_core_helper_function_prototype_array[]`](../libs/execution_context/ebpf_general_helpers.c) there are `bpf_memcmp()`, `bpf_memcpy()`, `bpf_memmove()`, and `bpf_memset()` -- all of which are also derived from `<string.h>` functions.

## Scenarios

### Finding a token in a header

Assuming an appropriate extension existed to interact with an in-flight HTTP request, a customer wants to search through the Accept-Encoding header, because some older application can't handle gzip appropriately. (I'm sure this is a real use case somewhere.) Error handling is elided in this example for brevity.

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

We should aim to have sufficient coverage of the core C string functions. The functions that are of interest in particular are listed here; their eBPF counterparts will necessarily need to be somewhat different, especially an example like `strstr()`.

```C
errno_t strncpy_s(char *restrict dest, size_t dest_size, const char *restrict src, size_t src_count);
errno_t strncat_s(char *restrict dest, size_t dest_size, const char *restrict src, size_t src_count);
size_t strnlen_s(const char *str, size_t str_size);
int strncmp(const char *lhs, const char *rhs, size_t count);
char *strchr(const char *str, int ch);
char *strstr(const char *str, const char *substr);
```

This proposal isn't currently considering wide strings, but if there's appetite for them they'd follow the same pattern.

## Proposed names & prototypes

```C
errno_t bpf_strcpy(char *restrict dest, size_t dest_size, const char *restrict src, size_t src_count);
errno_t bpf_strcat(char *restrict dest, size_t dest_size, const char *restrict src, size_t src_count);
size_t bpf_strlen(const char *str, size_t str_size);
int bpf_strcmp(const char *lhs, size_t lhs_size, const char *rhs, size_t rhs_size, size_t count);
char *bpf_strchr(const char *str, size_t str_size, char ch);
char *bpf_strstr(const char *str, size_t str_size, const char *substr, size_t substr_size);
```

There are some key differences between the C and BPF versions of these functions, mostly because the C definitions depend on the sentinel terminal null. Note that a string may be shorter than its buffer in the eBPF functions, but will be considered terminated at the first null. For example:

```C
char *input = { 'a', 'l', 'p', 'h', 'a', '\0', 'b', 'r', 'a', 'v', 'o', '\0' };
char search = 'b';

char *found = bpf_strchr(input, sizeof input, search);
// found == NULL because the first 'b' is after a null

size_t string_len = bpf_strlen(input, sizeof input);
// string_len == 5 while sizeof input == 12

```
