# Proposal: ELF File Hash Embedding in PE Images

## Summary

This proposal introduces functionality to embed the SHA-256 hash of the original ELF file into the generated PE (Portable Executable) image during the eBPF compilation process. This enhancement provides traceability and provenance verification, allowing users to verify that a compiled PE image was generated from a specific ELF input file.

## Background

When eBPF programs are compiled from ELF format to native Windows executables (PE format) using the bpf2c tool, there is currently no built-in mechanism to verify the relationship between the original ELF file and the resulting PE image. This lack of traceability can be problematic for:

- Debugging and troubleshooting
- Security auditing and compliance
- Version management and deployment verification
- Supply chain integrity verification

## Proposed Changes

### 1. Hash Embedding in PE Images

The bpf2c code generator will be modified to:

- Calculate the SHA-256 hash of the input ELF file during compilation
- Embed this hash as binary data in a dedicated "hash" section of the generated PE image
- Use compiler pragmas to ensure the hash data is included in the final binary even if not directly referenced

**Technical Implementation:**
```cpp
#pragma const_seg(push, "hash")
// bpf2c emits the full 32-byte SHA-256 array; values below illustrate the layout.
const uint8_t _elf_hash[] = {
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
    0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
    0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
    0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
};
#pragma const_seg(pop)
#pragma comment(linker, "/INCLUDE:_elf_hash")
```

### 2. New API for Hash Extraction

A new API function `ebpf_api_read_file_section()` will be added to extract data from named sections in PE and ELF files. In the context of this proposal, the hash is embedded into the generated PE image, and this API is used to retrieve that embedded hash:

```cpp
_Must_inspect_result_ ebpf_result_t
ebpf_api_read_file_section(
    _In_z_ const char* file_path,
    _In_z_ const char* section_name,
    _Out_writes_bytes_opt_(*data_size) uint8_t* data,
    _Inout_ size_t* data_size) EBPF_NO_EXCEPT;
```

This API follows a two-call pattern similar to many Windows APIs:
- Supports both PE and ELF file formats
- When `data` is `NULL`, `data_size` must be a valid pointer; on return, `*data_size` contains the required buffer size in bytes for the named section, and no data is written
- When `data` is non-`NULL`, the caller must set `*data_size` to the size in bytes of the `data` buffer on input; on successful return, `*data_size` contains the number of bytes written
- If the provided buffer is too small, the function fails with an appropriate error code, sets `*data_size` to the required size, and does not modify the buffer
- Provides appropriate error codes for missing files or sections
- The expected section name for hash retrieval is "hash"

### 3. NetSh Command Line Interface

A new `netsh ebpf show hash` command will be added to extract and display the embedded hash from PE images:

**Command Syntax:**
```
netsh ebpf show hash [filename=]<path> [hashonly]
```

**Parameters:**
- `filename`: Required path to the PE file
- `hashonly`: Optional keyword flag. Specify this by adding the literal word `hashonly` (with no `=` and no value) to the command line to output only the embedded ELF hash value as a hexadecimal string. The format of this string matches the `Hash` field from PowerShell `Get-FileHash`, but the value itself is the hash of the original ELF file (for example, `program.o`), not the PE file (for example, `program.sys`). To verify integrity, compare this value against `Get-FileHash` of the original ELF file

**Example Output:**

Without `hashonly` flag:
```
Hash for example.sys:
Size: 32 bytes
Data: a1 b2 c3 d4 e5 f6 07 18
      29 3a 4b 5c 6d 7e 8f 90
      01 12 23 34 45 56 67 78
      89 9a ab bc cd de ef f0
```

With `hashonly` flag:
```
A1B2C3D4E5F60718293A4B5C6D7E8F90011223344556677889AABBCCDDEEFF0
```

Note: The `netsh` output without `hashonly` groups bytes in lowercase hex with spaces for readability; `hashonly` emits an uppercase, contiguous hex string matching the `Hash` value from `Get-FileHash`.

## Use Cases

### 1. Integrity Verification
Users can verify that a deployed PE file corresponds to a specific ELF source:
```powershell
# Get hash from compiled PE
netsh ebpf show hash filename=program.sys hashonly

# Compare with original ELF file hash
Get-FileHash program.o -Algorithm SHA256
```

### 2. Debugging and Troubleshooting
When investigating issues with deployed eBPF programs, developers can verify they are working with the expected version:
```powershell
netsh ebpf show hash filename=C:\Windows\System32\drivers\myprogram.sys
```

### 3. Automated Testing and CI/CD
Build systems can automatically verify that compilation produces consistent results and that the correct versions are being deployed.

### 4. Security Auditing
Security teams can trace deployed eBPF drivers back to their original source files for compliance and audit purposes.

## Testing Strategy

The implementation will include comprehensive test coverage:

1. **Unit Tests**: API function testing with various file formats and edge cases
2. **Integration Tests**: End-to-end testing of the compilation and hash extraction process
3. **NetSh Command Tests**: Validation of command-line interface and output formatting
4. **Error Condition Tests**: Verification of proper error handling for all failure modes

## Security Considerations

- Hash verification is cryptographically strong (SHA-256)
- The hash is embedded as read-only data in the PE at compile time; integrity verification succeeds only if this embedded hash matches the original ELF, although an attacker with sufficient access could still modify the PE file (including the embedded hash) on disk
- Hash extraction API validates file format before processing
- No sensitive information is exposed through the hash mechanism

## Performance Impact

- **Compilation**: Minimal overhead during bpf2c compilation (one-time hash calculation)
- **Runtime**: No performance impact on eBPF program execution
- **Hash Extraction**: Efficient section-based lookup with minimal file I/O

## Future Enhancements

This foundation enables several potential future improvements:

1. **Extended Metadata**: Embed compilation timestamp, compiler version, or source file path
2. **Hash Verification**: Automatic hash verification during program loading
3. **Digital Signatures**: Integration with code signing infrastructure
4. **Audit Logging**: Automatic logging of hash verification results

## Conclusion

The ELF file hash embedding feature will provide essential traceability and integrity verification capabilities for the eBPF for Windows ecosystem. It will enable secure, auditable deployment of eBPF programs while maintaining backward compatibility and providing a user-friendly command-line interface for hash extraction and verification.

Once implemented, this feature is intended to be robust, well-tested, and suitable for production use, providing immediate value for debugging, security auditing, and compliance requirements.