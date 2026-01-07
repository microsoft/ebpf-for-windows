# Proposal: ELF File Hash Embedding in PE Images

## Summary

This proposal introduces functionality to embed the SHA-256 hash of the original ELF file into the generated PE (Portable Executable) image during the eBPF compilation process. This enhancement provides traceability and integrity verification capabilities, allowing users to verify that a compiled PE image corresponds to a specific ELF source file.

## Background

When eBPF programs are compiled from ELF format to native Windows executables (PE format) using the bpf2c tool, there is currently no built-in mechanism to verify the relationship between the original ELF file and the resulting PE image. This lack of traceability can be problematic for:

- Debugging and troubleshooting
- Security auditing and compliance
- Version management and deployment verification
- Supply chain integrity verification

## Proposed Changes

### 1. Hash Embedding in PE Images

The bpf2c code generator has been modified to:

- Calculate the SHA-256 hash of the input ELF file during compilation
- Embed this hash as binary data in a dedicated "hash" section of the generated PE image
- Use compiler pragmas to ensure the hash data is included in the final binary even if not directly referenced

**Technical Implementation:**
```cpp
#pragma const_seg(push, "hash")
const uint8_t _elf_hash[] = { /* hash bytes */ };
#pragma const_seg(pop)
#pragma comment(linker, "/INCLUDE:_elf_hash")
```

### 2. New API for Hash Extraction

A new API function `ebpf_api_get_data_section()` has been added to extract data from named sections in PE files. ELF files may also contain a hash section if they were compiled with hash embedding enabled:

```cpp
_Must_inspect_result_ ebpf_result_t
ebpf_api_get_data_section(
    _In_z_ const char* file_path,
    _In_z_ const char* section_name,
    _Out_writes_bytes_opt_(*data_size) uint8_t* data,
    _Inout_ size_t* data_size) EBPF_NO_EXCEPT;
```

This API:
- Supports both PE and ELF file formats
- Returns section size when called with NULL data pointer
- Provides appropriate error codes for missing files or sections

### 3. NetSh Command Line Interface

A new `netsh ebpf show hash` command has been implemented to extract and display the embedded hash from PE images:

**Command Syntax:**
```
netsh ebpf show hash [filename=]<path> [hashonly]
```

**Parameters:**
- `filename`: Required path to the PE file
- `hashonly`: Optional flag to output only the hash value (compatible with PowerShell Get-FileHash format)

**Example Output:**

Without `hashonly` flag:
```
Hash for example.sys:
Size: 32 bytes
Data: a1b2c3d4e5f6789a bcdef012345678ab cdef0123456789ab cdef0123456789ab
```

With `hashonly` flag:
```
A1B2C3D4E5F6789ABCDEF012345678ABCDEF0123456789ABCDEF0123456789AB
```

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

The implementation includes comprehensive test coverage:

1. **Unit Tests**: API function testing with various file formats and edge cases
2. **Integration Tests**: End-to-end testing of the compilation and hash extraction process
3. **NetSh Command Tests**: Validation of command-line interface and output formatting
4. **Error Condition Tests**: Verification of proper error handling for all failure modes

## Security Considerations

- Hash verification is cryptographically strong (SHA-256)
- The embedded hash is read-only and cannot be modified without rebuilding
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

The ELF file hash embedding feature provides essential traceability and integrity verification capabilities for the eBPF for Windows ecosystem. It enables secure, auditable deployment of eBPF programs while maintaining backward compatibility and providing a user-friendly command-line interface for hash extraction and verification.

The implementation is robust, well-tested, and ready for production use, providing immediate value for debugging, security auditing, and compliance requirements.