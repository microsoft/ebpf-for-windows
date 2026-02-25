# pdb2btf - PDB to BTF Converter

## Overview

`pdb2btf` is a tool that converts MSVC Program Database (PDB) files to BTF (BPF Type Format). It enables eBPF extensions to use BTF-based helper identification instead of static numeric IDs, reducing coordination requirements across multiple extensions including third-party ones.

## Usage

```cmd
pdb2btf --pdb <path-to-pdb> --roots <symbol-names> --out <output-btf-file>
```

### Options

- `--pdb <path>`: Path to the input PDB file (required)
- `--roots <names>`: Comma-separated list of root symbol names to include (required)
- `--out <path>`: Path to output BTF file (required)
- `--help`, `-h`: Show help message

### Examples

Export a single type:
```cmd
pdb2btf --pdb mydriver.pdb --roots my_helper_function --out mydriver.btf
```

Export multiple types:
```cmd
pdb2btf --pdb netebpfext.pdb --roots bind_operation_t,bind_context_t --out netebpfext.btf
```

## How It Works

1. **Root Selection**: The tool starts from user-specified root symbols (types, functions, or variables)
2. **Type Discovery**: Recursively discovers all types referenced by the root symbols
3. **Type Conversion**: Converts PDB type information to BTF format:
   - Base types (integers, booleans, characters)
   - Pointers
   - Arrays
   - Structs and unions (including bitfields)
   - Enumerations
   - Typedefs
   - Function prototypes
4. **BTF Generation**: Emits a deterministic BTF blob that can be consumed by eBPF tools

## Supported Type Mappings

| PDB Type | BTF Type | Notes |
|----------|----------|-------|
| Base types (int, uint, char, etc.) | `btf_kind_int` | Includes sign, size, and bitfield information |
| Pointers | `btf_kind_ptr` | Preserves pointed-to type |
| Arrays | `btf_kind_array` | Includes element type and count |
| Structs | `btf_kind_struct` | Includes member names, types, and offsets (including bitfields) |
| Unions | `btf_kind_union` | Similar to structs |
| Enums | `btf_kind_enum` | Includes member names and values |
| Typedefs | `btf_kind_typedef` | Preserves type aliases |
| Functions | `btf_kind_function` | Includes function name and linkage |
| Function types | `btf_kind_function_prototype` | Includes return type and parameters |

## Use Cases

### Helper Resolution by BTF ID

Instead of coordinating static helper IDs across extensions:

1. Extension driver builds with debug information
2. Run `pdb2btf` to generate BTF from the extension's PDB
3. Extension publishes BTF describing its helpers and required types
4. eBPF programs reference helpers by BTF type information
5. Loader resolves helper calls without requiring coordinated numeric IDs

## Implementation Details

### Root Selection Strategy

The tool uses an **allowlist-based** approach:
- User explicitly specifies which symbols to include via `--roots`
- All types reachable from those roots are automatically included
- This ensures deterministic output and excludes implementation details

### Deterministic Output

BTF output is deterministic for the same input:
- Types are emitted in a consistent order
- String table is stable
- No timestamps, paths, or build-specific metadata

### PDB Reading

The tool uses Microsoft's Debug Interface Access (DIA) SDK to read PDB files:
- COM-based interface for querying type information
- Supports all MSVC-generated PDB formats
- Handles complex types including templates and nested structures

## Building

The tool is built as part of the eBPF for Windows solution:

```cmd
msbuild /m /p:Configuration=Debug /p:Platform=x64 ebpf-for-windows.sln
```

The built executable will be in `x64\Debug\pdb2btf.exe`.

## Requirements

- Windows (for DIA SDK support)
- MSVC toolchain (for PDB generation)
- msdia140.dll must be registered (installed with Visual Studio)

## Future Enhancements

Potential future additions (not in MVP):

- `--out-elf <path>`: Output BTF embedded in a minimal ELF file
- `--out-json <path>`: Output human-readable JSON for debugging
- `--pe <path>`: Optional PE image input for additional metadata
- Export-based root selection (automatically find exported symbols)
- Prefix-based filtering (e.g., include all symbols starting with `ebpf_`)
- `.BTF.ext` section generation for line information

## Related Documentation

- [eBPF Extensions Documentation](../../docs/eBpfExtensions.md)
- [BTF Specification](https://www.kernel.org/doc/html/latest/bpf/btf.html)
- [DIA SDK Documentation](https://docs.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/debug-interface-access-sdk)
