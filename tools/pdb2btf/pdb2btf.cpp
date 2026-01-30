// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "libbtf/btf.h"
#include "libbtf/btf_type_data.h"
#include "libbtf/btf_write.h"

#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <atlbase.h>
#include <comdef.h>
#include <dia2.h>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

#pragma comment(lib, "diaguids.lib")

// Helper class for managing COM lifetime
class com_initializer
{
  public:
    com_initializer()
    {
        HRESULT hr = CoInitialize(nullptr);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
            throw std::runtime_error("Failed to initialize COM");
        }
        _initialized = (hr != RPC_E_CHANGED_MODE);
    }
    ~com_initializer()
    {
        if (_initialized) {
            CoUninitialize();
        }
    }

    // Prevent copying/moving to avoid double-uninitialization
    com_initializer(const com_initializer&) = delete;
    com_initializer&
    operator=(const com_initializer&) = delete;
    com_initializer(com_initializer&&) = delete;
    com_initializer&
    operator=(com_initializer&&) = delete;

  private:
    bool _initialized = false;
};

// Command-line options
struct options
{
    std::string pdb_path;
    std::string output_path;
    std::vector<std::string> root_names;
};

// Type converter class
class pdb_to_btf_converter
{
  public:
    pdb_to_btf_converter(IDiaSession* session) : _session(session) {}

    // Safe size conversion from ULONGLONG to uint32_t with overflow check
    // BTF size_in_bytes fields are uint32_t; types > 4GB are not supported
    static uint32_t
    safe_size_cast(ULONGLONG size)
    {
        if (size > UINT32_MAX) {
            std::cerr << "Warning: type size " << size << " exceeds uint32_t max, truncating" << std::endl;
            return UINT32_MAX;
        }
        return static_cast<uint32_t>(size);
    }

    // Main conversion entry point
    bool
    convert(const std::vector<std::string>& root_names, const std::string& output_path)
    {
        try {
            // Get global scope
            CComPtr<IDiaSymbol> global_scope;
            if (FAILED(_session->get_globalScope(&global_scope))) {
                std::cerr << "Failed to get global scope" << std::endl;
                return false;
            }

            // Find and process root symbols
            for (const auto& root_name : root_names) {
                if (!process_root_symbol(global_scope, root_name)) {
                    std::cerr << "Warning: could not find root symbol: " << root_name << std::endl;
                }
            }

            // Serialize BTF data
            auto btf_bytes = _btf_data.to_bytes();

            // Write to file
            std::ofstream out(output_path, std::ios::binary);
            if (!out) {
                std::cerr << "Failed to open output file: " << output_path << std::endl;
                return false;
            }

            out.write(reinterpret_cast<const char*>(btf_bytes.data()), btf_bytes.size());

            if (!out.good()) {
                std::cerr << "Failed to write to output file: " << output_path << std::endl;
                return false;
            }

            std::cout << "Successfully wrote " << btf_bytes.size() << " bytes to " << output_path << std::endl;
            return true;

        } catch (const std::exception& e) {
            std::cerr << "Conversion error: " << e.what() << std::endl;
            return false;
        }
    }

  private:
    bool
    process_root_symbol(IDiaSymbol* global_scope, const std::string& name)
    {
        CComPtr<IDiaEnumSymbols> enum_symbols;
        _bstr_t bstr_name(name.c_str());

        // Search for the symbol
        if (FAILED(global_scope->findChildren(SymTagNull, bstr_name, nsCaseSensitive, &enum_symbols))) {
            return false;
        }

        LONG count = 0;
        if (FAILED(enum_symbols->get_Count(&count)) || count == 0) {
            return false;
        }

        // Process first matching symbol
        CComPtr<IDiaSymbol> symbol;
        ULONG fetched = 0;
        if (FAILED(enum_symbols->Next(1, &symbol, &fetched)) || fetched == 0) {
            return false;
        }

        // Convert symbol to BTF
        convert_symbol(symbol);
        return true;
    }

    libbtf::btf_type_id
    convert_symbol(IDiaSymbol* symbol)
    {
        if (!symbol) {
            return 0; // void type
        }

        // Check cache
        DWORD symbol_id = 0;
        symbol->get_symIndexId(&symbol_id);

        auto it = _symbol_cache.find(symbol_id);
        if (it != _symbol_cache.end()) {
            return it->second;
        }

        // Get symbol tag
        DWORD tag = 0;
        if (FAILED(symbol->get_symTag(&tag))) {
            return 0;
        }

        libbtf::btf_type_id btf_id = 0;

        switch (tag) {
        case SymTagBaseType:
            btf_id = convert_base_type(symbol);
            break;
        case SymTagPointerType:
            btf_id = convert_pointer_type(symbol);
            break;
        case SymTagArrayType:
            btf_id = convert_array_type(symbol);
            break;
        case SymTagUDT:
            btf_id = convert_udt(symbol);
            break;
        case SymTagEnum:
            btf_id = convert_enum(symbol);
            break;
        case SymTagTypedef:
            btf_id = convert_typedef(symbol);
            break;
        case SymTagFunctionType:
            btf_id = convert_function_type(symbol);
            break;
        case SymTagFunction:
            btf_id = convert_function(symbol);
            break;
        default:
            // Unsupported or not needed type
            break;
        }

        if (btf_id != 0) {
            _symbol_cache[symbol_id] = btf_id;
        }

        return btf_id;
    }

    libbtf::btf_type_id
    convert_base_type(IDiaSymbol* symbol)
    {
        ULONGLONG size = 0;
        symbol->get_length(&size);

        DWORD base_type = 0;
        symbol->get_baseType(&base_type);

        libbtf::btf_kind_int int_type{};
        int_type.size_in_bytes = safe_size_cast(size);
        // BTF field_width_in_bits is uint8_t; cap at 255 for types > 31 bytes
        int_type.field_width_in_bits = static_cast<uint8_t>(std::min(size * 8, static_cast<ULONGLONG>(255)));
        int_type.offset_from_start_in_bits = 0;

        switch (base_type) {
        case btNoType:
            return 0; // void
        case btVoid:
            return 0;
        case btChar:
            int_type.name = "char";
            int_type.is_char = true;
            int_type.is_signed = true;
            break;
        case btWChar:
            int_type.name = "wchar_t";
            int_type.is_signed = false;
            break;
        case btInt:
        case btLong:
            int_type.is_signed = true;
            int_type.name = "int" + std::to_string(size * 8) + "_t";
            break;
        case btUInt:
        case btULong:
            int_type.is_signed = false;
            int_type.name = "uint" + std::to_string(size * 8) + "_t";
            break;
        case btFloat:
            // For MVP, treat as integer
            int_type.name = "float" + std::to_string(size * 8);
            break;
        case btBool:
            int_type.name = "bool";
            int_type.is_bool = true;
            int_type.is_signed = false;
            break;
        default:
            int_type.name = "unknown" + std::to_string(size * 8);
            break;
        }

        return _btf_data.append(int_type);
    }

    libbtf::btf_type_id
    convert_pointer_type(IDiaSymbol* symbol)
    {
        CComPtr<IDiaSymbol> pointee;
        if (FAILED(symbol->get_type(&pointee))) {
            return 0;
        }

        libbtf::btf_kind_ptr ptr_type{};
        ptr_type.type = convert_symbol(pointee);

        return _btf_data.append(ptr_type);
    }

    libbtf::btf_type_id
    convert_array_type(IDiaSymbol* symbol)
    {
        CComPtr<IDiaSymbol> element_type_symbol;
        if (FAILED(symbol->get_type(&element_type_symbol))) {
            return 0;
        }

        ULONGLONG size = 0;
        symbol->get_length(&size);

        ULONGLONG element_size = 0;
        element_type_symbol->get_length(&element_size);

        uint32_t count = (element_size > 0) ? safe_size_cast(size / element_size) : 0;

        libbtf::btf_kind_array array_type{};
        array_type.element_type = convert_symbol(element_type_symbol);
        array_type.index_type = get_or_create_int_type(4, false); // uint32
        array_type.count_of_elements = count;

        return _btf_data.append(array_type);
    }

    libbtf::btf_type_id
    convert_udt(IDiaSymbol* symbol)
    {
        _bstr_t name_bstr;
        symbol->get_name(name_bstr.GetAddress());
        std::string name = static_cast<const char*>(name_bstr);

        DWORD udt_kind = 0;
        symbol->get_udtKind(&udt_kind);

        ULONGLONG size = 0;
        symbol->get_length(&size);

        if (udt_kind == UdtStruct || udt_kind == UdtClass) {
            return convert_struct(symbol, name, size);
        } else if (udt_kind == UdtUnion) {
            return convert_union(symbol, name, size);
        }

        return 0;
    }

    libbtf::btf_type_id
    convert_struct(IDiaSymbol* symbol, const std::string& name, ULONGLONG size)
    {
        libbtf::btf_kind_struct struct_type{};
        if (!name.empty()) {
            struct_type.name = name;
        }
        struct_type.size_in_bytes = safe_size_cast(size);

        // Enumerate members
        CComPtr<IDiaEnumSymbols> enum_children;
        if (SUCCEEDED(symbol->findChildren(SymTagData, nullptr, nsNone, &enum_children))) {
            CComPtr<IDiaSymbol> child;
            ULONG fetched = 0;

            while (SUCCEEDED(enum_children->Next(1, &child, &fetched)) && fetched == 1) {
                DWORD location_type = 0;
                if (SUCCEEDED(child->get_locationType(&location_type)) && location_type == LocIsThisRel) {
                    libbtf::btf_kind_struct_member member{};

                    _bstr_t member_name;
                    if (SUCCEEDED(child->get_name(member_name.GetAddress()))) {
                        member.name = static_cast<const char*>(member_name);
                    }

                    CComPtr<IDiaSymbol> member_type;
                    if (SUCCEEDED(child->get_type(&member_type))) {
                        member.type = convert_symbol(member_type);
                    }

                    LONG offset = 0;
                    if (SUCCEEDED(child->get_offset(&offset))) {
                        member.offset_from_start_in_bits = offset * 8;
                    }

                    // Handle bitfields - BTF encodes bitfield size in upper 8 bits of offset
                    DWORD bit_position = 0;
                    if (SUCCEEDED(child->get_bitPosition(&bit_position))) {
                        member.offset_from_start_in_bits += static_cast<uint32_t>(bit_position);

                        // Get bitfield size and encode in upper 8 bits per BTF specification
                        ULONGLONG bitfield_size = 0;
                        if (SUCCEEDED(child->get_length(&bitfield_size)) && bitfield_size > 0) {
                            member.offset_from_start_in_bits |= (static_cast<uint32_t>(bitfield_size) & 0xFF) << 24;
                        }
                    }

                    struct_type.members.push_back(member);
                }

                child.Release();
            }
        }

        return _btf_data.append(struct_type);
    }

    libbtf::btf_type_id
    convert_union(IDiaSymbol* symbol, const std::string& name, ULONGLONG size)
    {
        libbtf::btf_kind_union union_type{};
        if (!name.empty()) {
            union_type.name = name;
        }
        union_type.size_in_bytes = safe_size_cast(size);

        // Enumerate members
        CComPtr<IDiaEnumSymbols> enum_children;
        if (SUCCEEDED(symbol->findChildren(SymTagData, nullptr, nsNone, &enum_children))) {
            CComPtr<IDiaSymbol> child;
            ULONG fetched = 0;

            while (SUCCEEDED(enum_children->Next(1, &child, &fetched)) && fetched == 1) {
                DWORD location_type = 0;
                if (SUCCEEDED(child->get_locationType(&location_type)) && location_type == LocIsThisRel) {
                    libbtf::btf_kind_union_member member{};

                    _bstr_t member_name;
                    if (SUCCEEDED(child->get_name(member_name.GetAddress()))) {
                        member.name = static_cast<const char*>(member_name);
                    }

                    CComPtr<IDiaSymbol> member_type;
                    if (SUCCEEDED(child->get_type(&member_type))) {
                        member.type = convert_symbol(member_type);
                    }

                    member.offset_from_start_in_bits = 0; // Union members all start at offset 0

                    union_type.members.push_back(member);
                }

                child.Release();
            }
        }

        return _btf_data.append(union_type);
    }

    libbtf::btf_type_id
    convert_enum(IDiaSymbol* symbol)
    {
        _bstr_t name_bstr;
        symbol->get_name(name_bstr.GetAddress());
        std::string name = static_cast<const char*>(name_bstr);

        ULONGLONG size = 0;
        symbol->get_length(&size);

        libbtf::btf_kind_enum enum_type{};
        if (!name.empty()) {
            enum_type.name = name;
        }
        enum_type.size_in_bytes = safe_size_cast(size);
        enum_type.is_signed = false; // Will be updated if negative values are found

        // Enumerate values
        CComPtr<IDiaEnumSymbols> enum_children;
        if (SUCCEEDED(symbol->findChildren(SymTagNull, nullptr, nsNone, &enum_children))) {
            CComPtr<IDiaSymbol> child;
            ULONG fetched = 0;

            while (SUCCEEDED(enum_children->Next(1, &child, &fetched)) && fetched == 1) {
                DWORD child_tag = 0;
                if (SUCCEEDED(child->get_symTag(&child_tag)) && child_tag == SymTagData) {
                    libbtf::btf_kind_enum_member member{};

                    _bstr_t member_name;
                    if (SUCCEEDED(child->get_name(member_name.GetAddress()))) {
                        member.name = static_cast<const char*>(member_name);
                    }

                    VARIANT value_variant;
                    VariantInit(&value_variant);
                    if (SUCCEEDED(child->get_value(&value_variant))) {
                        int32_t signed_value = 0;
                        bool is_signed_type = false;
                        switch (value_variant.vt) {
                        case VT_I1:
                            signed_value = value_variant.cVal;
                            is_signed_type = true;
                            break;
                        case VT_I2:
                            signed_value = value_variant.iVal;
                            is_signed_type = true;
                            break;
                        case VT_I4:
                        case VT_INT:
                            signed_value = value_variant.lVal;
                            is_signed_type = true;
                            break;
                        case VT_UI1:
                            member.value = value_variant.bVal;
                            break;
                        case VT_UI2:
                            member.value = value_variant.uiVal;
                            break;
                        case VT_UI4:
                        case VT_UINT:
                            member.value = value_variant.ulVal;
                            break;
                        case VT_I8:
                            signed_value = static_cast<int32_t>(value_variant.llVal);
                            is_signed_type = true;
                            break;
                        case VT_UI8:
                            member.value = static_cast<uint32_t>(value_variant.ullVal);
                            break;
                        }

                        // Check for negative values in signed types
                        if (is_signed_type) {
                            if (signed_value < 0) {
                                enum_type.is_signed = true;
                            }
                            member.value = static_cast<uint32_t>(signed_value);
                        }

                        VariantClear(&value_variant);
                    }

                    enum_type.members.push_back(member);
                }

                child.Release();
            }
        }

        return _btf_data.append(enum_type);
    }

    libbtf::btf_type_id
    convert_typedef(IDiaSymbol* symbol)
    {
        _bstr_t name_bstr;
        symbol->get_name(name_bstr.GetAddress());
        std::string name = static_cast<const char*>(name_bstr);

        CComPtr<IDiaSymbol> underlying_type;
        if (FAILED(symbol->get_type(&underlying_type))) {
            return 0;
        }

        libbtf::btf_kind_typedef typedef_type{};
        typedef_type.name = name;
        typedef_type.type = convert_symbol(underlying_type);

        return _btf_data.append(typedef_type);
    }

    libbtf::btf_type_id
    convert_function_type(IDiaSymbol* symbol)
    {
        libbtf::btf_kind_function_prototype proto{};

        // Get return type
        CComPtr<IDiaSymbol> return_type;
        if (SUCCEEDED(symbol->get_type(&return_type))) {
            proto.return_type = convert_symbol(return_type);
        }

        // Get parameters
        CComPtr<IDiaEnumSymbols> enum_children;
        if (SUCCEEDED(symbol->findChildren(SymTagFunctionArgType, nullptr, nsNone, &enum_children))) {
            CComPtr<IDiaSymbol> child;
            ULONG fetched = 0;

            while (SUCCEEDED(enum_children->Next(1, &child, &fetched)) && fetched == 1) {
                libbtf::btf_kind_function_parameter param{};

                _bstr_t param_name;
                if (SUCCEEDED(child->get_name(param_name.GetAddress()))) {
                    param.name = static_cast<const char*>(param_name);
                }

                CComPtr<IDiaSymbol> param_type;
                if (SUCCEEDED(child->get_type(&param_type))) {
                    param.type = convert_symbol(param_type);
                }

                proto.parameters.push_back(param);
                child.Release();
            }
        }

        return _btf_data.append(proto);
    }

    libbtf::btf_type_id
    convert_function(IDiaSymbol* symbol)
    {
        _bstr_t name_bstr;
        symbol->get_name(name_bstr.GetAddress());
        std::string name = static_cast<const char*>(name_bstr);

        CComPtr<IDiaSymbol> function_type;
        if (FAILED(symbol->get_type(&function_type))) {
            return 0;
        }

        libbtf::btf_type_id proto_id = convert_function_type(function_type);

        libbtf::btf_kind_function func{};
        func.name = name;
        func.type = proto_id;
        func.linkage = libbtf::BTF_LINKAGE_GLOBAL;

        return _btf_data.append(func);
    }

    libbtf::btf_type_id
    get_or_create_int_type(uint32_t size_bytes, bool is_signed)
    {
        std::string name = (is_signed ? "int" : "uint") + std::to_string(size_bytes * 8) + "_t";

        // Check if already exists
        try {
            return _btf_data.get_id(name);
        } catch (const std::runtime_error&) {
            // Type doesn't exist, create it
            libbtf::btf_kind_int int_type{};
            int_type.name = name;
            int_type.size_in_bytes = size_bytes;
            // BTF field_width_in_bits is uint8_t; cap at 255 for types > 31 bytes
            int_type.field_width_in_bits = static_cast<uint8_t>(std::min(size_bytes * 8, 255u));
            int_type.offset_from_start_in_bits = 0;
            int_type.is_signed = is_signed;
            int_type.is_char = false;
            int_type.is_bool = false;

            return _btf_data.append(int_type);
        }
    }

    IDiaSession* _session;
    libbtf::btf_type_data _btf_data;
    std::map<DWORD, libbtf::btf_type_id> _symbol_cache;
};

bool
parse_arguments(int argc, char* argv[], options& opts)
{
    bool help_requested = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--pdb" && i + 1 < argc) {
            opts.pdb_path = argv[++i];
        } else if (arg == "--out" && i + 1 < argc) {
            opts.output_path = argv[++i];
        } else if (arg == "--roots" && i + 1 < argc) {
            // Parse comma-separated list
            std::string roots_str = argv[++i];
            size_t start = 0;
            size_t end = roots_str.find(',');

            while (end != std::string::npos) {
                std::string root = roots_str.substr(start, end - start);
                if (!root.empty()) {
                    opts.root_names.push_back(root);
                }
                start = end + 1;
                end = roots_str.find(',', start);
            }
            std::string last_root = roots_str.substr(start);
            if (!last_root.empty()) {
                opts.root_names.push_back(last_root);
            }
        } else if (arg == "--help" || arg == "-h") {
            help_requested = true;
            break;
        }
    }

    // If help was requested, return true to indicate successful parse (but help needed)
    if (help_requested) {
        return false;
    }

    if (opts.pdb_path.empty() || opts.output_path.empty() || opts.root_names.empty()) {
        return false;
    }

    return true;
}

void
print_usage(const char* program_name)
{
    std::cout << "Usage: " << program_name << " --pdb <path> --roots <names> --out <path>" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --pdb <path>     Path to PDB file" << std::endl;
    std::cout << "  --roots <names>  Comma-separated list of root symbol names" << std::endl;
    std::cout << "  --out <path>     Path to output BTF file" << std::endl;
    std::cout << "  --help, -h       Show this help message" << std::endl;
}

int
main(int argc, char* argv[])
{
    options opts;

    if (!parse_arguments(argc, argv, opts)) {
        print_usage(argv[0]);
        return 1;
    }

    try {
        com_initializer com;

        // Create DIA data source
        CComPtr<IDiaDataSource> data_source;
        HRESULT hr = CoCreateInstance(
            CLSID_DiaSource, nullptr, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void**)&data_source);

        if (FAILED(hr)) {
            std::cerr << "Failed to create DIA data source. Make sure msdia140.dll is registered." << std::endl;
            return 1;
        }

        // Load PDB
        _bstr_t pdb_path(opts.pdb_path.c_str());
        hr = data_source->loadDataFromPdb(pdb_path);
        if (FAILED(hr)) {
            std::cerr << "Failed to load PDB: " << opts.pdb_path << std::endl;
            return 1;
        }

        // Open session
        CComPtr<IDiaSession> session;
        hr = data_source->openSession(&session);
        if (FAILED(hr)) {
            std::cerr << "Failed to open DIA session" << std::endl;
            return 1;
        }

        std::cout << "Successfully loaded PDB: " << opts.pdb_path << std::endl;

        // Convert PDB to BTF
        pdb_to_btf_converter converter(session);
        if (!converter.convert(opts.root_names, opts.output_path)) {
            std::cerr << "Conversion failed" << std::endl;
            return 1;
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
