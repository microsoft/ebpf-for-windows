# eBPF extensions

## 1 Overview
An "eBPF extension" is a Windows kernel driver or component that implements eBPF hooks or helper functions. The design
of eBPF for Windows is such that an extension providing an implementation for hooks and helper functions can be
developed and deployed without the need to modify either the eBPF execution context or the eBPF verifier.

## 1.1 Windows Network Module Registrar
The eBPF for Windows project uses the
[Network Module Registrar (NMR)](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-the-network-module-registrar)
feature in Windows to develop eBPF extensions that are decoupled from the core eBPF for Windows framework.  NMR
facilitates attaching software modules to each other. The
[Network Programming Interface (NPI)](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/network-programming-interface)
defines the contract between the modules.  The eBPF extensions would implement the
[Provider Modules](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/provider-module) for two types of
NPIs as discussed in detail below. Even though the NMR component and the relevant APIs have the word "Network" in them,
these software modules are completely agnostic of Windows Networking stack and non-networking eBPF extensions can be
developed using these.

## 1.2 Prerequisites
The audience is assumed to be familiar with
[NMR Architecture](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/architecture-overview)
and the various aspects of developing NMR modules as described in
[NMR documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/network-module-registrar2).

## 1.3 NPI Contracts for eBPF Extensions
eBPF Extensions need to implement *provider modules* for two types of NPIs. They are the **Program Information NPI**
provider and the **Hook NPI** provider. The following section explains when an extension must implement these
providers.

### 1.3.1 eBPF Program Information NPI Provider
The eBPF Program Information NPI contract is used to provide information about an eBPF program type. Program types
are defined as the ABI contracts that eBPF programs are written to conform to.
This information is consumed by the eBPF verifier to ensure that any eBPF programs of a given type is safe to load
and execute. The ABI contract includes both a description of the &quot;context&quot; parameter passed to the eBPF
program as well as the list of specific helper functions that are available to such eBPF programs.

eBPF extensions must implement a different Program Information NPI provider module for each program type for which it
provides implementation of hooks or helper functions specific to that program type.

### 1.3.2 eBPF Hook NPI Provider
The Hook NPI contracts are used by extension to invoke eBPF programs when OS events occur. A given eBPF hook may have
several attach types. The eBPF extension must register a separate Hook NPI provider module for each attach type it
supports for an eBPF hook. Note that, there can be more than one attach types for a given program type. If an extension
is adding a new attach type for an existing program type, then it only needs to implement the Hook NPI Provider.

## 2 Authoring an eBPF Extension
The steps for authoring an eBPF extension are:
1. Register the NPI provider.
2. Author any program type specific Helper Functions.
3. Invoke eBPF programs from hook(s).
4. Register program and attach types.

The following sections describe these steps in detail.

### 2.1 Program Information NPI Provider Registration
When registering itself to the NMR, the Program Information NPI Provider should have the
[`NPI_REGISTRATION_INSTANCE`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/netioddk/ns-netioddk-_npi_registration_instance)
initialized as follows:
* `NpiId`: This should be set to `EBPF_PROGRAM_INFO_EXTENSION_IID` defined in `ebpf_extension_uuids.h`.
* `ModuleId`: This should be set to the eBPF program type GUID.
* `NpiSpecificCharacteristics`: Pointer to structure of type `ebpf_program_data_t`.

#### `ebpf_extension_header_t` Struct
This is a mandatory header that is common to all data structures needed by eBPF extensions to register with the eBPF framework.
* `version`: Version of the extension data structure.
* `size`: Size of the extension data structure.
 When populating these data structures, the correct `version` and `size` fields must be set. The set of current version numbers and the
 size for the various extension structures are listed in `ebpf_windows.h`. For example:
```c
 #define EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION 1
 #define EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_SIZE \
    (EBPF_OFFSET_OF(ebpf_program_type_descriptor_t, is_privileged) + sizeof(char))
```
> NOTE: Extension developers **must not** set the `size` field of these structures to `sizeof()` of the corresponding type. Instead,
> the `CURRENT_VERSION_SIZE` macros defined in `ebpf_windows.h` should be used.

#### `ebpf_program_data_t` Struct
The various fields of this structure should be set as follows:
* `header`: Version and size.
* `program_info`: Pointer to `ebpf_program_info_t`.
* `program_type_specific_helper_function_addresses`: Pointer to `ebpf_helper_function_addresses_t`. This structure
provides the helper functions that are exclusive to this program type.
* `global_helper_function_addresses`:  Pointer to `ebpf_helper_function_addresses_t`. This structure provides helper
functions that override the global helper functions provided by the eBPF runtime.
* `context_create`: Pointer to `ebpf_program_context_create_t` function that creates a program type specific context
structure from provided data and context buffers.
* `context_destroy`: Pointer to `ebpf_program_context_destroy_t` function that destroys a program type specific
context structure and populates the returned data and context buffers.
* `required_irql`: IRQL at which the eBPF program is invoked by bpf_prog_test_run_opts.

#### `ebpf_program_info_t` Struct
The various fields of this structure should be set as follows:
* `header`: Version and size.
* `program_type_descriptor`: Pointer to `ebpf_program_type_descriptor_t`.
* `count_of_helpers`: The number of helper functions that are implemented by this extension for the given program type.
* `helper_prototype`: Pointer to array of `ebpf_helper_function_prototype_t`.

#### `ebpf_program_type_descriptor_t` Struct
The various fields of this structure should be set as follows:
* `header`: Version and size.
* `name`: Friendly name of the program type.
* `context_descriptor`: Pointer of type `ebpf_context_descriptor_t`.
* `program_type`: GUID for the program type. This should be the same as the `NpiId` in `NPI_REGISTRATION_INSTANCE` as
noted above.
* `bpf_prog_type`: Set to the equivalent bpf program type integer. If there is no equivalent bpf program type, this
field should be set to `0 (BPF_PROG_TYPE_UNSPEC)`.
* `is_privileged`: Set to `FALSE`.

#### `ebpf_context_descriptor_t` Struct
This structure (as the name signifies) provides a description of the context parameter that a hook passes when
invoking an eBPF program. The various fields of this struct are as follows.
* `header`: Version and size.
* `size`: Size of the context structure.
* `data`: Offset (in bytes) to the field in the context structure that is pointing to the beginning of context data.
* `end`: Offset (in bytes) to the field in the context structure that is pointing to the end of context data.
* `meta`: Offset (in bytes) to the field in the context structure that is pointing to the beginning of context metadata.

For example, for the XDP_TEST program types, the context data structure is as follows:
```c
// XDP_TEST hook.  We use "struct xdp_md" for cross-platform compatibility.
typedef struct xdp_md
{
    void* data;         ///< Pointer to start of packet data.
    void* data_end;     ///< Pointer to end of packet data.
    uint64_t data_meta; ///< Packet metadata.

    /* size: 12, cachelines: 1, members: 3 */
    /* last cacheline: 12 bytes */
} xdp_md_t;
```
The corresponding context descriptor looks like:
```c
const ebpf_context_descriptor_t g_xdp_context_descriptor = {sizeof(xdp_md_t),
                                                            EBPF_OFFSET_OF(xdp_md_t, data),
                                                            EBPF_OFFSET_OF(xdp_md_t, data_end),
                                                            EBPF_OFFSET_OF(xdp_md_t, data_meta)};
```
If any of the data or metadata pointer fields are not present on the context structure, the offset value is set to -1
in the context descriptor.

#### `ebpf_helper_function_prototype_t` Struct
This structure is used to describe the prototypes of the various helper functions implemented by the extension.
```c
typedef struct _ebpf_helper_function_prototype_flags
{
    bool reallocate_packet : 1;
} ebpf_helper_function_prototype_flags_t;

typedef struct _ebpf_helper_function_prototype
{
    ebpf_extension_header_t header;
    uint32_t helper_id;
    const char* name;
    ebpf_return_type_t return_type;
    ebpf_argument_type_t arguments[5];
    ebpf_helper_function_prototype_flags_t flags;
} ebpf_helper_function_prototype_t;
```
* `header`: Version and size.
* `helper_id`: Integer signifying the helper function ID. (See section 2.6).
Helper function IDs for different program types need not be unique.
* `name`: Helper function name.
* `return_type`: Set the appropriate value for the `ebpf_return_type_t` enum that represents the return type of the
helper function.
* `arguments`: Array of (at most) five helper function arguments of type `ebpf_argument_type_t`.
* `flags`: Bit field of flags.
   * `reallocate_packet`: Flag indicating if this helper function performs packet reallocation.


#### `ebpf_argument_type_t` Enum
This enum describes the various argument types that can be passed to an eBPF helper function. This is defined in the
[PREVAIL Verifier](https://github.com/vbpf/ebpf-verifier) project.
```c
typedef enum _ebpf_argument_type {
    EBPF_ARGUMENT_TYPE_DONTCARE = 0,
    EBPF_ARGUMENT_TYPE_ANYTHING,
    EBPF_ARGUMENT_TYPE_CONST_SIZE,
    EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO,
    EBPF_ARGUMENT_TYPE_PTR_TO_CTX,
    EBPF_ARGUMENT_TYPE_PTR_TO_MAP,
    EBPF_ARGUMENT_TYPE_PTR_TO_MAP_OF_PROGRAMS,
    EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY,
    EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE,
    EBPF_ARGUMENT_TYPE_PTR_TO_MEM,
    EBPF_ARGUMENT_TYPE_PTR_TO_MEM_OR_NULL,
    EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MEM,
} ebpf_argument_type_t;
```

#### `ebpf_return_type` Enum
This enum describes the various return types from an eBPF helper function. This is defined in the
[PREVAIL Verifier](https://github.com/vbpf/ebpf-verifier) project.
```c
typedef enum _ebpf_return_type {
    EBPF_RETURN_TYPE_INTEGER = 0,
    EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE_OR_NULL,
    EBPF_RETURN_TYPE_INTEGER_OR_NO_RETURN_IF_SUCCEED,
} ebpf_return_type_t;
```

#### `ebpf_helper_function_addresses_t` Struct
This structure is used to specify the address at which the various helper functions implemented by the extension
reside. If an eBPF program is JIT compiled, then the generated machine code will have `call` instructions to these
addresses. For interpreted mode, the eBPF Execution Engine will invoke the functions at these addresses. The fields of
this struct should be set as follows:
* `helper_function_count`: Number of helper functions implemented by the extension for the given program type.
* `helper_function_address`: Array of addresses (64-bit unsigned integer) for the helper functions. The addresses must
be arranged in the array in the *same order* as the array of helper function prototypes denoted by the
`helper_prototype` field in `ebpf_program_info_t` struct.  For the correct execution of eBPF programs, the helper
function addresses cannot change while a loaded eBPF program is executing.

There are two sets of helper function addresses that the extension can return. The first are helper functions that are
only callable during execution of an eBPF program that matches this program type. The second are helper function
implementations that override the global helper function implementations provided by the eBPF runtime.

### `ebpf_program_context_create_t` Function
This optional function is used to build a program type specific context structure that is used when an application
calls `bpf_prog_test_run_opts`. The application optionally passes in flat buffers representing the data and the context
structure to be passed to the eBPF program. The extension then constructs a context structure to be passed to the eBPF
program. Note: If `ebpf_program_context_create_t` is present, then `ebpf_program_context_destroy_t` and `required_irql`
must be set.

### `ebpf_program_context_destroy_t` Function
This optional function is used to populate the flat buffers representing the data and context structures that are
returned to the application when the `bpf_prog_test_run_opts` call completes. In addition, the function frees any
resources allocated in the `ebpf_program_context_create_t` call.

### 2.2 Backward compatibility of the Extension data structures
All the extension data structures are versioned. To maintain backward compatibility with the existing extensions, new fields **MUST** be added
to the end of a data structure. The constant defining the current size of the modified struct will be updated in `ebpf_windows.h`. Existing
eBPF extensions will continue to work without requiring recompilation. If an extension is modified to use a newly added field, the length
field must be updated accordingly.

If the change in data structure is such that it is no longer backward compatible (such as changing field type or position),
then the version number will be updated. In this case, the product version of eBPF for Windows must be updated to indicate a breaking change
as well. Existing eBPF extensions would need to be re-compiled to work with the latest version of eBPF.

### 2.3 Program Information NPI Client Attach and Detach Callbacks
The eBPF Execution Context registers a Program Information NPI client module with the NMR for every eBPF program that
gets loaded. The Execution Context will use the program type GUID of the program as the NPI ID of the client module.
And as a result, upon eBPF program load, the associated Program Information NPI client module will attach with the
corresponding Program Information NPI provider module in the extension. The Program Information NPI does not have any
client or provider dispatch tables. Neither does the client's `NpiSpecificCharacteristics` have any data. So, no
special processing is required in the client attach and detach callback handler on the provider module. An extension
must not unload until there are no more attached Program Information NPI clients.

### 2.4 Hook NPI Provider Registration
When registering itself to the NMR, the Hook NPI provider should have the
[`NPI_REGISTRATION_INSTANCE`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/netioddk/ns-netioddk-_npi_registration_instance)
initialized as follows:
* `NpiId`: This should be set to `EBPF_HOOK_EXTENSION_IID` defined in `ebpf_extension_uuids.h`.
* `ModuleId`: This should be set to the attach type GUID.
* `NpiSpecificCharacteristics`: Pointer to structure of type `ebpf_attach_provider_data_t`.

#### `ebpf_attach_provider_data_t` Struct
This structure is used to specify the attach type supported by the extension for the given Hook NPI provider. It
contains the following fields:
* `supported_program_type`
* `bpf_attach_type`

The `supported_program_type` field of the struct should be filled with the `ebpf_program_type_t` (GUID) of the
supported program type. While attaching an eBPF program to a hook instance, the Execution Context enforces that the
requested attach type is supported by the Hook NPI provider. If not, the eBPF program fails to attach to the hook.

The `bpf_attach_type` field should contain the equivalent bpf attach type integer. If there is no equivalent bpf
attach type, this field should be set to `0 (BPF_ATTACH_TYPE_UNSPEC)`.

### 2.5 Hook NPI Client Attach and Detach Callbacks
The eBPF Execution Context registers a Hook NPI client module with the NMR for each program that is attached to a hook.
The attach type GUID is used as the NPI of the client module. And as a result, when an eBPF program gets attached to
a hook, the associated Hook NPI client module will attach to the corresponding Hook NPI provider module in the
extension. The
[client attach callback](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/netioddk/nc-netioddk-npi_provider_attach_client_fn)
function is invoked when the NPI client is being attached. The provider must store the following in a per-client data
structure from the passed in parameters:
* `ClientBindingContext`: Client binding context.
* `ClientDispatch`: Client dispatch table (see section 2.5 below).
* `NpiSpecificCharacteristics`: Obtained from `ClientRegistrationInstance` parameter. This contains attach-type
specific data that may be used by an extension for attaching an eBPF program. For example, when an eBPF program is
being attached to an XDP_TEST hook, the network interface index can be passed via this parameter. This tells the extension
to invoke the eBPF program whenever there are any inbound packets on that network interface. The attach parameter can
be obtained as follows:
```c
ebpf_extension_data_t* extension_data = (ebpf_extension_data_t*)ClientRegistrationInstance->NpiSpecificCharacteristics;
attach_parameter = extension_data->data;
```

The per-client data structure should be returned as the `ProviderBindingContext` output parameter.

Upon
[client detach callback](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/netioddk/nc-netioddk-npi_provider_detach_client_fn)
the provider must free the per-client context passed in via `ProviderBindingContext` parameter.

### 2.6 Invoking an eBPF program from Hook NPI Provider
To invoke an eBPF program, the extension uses the dispatch table supplied by the Hook NPI client during attaching.
The client dispatch table contains the functions, with the following type prototypes:

```c
/**
 * @brief Invoke the eBPF program.
 *
 * @param[in] extension_client_binding_context The context provided by the extension client when the binding was created.
 * @param[in,out] program_context The context for this invocation of the eBPF program.
 * @param[out] result The result of the eBPF program.
 *
 * @retval EBPF_SUCCESS if successful or an appropriate error code.
 * @retval EBPF_NO_MEMORY if memory allocation fails.
 * @retval EBPF_EXTENSION_FAILED_TO_LOAD if required extension is not loaded.
 */
typedef ebpf_result_t (*ebpf_program_invoke_function_t)(
    _In_ const void* extension_client_binding_context, _Inout_ void* program_context, _Out_ uint32_t* result);

/**
 * @brief Prepare the eBPF program for batch invocation.
 *
 * @param[in] extension_client_binding_context The context provided by the extension client when the binding was created.
 * @param[in] state_size The size of the state to be allocated, which should be greater than or equal to
 * sizeof(ebpf_execution_context_state_t).
 * @param[out] state The state to be used for batch invocation.
 *
 * @retval EBPF_SUCCESS if successful or an appropriate error code.
 * @retval EBPF_NO_MEMORY if memory allocation fails.
 * @retval EBPF_EXTENSION_FAILED_TO_LOAD if required extension is not loaded.
 */
typedef ebpf_result_t (*ebpf_program_batch_begin_invoke_function_t)(
    _In_ const void* extension_client_binding_context, size_t state_size, _Out_writes_(state_size) void* state);

/**
 * @brief Invoke the eBPF program in batch mode.
 *
 * @param[in] extension_client_binding_context The context provided by the extension client when the binding was created.
 * @param[in,out] program_context The context for this invocation of the eBPF program.
 * @param[out] result The result of the eBPF program.
 * @param[in] state The state to be used for batch invocation.
 *
 * @retval EBPF_SUCCESS.
 */
typedef ebpf_result_t (*ebpf_program_batch_invoke_function_t)(
    _In_ const void* extension_client_binding_context,
    _Inout_ void* program_context,
    _Out_ uint32_t* result,
    _In_ const void* state);

/**
 * @brief Clean up the eBPF program after batch invocation.
 *
 * @param[in] extension_client_binding_context The context provided by the extension client when the binding was created.
 * @param[in,out] state The state to be used for batch invocation.
 *
 * @retval EBPF_SUCCESS.
 */
typedef ebpf_result_t (*ebpf_program_batch_end_invoke_function_t)(
    _In_ const void* extension_client_binding_context, _Inout_ void* state);
```

The function pointer can be obtained from the client dispatch table as follows:
```c
invoke_program = (ebpf_program_invoke_function_t)client_dispatch_table->function[0];
```
When an extension invokes this function pointer, then the call flows through the eBPF Execution Context and eventually
invokes the eBPF program.  When invoking an eBPF program, the extension must supply the client binding context it
obtained from the Hook NPI client as the `client_binding_context` parameter. For the second parameter `context`, it
must pass the program type specific context data structure. Note that the Program Information NPI provider supplies
the context descriptor (using the `ebpf_context_descriptor_t` type) to the eBPF verifier and JIT-compiler via the NPI
client hosted by the Execution Context. The `result` output parameter holds the return value from the eBPF program
post execution.

In cases where the same eBPF program will be invoked sequentially with different context data (aka batch invocation),
the caller can reduce the overhead by using the batch invocation APIs. Prior to the first invocation, the batch
begin API is called, which caches state used by the eBPF program and prevents the program from being unloaded. The
caller is responsible for providing storage large enough to store an instance of ebpf_execution_context_state_t and
ensuring that it remain valid until calling the batch end API. Between the begin and end calls, the caller may call
the batch invoke API multiple times to invoke the BPF program with minimal overhead. Callers must limit the length
of time a batch is open and must not change IRQL between calling batch begin and end. Batch end cost may scale with
the number of times the program has been invoked, so callers should limit the number of calls within a batch to
prevent long delays in batch end.

### 2.7 Authoring Helper Functions
An extension can provide an implementation of helper functions that can be invoked by the eBPF programs. The helper
functions can be of two types:
1. Program-Type specific: These helper functions can only be invoked by eBPF programs of a given program type. Usually,
an extension may provide implementations for hooks of certain program types and provide helper functions that are
associated with those helper functions. The Program Information NPI provider must then provide the prototypes and
addresses for those functions. For these type of helpers, the helper function Id must be greater that 65535 (0xFFFF)
for program type specific helper functions.
2. General: The general helper functions can be invoked by eBPF programs of all types. Examples of this type of helper
functions are the eBPF Map helper functions. These helper functions are implemented by the eBPF Execution Context
itself. However, if a program type so chooses, it may provide implementations for general helper functions. For that
the extension would have to provide another Program Information NPI provider, which *does not* provide any program
context descriptor. Instead, it only supplies the prototypes and addresses of the general helper functions. The NPI ID
of this module defined as:
```c
GUID ebpf_general_helper_function_module_id = {/* 8d2a1d3f-9ce6-473d-b48e-17aa5c5581fe */
                                                  0x8d2a1d3f,
                                                  0x9ce6,
                                                  0x473d,
                                                  {0xb4, 0x8e, 0x17, 0xaa, 0x5c, 0x55, 0x81, 0xfe}};
```
The helper function ID for a general helper function must be in the range 0 - 65535 and must be globally unique.

The parameter and return types for these helper functions must adhere to the `ebpf_argument_type_t` and
`ebpf_return_type_t` enums.

### 2.8 Registering Program Types and Attach Types - eBPF Store
The eBPF Execution Context loads an eBPF program from an ELF file that has program section(s) with section names. The
prefix to these names determines the program type. For example, the section name `"xdp_test"` implies that the corresponding
program type is `EBPF_PROGRAM_TYPE_XDP_TEST`.

The *Execution Context* discovers the program type associated with a section prefix by reading the data from the ***"eBPF store"***, which is currently kept in the Windows registry. An extension developer must author a user mode application which will use eBPF store APIs to update the program types it implements along with the associated section prefixes. eBPF store APIs are exported from ebpfapi.dll.

To operate on the eBPF store, the user mode application needs to link with eBPFApi.dll and include the related `include\ebpf_store_helper.h` header file, both distributed within the [eBPF for Windows NuGet package](https://www.nuget.org/packages/eBPF-for-Windows/). With these, the application can use the following APIs to register program types, attach types, and helper functions:

- `ebpf_store_update_section_information`: updates the section information in the eBPF store, given a pointer to an array of section information (i.e., `_ebpf_program_section_info`):

    ```c
    ebpf_result_t
    ebpf_store_update_section_information(
        _In_reads_(section_info_count) const ebpf_program_section_info_t* section_info, uint32_t section_info_count);
    ```

- `ebpf_store_update_program_information_array`: updates program information in the eBPF store, given a pointer to an array of program information (i.e., `_ebpf_program_info`):

    ```c
    ebpf_result_t
    ebpf_store_update_program_information_array(
        _In_reads_(program_info_count) const ebpf_program_info_t* program_info, uint32_t program_info_count);
    ```

### 2.9 eBPF Sample Driver
The eBPF for Windows project provides a
[sample extension driver](https://github.com/microsoft/ebpf-for-windows/tree/8f46b4020f79c32f994d3a59671ce8782e4b4cf0/tests/sample/ext)
as an example for how to implement an extension. This simple extension exposes a new program type, and implements a
hook for it with a single attach type. It implements simple NPI provider modules for the two NPIs. It also implements
three program-type specific helper functions.
