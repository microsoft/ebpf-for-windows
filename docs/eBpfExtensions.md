# eBPF extensions

## 1 Overview
An "eBPF extension" is a Windows kernel driver or component that implements eBPF hooks, helper functions and extensible maps. The design
of eBPF for Windows is such that an extension providing an implementation for hooks, helper functions and maps can be
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
eBPF Extensions need to implement *provider modules* for three types of NPIs. They are the **Program Information NPI**
provider, **Hook NPI** provider and **Map Information NPI**.
**Map Information NPI** is optional and only needs to be implemented if an extension want to add support for a
program type specific map. The following section explains when an extension must implement these providers.

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

### 1.3.3 eBPF Map Information NPI Provider
The Map Info NPI contract is used by extension to provide an implementation for a map type that is not already
implemented by the eBPF runtime. An example for this can be *BPF_MAP_TYPE_XSKMAP*. The eBPF extension must register
a separate Map Info NPI provider module for each map type it implements.

## 2 Authoring an eBPF Extension
The steps for authoring an eBPF extension are:
1. Register the NPI provider.
2. Author any program type specific Helper Functions.
3. Author any extensible maps.
3. Invoke eBPF programs from hook(s).
4. Register program and attach types.
5. Register extensible map types, if any.

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
* `size`: Size of the extension data structure, not including any padding.
* `total_size` Total size of the extension data structure, including any padding.

 When populating these data structures, the correct `version`, `size` and `total_size` fields must be set. The set of current version numbers and the
 size for the various extension structures are listed in `ebpf_windows.h`. For example:
```c
 #define EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION 1
 #define EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_SIZE \
    (EBPF_OFFSET_OF(ebpf_program_type_descriptor_t, is_privileged) + sizeof(char))
 #define EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_TOTAL_SIZE sizeof(ebpf_program_type_descriptor_t)
```

When initializing the `ebpf_extension_header_t` struct, instead of using the individual values listed above, macros like below can also be used for convenience.
```c
#define EBPF_PROGRAM_TYPE_DESCRIPTOR_HEADER                                                              \
    {                                                                                                    \
        EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION, EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_SIZE, \
            EBPF_PROGRAM_TYPE_DESCRIPTOR_CURRENT_VERSION_TOTAL_SIZE                                      \
    }
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
* `capabilities`: 32-bit integer describing the optional capabilities / features supported by the extension.
    * No capabilities are currently defined.
    * The first bit is reserved and must be zero.

#### `EBPF_CONTEXT_HEADER` eBPF Program Context Header

Extensions are required to add a context header at the start of each context passed to the eBPF program.
This is required for all extensions to support for runtime state needed by helpers.
To support this, the extension can use the macro `EBPF_CONTEXT_HEADER` to include
the context header at the start of the program context structure. The context pointer passed to the
eBPF program should point immediately after the context header.

*Example*

Below is an example of a sample extension including the eBPF context header at the start of the original
context structure:

```c
// Original sample extension program context that is passed to the eBPF program.
typedef struct _sample_program_context
{
    uint8_t* data_start;
    uint8_t* data_end;
    uint32_t uint32_data;
    uint16_t uint16_data;
    uint32_t helper_data_1;
    uint32_t helper_data_2;
} sample_program_context_t;

// Program context including the context header.
typedef struct _sample_program_context_header
{
    EBPF_CONTEXT_HEADER;
    sample_program_context_t context;
} sample_program_context_header_t;
```
The extension passes a pointer to `context` inside `sample_program_context_header_t` and not a pointer to
`sample_program_context_header_t` when invoking the eBPF program. The header is not accessible
by the program.

##### Pointer members in program contexts

The sample program context above contains two pointer fields, `data_start` and `data_end`.
If the intent of an extension is to provide compatibility with some program type that exists on Linux,
and pointer members exist in the program context, there is a potential problem to be aware of.

On Linux, "pointers" in some program contexts are defined as 32-bit integers, even on 64-bit platforms (with conversion
done at program load time), whereas the example above will result in 64-bit pointers on
64-bit platforms.  eBPF for Windows aims to provide source compatibility, but not binary compatibility.

The issue may go unnoticed until verification of a program that works fine on Linux failing
unexpectedly on Windows due to the program hard coding the context structure it expects, which of course won't
match what the Windows extension uses, since the context has a different offset for `data_end`.

As such, extensions intended to provide source-compatibility with Linux should minimally document this
issue in discussing how to use the extension, and ideally show how to write cross-platform eBPF program
code without using ifdefs.

As an example, on Linux the BPF_XDP program type uses the `xdp_md` context which has:

```
struct xdp_md {
    __u32 data;          /* Pointer to start of packet data */
    __u32 data_end;      /* Pointer to end of packet data */
...
};

```

and a sample XDP program might have:

```
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Verify that data_end is at least as long as the size we need.
    // ...

    // Access memory pointed to by data.
    // ...
}
```

Meeting the eBPF for Windows goal of being source-compatible with Linux means that,
however the `xdp_md` context is defined on Windows, the cast
```
   void *data_end = (void *)(long)ctx->data_end;
```
needs to work.

As a second example to illustrate that the problem is not XDP-specific, on Linux the
`__sk_buff` structure is defined as:
```
struct __sk_buff {
...
    __u32 data;
    __u32 data_end;
...
};
```

and a sample TC classifier program might have:

```
SEC("classifier")
int classifier_prog(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // ...
}
```

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
* `bpf_prog_type`: Set to the equivalent bpf program type integer. If there is no equivalent bpf program type, either add a value to the `bpf_prog_type` enum and assign it here or this field should be set to `0 (BPF_PROG_TYPE_UNSPEC)`.
* `is_privileged`: Set to `FALSE`.

#### `ebpf_context_descriptor_t` Struct
This structure (as the name signifies) provides a description of the context parameter that a hook passes when
invoking an eBPF program. The various fields of this struct are as follows.
* `header`: Version and size.
* `size`: Size of the context structure.
* `data`: Offset (in bytes) to the field in the context structure that is pointing to the beginning of context data.
* `end`: Offset (in bytes) to the field in the context structure that is pointing to the end of context data.
* `meta`: Offset (in bytes) to the field in the context structure that is pointing to the beginning of context metadata.

For example, for the BPF_PROG_TYPE_SAMPLE program types, the context data structure is as follows:
```c
// Sample extension program context.
typedef struct _sample_program_context
{
    uint8_t* data_start;
    uint8_t* data_end;
    uint32_t uint32_data;
    uint16_t uint16_data;
    uint32_t helper_data_1;
    uint32_t helper_data_2;
} sample_program_context_t;
```
The corresponding context descriptor looks like:
```c
const ebpf_context_descriptor_t g_sample_program_context_descriptor = {sizeof(sample_program_context_t),
                                                            EBPF_OFFSET_OF(sample_program_context_t, data_start),
                                                            EBPF_OFFSET_OF(sample_program_context_t, data_end),
                                                            -1};
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
* `implicit_context`: Flag indicating the extension requires implicit context for this helper function.

**Note about `implicit_context`**:
With the `implicit_context` feature, an extension can choose to get the program context as the 6th argument to the
helper function. In case the helper function does not require all the original 5 arguments (program context being
the 6th argument), the helper function should declare dummy arguments as placeholders for the unused arguments.
Note that this new change does not require any change in the helper function prototype that is needed for the
program verification.

**Example**
Below is an example of a helper function only takes 1 argument `arg` as input, but to get also program context
as input, also declares the remaining 4 dummy arguments (`dummy_param1` to `dummy_param4`).

```c
static int64_t
sample_ebpf_extension_helper_implicit_2(
    uint32_t arg,
    uint64_t dummy_param1,
    uint64_t dummy_param2,
    uint64_t dummy_param3,
    uint64_t dummy_param4,
    _In_ const sample_program_context_t* context)
```

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

#### 2.2.1 Backward / Forward compatibility
For the cases when a new feature is exposed from eBPF to the extensions that is backward compatible, and requires a bit field / flag to be
added to one of the extension data structures, there are 2 possible options:
1. Add a new variable in the structure corresponding to the new feature. This will result in increasing the size of the struct.
2. Utilize a bit field in an (if available) existing `flags` field. This option does not result in increasing the size of the struct.

Which of the above 2 options to choose will depend if the feature is forward compatible. If the new feature is forward compatible, (i.e.
an extension compiled with new eBPF headers can work fine with an older eBPF runtime), then any of the above 2 options can be chosen to
add the flag. However, if the feature is not forward compatible, and will cause functional issues or crashes (when a new extension is
deployed with older eBPF runtime), then option 1 **MUST** be chosen. Choosing option 1 results in and increase of the size of the struct,
allowing older eBPF runtime to detect an incompatible extension, and reject binding to such an extension.

#### 2.2.2 Hashing of data structures to validate verification of native images
When native images are generated, bpf2c uses the verifier to ensure that the program is safe to execute and then
computes a hash over the invariants used to validate the program. These invariants include the properties of the
program information provider and the signature of any helper functions used. The following fields are included in the hash:
1. ebpf_program_type_descriptor_t::name
2. ebpf_program_type_descriptor_t::context_descriptor
3. ebpf_program_type_descriptor_t::program_type
4. ebpf_program_type_descriptor_t::bpf_prog_type
5. ebpf_program_type_descriptor_t::is_privileged
6. Count of helper ids being used (as a unsigned 64bit integer)
7. Each helper function being used is then appended to the hash in order of id.
    1. ebpf_helper_function_prototype_t::helper_id
    2. ebpf_helper_function_prototype_t::name
    3. ebpf_helper_function_prototype_t::return_type
    4. Each element of the ebpf_helper_function_prototype_t::arguments array
    5. ebpf_helper_function_prototype_t::flags - only if non-default value

Any new fields MUST be added to the end of the hash and the hash MUST include all fields up to and including the last
field containing a non-default value. Fields containing default values after the last non-default value MUST NOT
be included. This ensures that hashes computed over older versions of the structure remain valid if new functionality
is not being used. If a new feature or functionality is being used, the hash value MUST change to ensure that the
verification constraints are honored. All new fields that affect verification MUST be included with a non-default value
and all fields that do not affect verification MUST NOT be included.

### 2.3 Program Information NPI Client Attach and Detach Callbacks
The eBPF execution context registers a Program Information NPI client module with the NMR for every eBPF program that
gets loaded. The execution context will use the program type GUID of the program as the NPI ID of the client module.
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
* `ModuleId`: This should be set to the attach type GUID. (See [ebpf_attach_provider_data_t Struct](eBpfExtensions.md#ebpf_attach_provider_data_t-struct))
* `NpiSpecificCharacteristics`: Pointer to structure of type `ebpf_attach_provider_data_t`.

#### `ebpf_attach_provider_data_t` Struct
This structure is used to specify the attach type supported by the extension for the given Hook NPI provider. It
contains the following fields:
* `supported_program_type`
* `bpf_attach_type`
* `link_type`

The `supported_program_type` field of the struct should be filled with the `ebpf_program_type_t` (GUID) of the
supported program type. This must be the same as the value of the `ModuleId` field in `NPI_REGISTRATION_INSTANCE`.
While attaching an eBPF program to a hook instance, the execution context enforces that the
requested attach type is supported by the Hook NPI provider. If not, the eBPF program fails to attach to the hook.

The `bpf_attach_type` field should contain the equivalent bpf attach type integer. If there is no equivalent bpf attach type, either add a value to the
`bpf_attach_type_t` enum (defined in `ebpf_structs.h`) and assign it here or this field should be set to `0 (BPF_ATTACH_TYPE_UNSPEC)`.

The `link_type` field should be set to a suitable value in `bpf_link_type` enum (defined in `ebpf_structs.h`). Depending on the hook,
some optional attach parameters may be provided when an eBPF program attaches to the hook. For example, the XDP hook expects a network interface index
passed in the attach parameters. This attach data is stored in the `bpf_link_info` struct. The `link_type` fields is used to determine
which attach parameter is present in the link info.

### 2.5 Hook NPI Client Attach and Detach Callbacks
The eBPF execution context registers a Hook NPI client module with the NMR for each program that is attached to a hook.
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
being attached to an BPF_XDP hook, the network interface index can be passed via this parameter. This tells the extension
to invoke the eBPF program whenever there are any inbound packets on that network interface. The attach parameter can
be obtained as follows:
```c
ebpf_extension_data_t* extension_data = (ebpf_extension_data_t*)ClientRegistrationInstance->NpiSpecificCharacteristics;
attach_parameter = extension_data->data;
```

### `ebpf_extension_data_t` Struct
This structure contains the additional data passed from the application to the attach provider. It contains the following fields:
* `data` Attach type specific data. See documentation for the attach type provider for the format of this data.
* `data_size` The length of the attach type specific data.
* `prog_attach_flags` A collection of attach type specific flags passed from the application to the attach provider.

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
 * @param[in] state_size The size of the state to be allocated, which should be greater than or equal to
 * sizeof(ebpf_execution_context_state_t).
 * @param[out] state The state to be used for batch invocation.
 *
 * @retval EBPF_SUCCESS if successful or an appropriate error code.
 * @retval EBPF_NO_MEMORY if memory allocation fails.
 * @retval EBPF_EXTENSION_FAILED_TO_LOAD if required extension is not loaded.
 */
typedef ebpf_result_t (*ebpf_program_batch_begin_invoke_function_t)(
    size_t state_size, _Out_writes_(state_size) void* state);

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
 * @param[in,out] state The state to be used for batch invocation.
 *
 * @retval EBPF_SUCCESS.
 */
typedef ebpf_result_t (*ebpf_program_batch_end_invoke_function_t)(
    _Inout_ void* state);
```

The function pointer can be obtained from the client dispatch table as follows:
```c
invoke_program = (ebpf_program_invoke_function_t)client_dispatch_table->function[0];
```
When an extension invokes this function pointer, then the call flows through the eBPF execution context and eventually
invokes the eBPF program.  When invoking an eBPF program, the extension must supply the client binding context it
obtained from the Hook NPI client as the `client_binding_context` parameter. For the second parameter `context`, it
must pass the program type specific context data structure. Note that the Program Information NPI provider supplies
the context descriptor (using the `ebpf_context_descriptor_t` type) to the eBPF verifier and JIT-compiler via the NPI
client hosted by the execution context. The `result` output parameter holds the return value from the eBPF program
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

### 2.7 Map Information NPI Provider Registration
When registering itself to the NMR, the Map Info NPI provider should have the
[`NPI_REGISTRATION_INSTANCE`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/netioddk/ns-netioddk-_npi_registration_instance)
initialized as follows:
* `NpiId`: This should be set to `EBPF_MAP_INFO_EXTENSION_IID` defined in `ebpf_extension_uuids.h`.
* `ModuleId`: This can be set to any provider chosen GUID.
* `NpiSpecificCharacteristics`: Pointer to structure of type `ebpf_map_provider_data_t`.

typedef struct _ebpf_map_provider_data
{
    ebpf_extension_header_t header;
    size_t supported_map_type_count;                                            // Number of supported map types
    _Field_size_(supported_map_type_count) const uint32_t* supported_map_types; // Array of supported map types
    ebpf_map_provider_dispatch_table_t* dispatch_table;
} ebpf_map_provider_data_t;

#### `ebpf_map_provider_data_t` Struct
This structure is used to specify all the extensible map types that the extension supports. It contains the following fields:
* `supported_map_type_count`
* `supported_map_types`
* `dispatch_table`

The `supported_map_type_count` field contains the number of extensible maps that the extension supports.
The `supported_map_types` is a pointer to an array containing the map types of the extensible maps that the extension supports.
The `dispatch_table` is a pointer to the provider dispatch table that the extension provides for operations on the supported maps.

#### Map ID
eBPF-for-Windows runtime supports some global map types. eBPF-for-Windows has reserved the map IDs 1 to 4095 (BPF_MAP_TYPE_MAX) for the global map types implemented in eBPF Core. Extensions need to use a map ID > BPF_MAP_TYPE_MAX for any extensible map they implement.

Note: Though this is not required, extensions *can* register their map types by creating a pull request to eBPF-for-Windows
repo and updating `ebpf_map_type_t` enum in ebpf_structs.h. This helps in any map type collision with another extension.

#### `ebpf_map_provider_dispatch_table_t` Struct
```
typedef struct _ebpf_map_provider_dispatch_table
{
    ebpf_extension_header_t header;
    _Notnull_ ebpf_map_create_t create_map_function;
    _Notnull_ ebpf_map_delete_t delete_map_function;
    _Notnull_ ebpf_map_associate_program_type_t associate_program_function;
    ebpf_map_find_element_t find_element_function;
    ebpf_map_update_element_t update_element_function;
    ebpf_map_delete_element_t delete_element_function;
    ebpf_map_get_next_key_and_value_t get_next_key_and_value_function;
} ebpf_map_provider_dispatch_table_t;
```
This the dispatch table that the extension needs to implement and provide to eBPF runtime. It contains the following fields:
1. `create_map_function` - Called by eBPF runtime to create the map.
2. `delete_map_function` - Called by eBPF runtime to delete the map.
3. `associate_program_function` - Called by eBPF runtime to validate if a specific map can be associated with the supplied program type. eBPFCore invokes this function before an extensible map is associated with a program.
4. `find_element_function` - Function to find an entry.
5. `update_element_function` - Function to update an entry.
5. `delete_element_function` - Function to delete an entry.
6. `get_next_key_and_value_function` - Function to get the next key and value.

When `create_map_function` is invoked, the extension will allocate a map, and return a pointer to it (called `map_context`) back to the eBPF runtime. When any of the APIs are invoked for this map, the extension will get this `map_context` back as an input parameter.

#### `ebpf_map_client_data_t` Struct
`ebpf_map_client_data_t` is the client data that is provided by eBPFCore to the extension when it attaches to the NMR provider. It is defined as below:

```
typedef struct _ebpf_map_client_data
{
    ebpf_extension_header_t header; ///< Standard extension header containing version and size information.
    uint64_t map_context_offset;    ///< Offset within the map structure where the provider context data is stored.
    ebpf_map_client_dispatch_table_t* dispatch_table; ///< Pointer to client dispatch table.
} ebpf_map_client_data_t;
```

`map_context_offset` is provided by eBPFCore to the extension to get to the extension specific map context when the
extensible map is being used in a helper function. This value is constant for all the bindings from eBPFCore to the
extension for all extensible map types and instances.

`dispatch_table` is the client dispatch table provided by eBPFCore to the extension. It is defined as below:
```
typedef struct _ebpf_map_client_dispatch_table
{
    ebpf_extension_header_t header;
    epoch_allocate_with_tag_t epoch_allocate_with_tag;
    epoch_allocate_cache_aligned_with_tag_t epoch_allocate_cache_aligned_with_tag;
    epoch_free_t epoch_free;
    epoch_free_cache_aligned_t epoch_free_cache_aligned;
} ebpf_map_client_dispatch_table_t;
```
The client dispatch table provides *epoch based memory management* APIs that extension can use for allocating
memory when implementing extensible maps.
See [Epoch based memory management](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/EpochBasedMemoryManagement.md) for more details on this topic.

### 2.8 Authoring Helper Functions
An extension can provide an implementation of helper functions that can be invoked by the eBPF programs. The helper
functions can be of two types:
1. Program-Type specific: These helper functions can only be invoked by eBPF programs of a given program type. Usually,
an extension may provide implementations for hooks of certain program types and provide helper functions that are
associated with those helper functions. The Program Information NPI provider must then provide the prototypes and
addresses for those functions. For these type of helpers, the helper function Id must be greater that 65535 (0xFFFF)
for program type specific helper functions.
2. General: The general helper functions can be invoked by eBPF programs of all types. Examples of this type of helper
functions are the eBPF Map helper functions. These helper functions are implemented by the eBPF execution context
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

### 2.9 Helper functions that use extensible maps.
If the extension is implementing a helper function that takes an extensible map as input, when the helper function is
invoked, it will **not** get the map context that it had passed earlier to eBPFCore. It will instead get a pointer to
a separate map structure that eBPFCore maintains. Using this pointer, and the `map_context_offset` provided in the
`map_client_data`, extensions will need to get their map context. `MAP_CONTEXT()` macro is provied in `ebpf_extensions.h`
for extensions to get their map context. Extensions should validate that the map context they got back is NULL or not,
and handle it appropriately.

### 2.9 Registering Program Types and Attach Types - eBPF Store
The eBPF execution context loads an eBPF program from an ELF file that has program section(s) with section names. The
prefix to these names determines the program type. For example, the section name `"xdp"` implies that the corresponding
program type is `BPF_PROG_TYPE_XDP`.

The *execution context* discovers the program type associated with a section prefix by reading the data from the ***"eBPF store"***, which is currently kept in the Windows registry. An extension developer must author a user mode application which will use eBPF store APIs to update the program types it implements along with the associated section prefixes. eBPF store APIs are exported from ebpfapi.dll.

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

### 2.10 eBPF Sample Driver
The eBPF for Windows project provides a
[sample extension driver](https://github.com/microsoft/ebpf-for-windows/tree/8f46b4020f79c32f994d3a59671ce8782e4b4cf0/tests/sample/ext)
as an example for how to implement an extension. This simple extension exposes a new program type, and implements a
hook for it with a single attach type. It implements simple NPI provider modules for the two NPIs. It also implements
three program-type specific helper functions.
The extension also implements two extensible maps, and implements a provider module for the two maps that it implements.
