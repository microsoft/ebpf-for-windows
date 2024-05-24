# Load Multiple Instances of Native Module

When using native mode on Windows, the programs are loaded from a native driver instead of an ELF file. As part of the
load operation, the native driver is loaded in the kernel and the eBPF execution context orchestrates the creation of
maps and loading the programs from the native driver. The execution context fetches the map properties from the native
module (using functions exported by the native driver via NMR) and creates the required maps.
But when trying to load the same native driver again, we hit a restriction that a driver cannot be loaded multiple
times. This restriction creates a limitation where the same program(s) cannot be loaded multiple times when using
native mode.

This document discusses proposal(s) for loading eBPF programs multiple times from the same native module.

At a high level, adding this feature support requires 2 changes:
1. Changes in ebpfapi and ebpfcore to synchronize service creation and deletion, along with driver load and unload.
1. Changes in BPF2C / native module to use "per-instance" map and helper contexts, instead of global contexts.
Similarly, changes in ebpfcore to create the "per-instance" contexts when programs are loaded from native module,
and pass the context to the program whenever the program is invoked.

This document mainly discusses the first change mentioned above, and possible options to implement it.

## Synchronize service creation
To ensure service creation / deletion, and driver load / unload are synchronized between multiple processes trying to
load the same native module, there are two proposed options below.

**Note regarding service name creation**

For both the options discussed below, the *service name* cannot be same as the *driver name*. This is to handle the
following scenario:

If two different applications / products have their own native programs (sys files) that have same file name, but are
located in different paths, these two sys files should be allowed to be loaded at the same time. If the service name is
same as sys file name, that will not work. To handle such a case, one option is to construct service path by taking
file_name (without the extension) and appending it with 32-bit hash (e.g. use murmur hash with fixed hash seed) of the
full path. That should make the service name unique. This logic to generate the unique file name can be implemented in
ebpfapi as follows:
1. App passes file name to libbpf / eBPF APIs. This can be just the file name, or file name including absolute or
relative path.
2. ebpfapi calls `GetFullPathName` to get the full path of the file.
3. Compute hash of the full path.
4. Use the hash of full path and the file name to generate unique service name (e.g. `droppacket_<32_bit_hash>`)

### Option 1

1. ebpfcore exposes a new IOCTL `GET_NATIVE_MODULE_HANDLE` which takes service name as input.
2. Any user app that wants to load the native module first calls `GET_NATIVE_MODULE_HANDLE` IOCTL.
3. If ebpfcore finds a module entry which is already loaded, it returns `SUCCESS`. App continues to step 7.
4. If ebpfcore does not find a module entry with that service name, it returns `EBPF_SERVICE_NOT_PRESENT` to user mode.
5. If the user app gets `EBPF_SERVICE_NOT_PRESENT`, it deletes any possible previous service entry, and creates a new
   service entry. Continue to step 7.
6. If 2 threads are calling `GET_NATIVE_MODULE_HANDLE` in parallel for the same module that is not yet loaded, one
thread will get `EBPF_SERVICE_NOT_PRESENT` error, which delegates service entry creation to that thread. Other threads
will be blocked until the delegated thread creates a service entry and loads the driver (by calling
`LOAD_NATIVE_MODULE`).
7. If user app gets SUCCESS, it proceeds to call `LOAD_NATIVE_MODULE` by passing the module handle that was provided
by ebpfcore.
8. Once the module is loaded, threads that were blocked earlier for `GET_NATIVE_MODULE_HANDLE` will be unblocked.
9. Apps can then call `LOAD_NATIVE_MODULE_PROGRAMS` to load multiple instances of programs from the native module.
10. If an app calls `GET_NATIVE_MODULE_HANDLE` while the native module is being unloaded, it will block until the
driver has been unloaded. Once the driver has been unloaded, the thread will be unblocked and will get
`EBPF_SERVICE_NOT_PRESENT` return code.
11. If the delegated app that was creating the service crashes, that will cause the module handle to be closed. Closing
the handle will give an indication to ebpfcore to choose one of the other waiting threads (if any) to create the service
entry and load the driver.

**Note**: In this option, the application can simply pass the driver name (with absolute or relative path) to libbpf /
eBPF API and ebpfapi.dll can internally generate a unique service name.

#### `GET_NATIVE_MODULE_HANDLE` Design:
1. UM will pass the service name. ebpfcore looks for the module based on the service name.
2. If ebpfcore does not find the module, it does the following:
    1. Generate a GUID for the client.
    2. Create a placeholder native module and add it to hash tables.
    3. Populate the service path (created by appending the service name to path prefix), and the module ID in the
    native module.
    4. Return the module HANDLE, module ID and return code `EBPF_SERVICE_NOT_PRESENT`.
3. If runtime finds the module, and it not in "unloading" state, it will return a new handle to module.
4. If runtime finds the module, and it is in "placeholder" state, it will block on an event, which will be set when the
module is loaded.
5. If runtime finds the module, and it is in "unloading" state, it will block on another event, which will be set when
call to driver unload returns. Once this event is set, this thread will be unblocked and move to step 2.

#### Misc. Changes
1. ebpfcore will now maintain 2 hash tables to look up the native modules. One hash table has service name as key, and
another has module ID as key.
2. Currently native module is deleted from hash table when ref count becomes 0, which is before the driver is unloaded.
In this new design the native module should be deleted from the hash table only when the driver unload call has
completed. Also, we need to ensure that driver unload happens inline.

### Option 2
Another approach is to completely skip all the above synchronization logic in ebpfcore and ebpfapi.dll, and separate
out service install / uninstall completely from the scope of the application. Native modules will be installed by some
installer that installs the native module on the system. Once that is done, programs can be loaded / unloaded multiple
times, without the need of install / uninstall of service entries.

Changes needed to implement this:
1. Installer installs the service entry. We need to ensure the service name is unique. Two native modules with same
name but in different locations should be installed as 2 different services. Installer also populates the client module
ID registry key with a random GUID.
2. The app that loads the program will pass the service name to ebpfapi (TBD: How does app know the service name for its
service). We can still use the existing `bpf_object__open` API, and the API can take the service name instead of file
name as input.

**Note**:
1. If we want to continue using existing APIs without any change, it causes a limitation that with this approach,
**every application / product** using a native eBPF program will need to implement the installer logic.
2. Since this approach requires multiple components to generate the service name for the sys file, one option can be to
export an API from ebpfapi.dll that takes file name as input and generates and returns a service name for that file.

## Native Module Changes
This section captures the changes needed to support multiple instances of program in native module driver.

1. Update BPF2C to generate code for each program to take a `runtime_context` as input. This runtime context will
contain the map and helper addresses.
2. Changes in ebpfcore to create the `runtime_context` when the program is loaded, and pass this context to the
program whenever it is invoked.

## Backward Compatibility
To ensure backward compatibility with the older native modules, following changes are needed:

1. Update the generated code for each program to take a "runtime_context" as input. This runtime context will contain the map and helper addresses.
2. Add a new "version" section in the PE image which can then be read by ebpfapi.dll, to figure out which path to take - old or new.
