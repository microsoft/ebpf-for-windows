Extensible maps are program type specific maps that will be implemented by the extension that is implementing the program type (program info provider). This document contains the proposal for implementing support for extensible / program type specific maps in eBPF-for-Windows. The below sections describe all the scenarios / areas that will need to be updated or tested for this new map type.

### Map Id partitioning
Global maps get an ID for their map types from a global namespace. There are two possible options for how we can allocate IDs for map types for extensible maps.

**Option 1: Global Map IDs**
- The map type IDs are allocated from a global namespace. This will be disjoint from the namespace for global maps. Global maps will use IDs from 1 to 4095. Extensible maps will use IDs 4096 onwards.
- Each program info provider that implements a extensible map will need to register / reserve the MAP ID / enum in the eBPF repo by creating a PR.

**Option 2: Per-program map ID space**
- Just like program type specific helper functions, each program type can define map type IDs, and these can be overlapping.
- This has a problem though -- Existing user mode APIs to create a map can then not be used, as program type for the map cannot be disambiguated by just the map type. This will require a new eBPF map create API that will also take the corresponding program type (GUID or ID)

**Proposal**
Use option 1 as it allows keeping the user mode API for map creation same as on Linux, only adding a one-time step for extension developers to reserve the map ID in the global namespace (by creating a PR in eBPF repo).

### NMR interface for extensions
The NMR interface for program info provider will extended (non-breaking) and extensions will provide below information:
 - List of extensible map types it is supporting
 - APIs for
   - Map creation / map deletion
   - Map lookup, update, delete.

### eBPF Store
- Program info providers will now include the map types they are going to support when updating eBPF store. This should include the map type string, and the map type ID.
- eBPF store APIs will be updated to populate this information also in the registry.
- ebpfapi when loading will read the extensible map type information and create a in-memory map for `map-type : program type`.
- This will be used when explicitly creating map from user mode.

### Verfication
- For offline verification, eBPF store will be used to provide map information to the verfier.
- For online verification (JIT / interpret), map type to program type conversion will be done using eBPF store data. Then ebpfsvc will query ebpfcore to get program information which will also provide map information.


#### Map lifecycle
Even though the extensible map will be created by and reside in the extension, ebpfcore will also create a corresponding map entry, as it does for the global maps. The difference being, in case of extensible maps, the map CRUD APIs will be supplied by the extension, and map entry in ebpfcore will contain these function pointers provided by the extension.

Map lifetime will also be maintained by eBPFcore, and it will invoke extension's map delete API when the map needs to be finally deleted.
Similarly, map pinning will also be handled by eBPFcore as that impacts map lifetime.

Another thing to note is that once an extensible map is created, the corresponding extension cannot be allowed to unload / restart, as that will delete the map and its entries. This will be a limitation / restriction for the extension that is implementing extensible maps, and may impact their servicing flow.

### Map creation
Assuming option 1 for `Map ID partitioning`, below is the expected flow for map creation.

#### Explicit map creation
- App uses the existing map create APIs, and internally ebpfapi tries to find the corresponding program type from the eBPF store.
- Once it finds the program info provider, it makes a (new) ioctl call to create the extensible map, and also pass the program type.
- eBPFcore will first attach (NMR) to this provider, and check if the actual provider supports this map type. If yes, proceed to create map in the extension.

Implicit map creation flow will also be similar. ebpf runtime will have similar flow for map creation, automatic map pinning, and map reuse.

### Usermode CRUD APIs
Assuming option 1 for `Map ID partitioning`, all existing APIs should be applicable for extensible maps too.

### Map helper functions
The existing map helper functions implemented by ebpfcore will be used by the BPF programs for extensible maps also. For extensible maps, ebpfcore will redirect the calls to the extension.

### Exposing RCU semantics to extensions
For extensions to implement maps, they will need RCU support, and eBPF needs to expose RCU / epoch logic to extensions.

There are two options for this:

**Export RCU as lib**
- This will simplify logic in eBPFCore
- Extensions will have their own RCU "runtime"
- This approach will require recompilation and release from extension if there is a bug in RCU lib.

**Export RCU APIs via NMR interface**
- Probably adds more complexity to ebpfcore.
- Does not require new release from extensions wheenver there is a bugfix in RCU logic.

**Proposal**
Proposal here is to export RCU as lib.

## Perf Consideration
Since map APIs for extensible maps will have logner path length, we should measure perf for extensible map operations.
