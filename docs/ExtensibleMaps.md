# Introduction

Extensible maps are program type specific maps that will be implemented by the extension that is implementing the program type (program info provider). This document describes the design for the support for extensible / program type specific maps in eBPF-for-Windows. The below sections describe all the scenarios / areas that will need to be updated or tested for this new map type.

## Map Id partitioning
Global maps get an ID for their map types from a global namespace. The map type IDs are allocated from a global namespace. This will be disjoint from the namespace for global maps. Global maps will use IDs from 1 to 4095. Extensible maps will use IDs 4096 onwards.
- Each program info provider that implements a extensible map will need to register / reserve the MAP ID / enum in the eBPF repo by creating a PR.

## NMR interface for extensions
1. Add a new NMR interface for extensions to register as providers if they are implementing an extensible map. ebpfcore will be the NMR client.
2. As part of the NPI attach, the extensions will provide the list of all the map types they support.
3. Extension will also provide a dispatch table for map create, map elem lookup, map elem update, map delete elem, and map delete.
4. The dispatch table will also have a function to validate if this map can be associated with a specific program type.

## eBPFCore Changes / Flow
1. ebpfcore will create a new map struct ebpf_extended_map_t which will contain ebpf_core_map_t. The new struct will contain a dispatch table 
2. ebpfcore will implement code to register as NMR client for the new NPI interface, and also a attach callback.
3. When the map is being directly created from user mode, following will be the flow:
   1. ebpfcore will check if the map type is more than BPF_MAP_TYPE_MAX. If yes, it will register a new client, and get callbacks from the providers. In attach callback, it will check if this extension implements the requested map type. If yes, accept the connection. if no, reject the connection request.
   2. Once attached to the provider:
     1. take a reference on the provider, to disallow it to be unloaded. 
     2. create ebpf_extended_map_t struct and populate the dispatch table.
     3. Call into the extension to create the map. This call should return a void pointer to the map, that will be stored in ebpf_extended_map_t struct.
4. In the flows when the map is being associated with a program, and the map is an extensible map, ebpfcore will call the dispatch function provided by the extension to check if the map type can be associated with the specified program type.



<!-- The NMR interface for program info provider will extended (non-breaking) and extensions will provide below information:
 - List of extensible map types it is supporting
 - APIs for
   - Map creation / map deletion
   - Map lookup, update, delete. -->

<!-- ## eBPF Store
- Program info providers will now include the map types they are going to support when updating eBPF store. This should include the map type string, and the map type ID.
- eBPF store APIs will be updated to populate this information also in the registry.
- ebpfapi when loading will read the extensible map type information and create a in-memory map for `map-type : program type`.
- This will be used when explicitly creating map from user mode.

## Verfication
- No impact on verfication (online or offline), as the verifier only cares about the actual map definitions. -->

## Map lifecycle
Even though the extensible map will be created by and reside in the extension, ebpfcore will also create a corresponding map entry, as it does for the global maps. The difference being, in case of extensible maps, the map CRUD APIs will be supplied by the extension, and map entry in ebpfcore will contain these function pointers provided by the extension.

Map lifetime will also be maintained by eBPFcore, and it will invoke extension's map delete API when the map needs to be finally deleted.
Similarly, map pinning will also be handled by eBPFcore as that impacts map lifetime.

Another thing to note is that once an extensible map is created, the corresponding extension **cannot be allowed to unload / restart**, as that will delete the map and its entries. This will be a limitation / restriction for the extension that is implementing extensible maps, and may impact their servicing flow.

<!-- ## Map creation
Assuming option 1 for `Map ID partitioning`, below is the expected flow for map creation.

### Explicit map creation
- App uses the existing map create APIs, and internally ebpfapi tries to find the corresponding program type from the eBPF store.
- Once it finds the program info provider, it makes a (new) ioctl call to create the extensible map, and also pass the program type.
- eBPFcore will first attach (NMR) to this provider, and check if the actual provider supports this map type. If yes, proceed to create map in the extension.

Implicit map creation flow will also be similar. ebpf runtime will have similar flow for map creation, automatic map pinning, and map reuse. -->

## Map CRUD APIs

### Usermode CRUD APIs
Assuming option 1 for `Map ID partitioning`, all existing APIs should be applicable for extensible maps too.

### Map helper functions
The existing map helper functions implemented by ebpfcore will be used by the BPF programs for extensible maps also. For extensible maps, ebpfcore will redirect the calls to the extension.

<!-- ## Exposing RCU semantics to extensions
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
Since map APIs for extensible maps will have logner path length, we should measure perf for extensible map operations. -->
