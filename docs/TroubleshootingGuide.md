This document contains a troubleshooting guide for issues related to eBPF.

--------------------

# What Kind of Issue Are You Having ?

- [A specific eBPF program is failing verification](./debugging.md)
- [The eBPF program is not getting invoked](#troubleshooting-general-ebpf-program-issues)
- [A specific eBPF program is not behaving as expected](#troubleshooting-issues-related-to-a-specific-program-type)

--------------------

# Troubleshooting General eBPF Program Issues

If the eBPF program is not getting invoked at all, walk through the following steps to determine where the issue is and
resolve it:

1. [Verify eBPF components are running](#verify-ebpf-components-are-running)
2. [Verify Windows Filtering Platform (WFP) objects are present](#verify-wfp-objects-are-present)
3. [Verify the eBPF Program is Configured Correctly](#verify-the-ebpf-program-is-configured-correctly)

--------------------

## Verify eBPF Components Are Running

Verify that the necessary services are running. Run the following commands:
```
sc.exe queryex netebpfext
sc.exe queryex ebpfcore
```
We expect to see the following output, notably that the service is in the **Running** state:
```
SERVICE_NAME: ebpfcore
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 0
        FLAGS              :
```

**Mitigation:** For each service that is not running, execute:
```
sc.exe start netebpfext
sc.exe start ebpfcore
```

If the problem persists, obtain the `SERVICE_EXIT_CODE` and look at the
[eBPF diagnostic traces](./Diagnostics.md#ebpf-diagnostic-traces) for further diagnosis.

--------------------

## Verify WFP objects are present
netebpfext.sys uses the WFP platform to implement certain eBPF program types. If you are observing issues with the eBPF
program not getting invoked at all, you should check if the necessary WFP objects are present.

Depending on the program and attach type, different WFP objects are expected to be created. You can use the
[WFP state diagnostic file](./Diagnostics.md#wfp-state) to confirm that the necessary objects are present.

There are a few different WFP object types. Depending on the program type, you should check for specific instances of
each WFP object.
- `sublayer` object. Depending on the program type, a different `sublayerKey` may be expected. Note that the `weight`
  field may be different in the expected output than on your device, and it is not an issue if it is different.
- `callout` object. You should check that the `applicableLayer` of this object matches the expected output for the
  program type.
- `filter` object. When looking for the expected `filters` check for the following:
    - The `layerKey` matches the expected output.
    - The `sublayerKey` matches the `sublayerKey` in the expected output.
    - The `filterType` has the same GUID as the `calloutKey` in the `callout` object.

Note that the `calloutId` and `filterId` fields are NOT constant and are expected to change. Instead, use the
`calloutKey` and `filterKey` values to uniquely identify these objects.

The below section details the specific expected WFP objects for each program type.

**Mitigation**: If any of the expected objects are not present or incorrect, attempt mitigation by restarting both
`ebpfcore` and `netebpfext`:
```
sc.exe stop ebpfcore
sc.exe stop netebpext
sc.exe start ebpfcore
sc.exe start netebpfext
```

If the objects are still not present, check the [eBPF diagnostic traces](./Diagnostics.md#ebpf-diagnostic-traces) for
any errors.

**Next Steps**: If you have verified that the WFP objects are present, but the eBPF progarm is still not getting
invoked, see [troubleshooting eBPF program issues](#Troubleshooting-general-eBPF-Program-Issues).

--------------------

### Expected WFP objects for the program type BPF_PROG_TYPE_CGROUP_SOCK_ADDR
The following are the expected `sublayer` objects for this program type:
```xml
<item>
    <subLayerKey>{7c7b3fb9-3331-436a-98e1-b901df457fff}</subLayerKey>
    <displayData>
    <name>EBPF Sub-Layer</name>
    <description>Sub-Layer for use by eBPF callouts</description>
    </displayData>
    <flags/>
    <providerKey/>
    <providerData/>
    <weight>8</weight>
</item>
<item>
    <subLayerKey>{98849e12-b07d-11ec-9a30-18602489beee}</subLayerKey>
    <displayData>
    <name>EBPF CGroup Connect V4 Sub-Layer</name>
    <description>Sub-Layer for use by eBPF connect redirect callouts</description>
    </displayData>
    <flags/>
    <providerKey/>
    <providerData/>
    <weight>9</weight>
</item>
<item>
    <subLayerKey>{98849e13-b07d-11ec-9a30-18602489beee}</subLayerKey>
    <displayData>
    <name>EBPF CGroup Connect V6 Sub-Layer</name>
    <description>Sub-Layer for use by eBPF connect redirect callouts</description>
    </displayData>
    <flags/>
    <providerKey/>
    <providerData/>
    <weight>10</weight>
</item>
```

For eBPF programs using the `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` program type and attached at the
`EBPF_ATTACH_TYPE_CGROUP_INET4_CONNECT` hook, we expect a `callout` and `filter` present in the following layers:
1. `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4`
2. `FWPM_LAYER_ALE_CONNECT_REDIRECT_V6`
3. `FWPM_LAYER_ALE_AUTH_CONNECT_V4`

In this scenario, the `FWPM_LAYER_ALE_CONNECT_REDIRECT_V6` layer objects are necessary due to the way the WFP stack
handles dual-stack sockets.

This is the expected `callout` and `filter` at the `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4` layer:
```xml
<item>
    <calloutKey>{98849e0f-b07d-11ec-9a30-18602489beee}</calloutKey>
    <displayData>
        <name>ALE Connect Redirect eBPF Callout v4</name>
        <description>ALE Connect Redirect callout for eBPF</description>
    </displayData>
    <flags numItems="1">
        <item>FWPM_CALLOUT_FLAG_REGISTERED</item>
    </flags>
    <providerKey/>
    <providerData/>
    <applicableLayer>FWPM_LAYER_ALE_CONNECT_REDIRECT_V4</applicableLayer>
    <calloutId>300</calloutId>
</item>
<item>
    <filterKey>{d18b796a-2018-408e-af4a-ac1978b5a364}</filterKey>
    <displayData>
        <name>net eBPF sock_addr hook</name>
        <description>net eBPF sock_addr hook WFP filter</description>
    </displayData>
    <flags/>
    <providerKey/>
    <providerData/>
    <layerKey>FWPM_LAYER_ALE_CONNECT_REDIRECT_V4</layerKey>
    <subLayerKey>{7c7b3fb9-3331-436a-98e1-b901df457fff}</subLayerKey>
    <weight>
        <type>FWP_EMPTY</type>
    </weight>
    <filterCondition/>
    <action>
        <type>FWP_ACTION_CALLOUT_TERMINATING</type>
        <filterType>{98849e0f-b07d-11ec-9a30-18602489beee}</filterType>
    </action>
    <rawContext>18446603911448051536</rawContext>
    <reserved/>
    <filterId>68591</filterId>
    <effectiveWeight>
    <type>FWP_UINT64</type>
    <uint64>0</uint64>
    </effectiveWeight>
</item>
```

This is the expected `callout` and `filter` at the `FWPM_LAYER_ALE_CONNECT_REDIRECT_V6` layer:
```xml
<item>
    <calloutKey>{98849e10-b07d-11ec-9a30-18602489beee}</calloutKey>
    <displayData>
        <name>ALE Connect Redirect eBPF Callout v6</name>
        <description>ALE Connect Redirect callout for eBPF</description>
    </displayData>
    <flags numItems="1">
        <item>FWPM_CALLOUT_FLAG_REGISTERED</item>
    </flags>
    <providerKey>{ddb851f5-841a-4b77-8a46-bb7063e9f162}</providerKey>
    <providerData/>
    <applicableLayer>FWPM_LAYER_ALE_CONNECT_REDIRECT_V6</applicableLayer>
    <calloutId>279</calloutId>
</item>
<item>
    <filterKey>{162acb09-0cd9-4b80-b7a7-bdd653cca03a}</filterKey>
    <displayData>
        <name>net eBPF sock_addr hook</name>
        <description>net eBPF sock_addr hook WFP filter</description>
    </displayData>
    <flags/>
    <providerKey>{ddb851f5-841a-4b77-8a46-bb7063e9f162}</providerKey>
    <providerData/>
    <layerKey>FWPM_LAYER_ALE_CONNECT_REDIRECT_V6</layerKey>
    <subLayerKey>{98849e12-b07d-11ec-9a30-18602489beee}</subLayerKey>
    <weight>
        <type>FWP_EMPTY</type>
    </weight>
    <filterCondition/>
    <action>
        <type>FWP_ACTION_CALLOUT_TERMINATING</type>
        <filterType>{98849e10-b07d-11ec-9a30-18602489beee}</filterType>
    </action>
    <rawContext>18446624845314639248</rawContext>
    <reserved/>
    <filterId>68246</filterId>
    <effectiveWeight>
    <type>FWP_UINT64</type>
    <uint64>0</uint64>
    </effectiveWeight>
</item>
</filters>
```

This is the expected `callout` and `filter` at the `FWPM_LAYER_ALE_AUTH_CONNECT_V4` layer:
```xml
<item>
    <calloutKey>{98849e0b-b07d-11ec-9a30-18602489beee}</calloutKey>
    <displayData>
        <name>ALE Authorize Connect eBPF Callout v4</name>
        <description>ALE Authorize Connect callout for eBPF</description>
    </displayData>
    <flags numItems="1">
        <item>FWPM_CALLOUT_FLAG_REGISTERED</item>
    </flags>
    <providerKey>{ddb851f5-841a-4b77-8a46-bb7063e9f162}</providerKey>
    <providerData/>
    <applicableLayer>FWPM_LAYER_ALE_AUTH_CONNECT_V4</applicableLayer>
    <calloutId>274</calloutId>
</item>
<item>
    <filterKey>{f202cbe9-da2b-41bc-8db0-b25a799531b5}</filterKey>
    <displayData>
        <name>net eBPF sock_addr hook</name>
        <description>net eBPF sock_addr hook WFP filter</description>
    </displayData>
    <flags/>
    <providerKey>{ddb851f5-841a-4b77-8a46-bb7063e9f162}</providerKey>
    <providerData/>
    <layerKey>FWPM_LAYER_ALE_AUTH_CONNECT_V4</layerKey>
    <subLayerKey>{7c7b3fb9-3331-436a-98e1-b901df457fff}</subLayerKey>
    <weight>
        <type>FWP_EMPTY</type>
    </weight>
    <filterCondition/>
    <action>
        <type>FWP_ACTION_CALLOUT_TERMINATING</type>
        <filterType>{98849e0b-b07d-11ec-9a30-18602489beee}</filterType>
    </action>
    <rawContext>18446624845314639248</rawContext>
    <reserved/>
    <filterId>68244</filterId>
    <effectiveWeight>
    <type>FWP_UINT64</type>
    <uint64>0</uint64>
    </effectiveWeight>
</item>
```

--------------------

## Verify the eBPF Program is Configured Correctly

1. [Verify the eBPF program passes the verifier](./debugging.md)
2. [Verify the eBPF program is loaded](#verify-the-ebpf-program-is-loaded)
3. [Verify the eBPF program is attached](#verify-the-ebpf-program-is-attached)
4. [Resolve eBPF Program Load or Attach Failures](#ebpf-program-load-or-attach-failures)
5. [Verify eBPF maps are properly configured](#verify-ebpf-maps-are-properly-configured)

--------------------

### Verify the eBPF Program is Loaded

To check that the eBPF program is loaded, execute:
```
bpftool.exe -p prog
```
In this output, check that you see the expected eBPF program, looking at the `name` and `type`. Take note of the `id`
and `map_ids` for the next set of checks.

Example Output:
```json
[{
    "id": 196867,
    "type": "sock_addr",
    "name": "authorize_connect4",
    "map_ids": [66054,131331]
}]
```

--------------------

### Verify the eBPF Program is Attached

To check that the eBPF program is attached, execute:
```
bpftool.exe -p link
```
In this output, check for an entry with the `prog_id` which matches the `id` from the above output, and confirm that
the `attach_type` is as expected.

Example output:
```json
[{
    "id": 262403,
    "type": 2,
    "prog_id": 196867,
    "cgroup_id": 0,
    "attach_type": "cgroup/connect4"
}]
```

--------------------

### Verify eBPF Maps are Properly Configured

To check the map content, execute:
```
bpftool.exe -p map show id <id>
```
In this output, use the `map_ids` from the above output. Map usage is up to the eBPF program developer, so you should
confirm that the `type` and `name` is as expected for the scenario. This example output is from invoking the bpftool
for each map:
```json
{
    "id": 66054,
    "type": "hash",
    "name": "policy_map",
    "flags": 0,
    "bytes_key": 24,
    "bytes_value": 24,
    "max_entries": 10
}

{
    "id" : 131331,
    "type" : "lru_hash",
    "name" : "audit_map",
    "flags" : 0,
    "bytes_key" : 8,
    "bytes_value" : 24,
    "max_entries" : 1000
}
```

Once you have confirmed that the expected maps are present, you can then dump the map entries and check that the values
are as expected. You will need the `map_ids` from above. Then, you can execute the following command:
```
bpftool.exe map dump id <id>
```

Example Output:
```
key:
08 08 08 08 00 00 00 00  00 00 00 00 00 00 00 00
1a 0a 00 00 06 00 00 00
value:
7f 00 00 01 00 00 00 00  00 00 00 00 00 00 00 00
15 b3 00 00 00 00 00 00
Found 1 element
```

The map usage is up to the eBPF program developer. You should follow up with the developer to understand what
structures are used in the map and how you can use this output to verify that the map entries are populated correctly.

--------------------

### eBPF Program Load or Attach Failures

Once you have [identified that the program is not attached or loaded](#troubleshooting-general-ebpf-program-issues),
you should first confirm that the eBPF client has attempted to load and attach the program (i.e, there were no issues
within the eBPF client itself). If you have confirmed that the eBPF client has attempted to load/attach the program,
but it has failed, you can use the following to further debug your issue.

The common flow for configuring a eBPF program would be to first `open` the program, then `load` the program, and
finally, `attach` the program. For each of these operations, you can look for a trace statement within the
[eBPF diagnostic traces](./Diagnostics.md#ebpf-diagnostic-traces) which indicates failure:
- Open: Look for a trace with `ebpf_object_open`
- Load: Look for a trace with `ebpf_object_load`
- Attach: Look for a trace with `ebpf_program_attach_by_fd`

There are a few classes of known issues:

**eBPF Client Issues**

There are certain errors that likely point to the eBPF client. These errors will be present in
[eBPF diagnostic traces](./Diagnostics.md#ebpf-diagnostic-traces):
- `ERROR_ACCESS_DENIED` or `STATUS_ACCESS_DENIED`. This means that the user-mode application is not running as admin or
  localsystem. This points to an issue with the application. The resolution here is to run the user-mode application or
  service as localsystem or admin.
- `ERROR_FILE_NOT_FOUND`. This indicates that the application tried to open an eBPF program with an invalid path. This
  points to an issue within the application. The resolution is to change the path used by the application.

- `ERROR_INVALID_PARAMETER`. The trace shows `Program type` GUID is zero. Hence `ebpf_program_create` failed. The subsequent traces show `'An invalid parameter was passed to a service or function'` and `'The parameter is incorrect'` indicating that the user-mode application failed to set a valid program type in the eBPF program.
   ```
   [2]1C10.1B78::2023/06/23-19:45:16.265726200 [EbpfForWindowsProvider]{"Message":"Program type must be specified.","*guid":"{00000000-0000-0000-0000-000000000000}","meta":{"provider":"EbpfForWindowsProvider","event":"EbpfGenericMessage","time":"2023-06-24T02:45:16.2657262Z","cpu":2,"pid":7184,"tid":7032,"channel":11,"level":2,"keywords":"0x80"}}

   [2]1C10.1B78::2023/06/23-19:45:16.265726800 [EbpfForWindowsProvider]{"ErrorMessage":"ebpf_program_create returned error","Error":6,"meta":{"provider":"EbpfForWindowsProvider","event":"EbpfGenericError","time":"2023-06-24T02:45:16.2657268Z","cpu":2,"pid":7184,"tid":7032,"channel":11,"level":2,"keywords":"0x2"}}

   [2]1C10.1B78::2023/06/23-19:45:16.265740500 [EbpfForWindowsProvider]{"Api":"\"ebpf_core_invoke_protocol_handler\"","status":"0xC000000D(NT=An invalid parameter was passed to a service or function.)","meta":{"provider":"EbpfForWindowsProvider","event":"EbpfApiError","time":"2023-06-24T02:45:16.2657405Z","cpu":2,"pid":7184,"tid":7032,"channel":11,"level":2,"keywords":"0x4"}}

   [2]1C10.1B78::2023/06/23-19:45:16.265779400 [EbpfForWindowsProvider]{"Api":"DeviceIoControl","last_error":"87(WIN=The parameter is incorrect.)","meta":{"provider":"EbpfForWindowsProvider","event":"EbpfApiError","time":"2023-06-24T02:45:16.2657794Z","cpu":2,"pid":7184,"tid":7032,"channel":11,"level":2,"keywords":"0x100"}}
   ```

**NMR Attach Failures**

Another possibility is NMR attach failing. When this occurs, you may see error traces in
[eBPF diagnostic traces](./Diagnostics.md#ebpf-diagnostic-traces).
- `Invalid Program or Attach type`
    ```
    [1]48D498.48D750::2023/07/18-18:49:07.123107000 [EbpfForWindowsProvider]{"Message":"Program type and Attach type:","*guid1":"{f1832a85-85d5-45b0-98a0-7069d63013b0}","*guid2":"{00000000-0000-0000-0000-000000000000}","meta":{"provider":"EbpfForWindowsProvider","event":"EbpfGenericMessage","time":"2023-07-19T01:49:07.1231070Z","cpu":1,"pid":4773016,"tid":4773712,"channel":11,"level":4,"keywords":"0x80"}}

    [1]48D498.48D750::2023/07/18-18:49:07.123122800 [EbpfForWindowsProvider]{"ErrorMessage":"ebpf_program_create returned error","Error":23,"meta":{"provider":"EbpfForWindowsProvider","event":"EbpfGenericError","time":"2023-07-19T01:49:07.1231228Z","cpu":1,"pid":4773016,"tid":4773712,"channel":11,"level":2,"keywords":"0x2"}}

    [1]48D498.48D750::2023/07/18-18:49:07.123127100 [EbpfForWindowsProvider]{"Api":"\"ebpf_core_invoke_protocol_handler\"","status":"0xC000026C(NT=Unable to Load Device Driver)","meta":{"provider":"EbpfForWindowsProvider","event":"EbpfApiError","time":"2023-07-19T01:49:07.1231271Z","cpu":1,"pid":4773016,"tid":4773712,"channel":11,"level":2,"keywords":"0x4"}}

    [1]48D498.48D750::2023/07/18-18:49:07.123136900 [EbpfForWindowsProvider]{"Api":"DeviceIoControl","last_error":"2001(WIN=The specified driver is invalid.)","meta":{"provider":"EbpfForWindowsProvider","event":"EbpfApiError","time":"2023-07-19T01:49:07.1231369Z","cpu":1,"pid":4773016,"tid":4773712,"channel":11,"level":2,"keywords":"0x100"}}
    ```

    Check the Program type's GUID and Attach type's GUID in the trace. Program type and Attach type must have valid GUIDs as listed in [ebpf_program_attach_type_guids.h](https://github.com/microsoft/ebpf-for-windows/blob/main/include/ebpf_program_attach_type_guids.h).

    The first trace shows the `Program type` GUID is valid but the `Attach type` GUID is zero. Hence `ebpf_program_create` failed. The subsequent traces show `'Unable to Load Device Driver'` and `'The specified driver is invalid'` indicating that this is an NMR failure due to an invalid attach type.


    **Mitigation**: If you observe NMR failures, you can attempt to restart `netebpfext` and `ebpfcore`:
    ```
    sc.exe stop ebpfcore
    sc.exe stop netebpext
    sc.exe start ebpfcore
    sc.exe start netebpfext
    ```
    Note: If `ebpfcore` fails to stop, you can attempt to restart `ebpfsvc` and then `ebpfcore`.

    Then, attempt to load the program again. If this continues to fail, check your eBPF program source code to see if it has incorporated a valid program type and attach type. If the problem still persists, you will need to look further in
    [eBPF diagnostic traces](./Diagnostics.md#ebpf-diagnostic-traces).

--------------------

# Troubleshooting Issues Related to a Specific Program Type

- [Program Type BPF\_PROG\_TYPE\_CGROUP\_SOCK\_ADDR Issues](#program-type-bpf_prog_type_cgroup_sock_addr-issues)

--------------------
## Program Type BPF_PROG_TYPE_CGROUP_SOCK_ADDR Issues

The following are common issues with programs attached at the `BPF_CGROUP_INET4_CONNECT` or `BPF_CGROUP_INET6_CONNECT`
hook:
- [The eBPF program redirects traffic, but it is not working as expected.](#traffic-is-not-redirected-as-expected)

--------------------

### Traffic Is Not Redirected As Expected

If you are attaching your program at the `BPF_CGROUP_INET4_CONNECT` or `BPF_CGROUP_INET6_CONNECT` hooks, you can
redirect traffic to a different target IP address. Use the guidance below if the traffic is not getting redirected as
you expect.

Ensure that you have [verified the program is configured correctly](#verify-the-ebpf-program-is-configured-correctly),
notably, checking that any expected map usage is correctly configured.

Once you have confirmed that the program and any maps used are correctly configured, the next thing to look for is
whether or not the eBPF platform is performing the redirection. In the
[eBPF diagnostic traces](./Diagnostics.md#ebpf-diagnostic-traces), you should look for the following trace:
```
[3]10A8.0A54::2023/04/28-10:31:41.312214200 [NetEbpfExtProvider]{"Message":"connect_redirect_classify",
"TransportEndpointHandle":463,"Protocol":6,"src_ip":"0.0.0.0","src_port":51346,"dst_ip":"8.8.8.8","dst_port":6666,
"redirected_ip":"127.0.0.1","redirected_port":5555,"Verdict":1,"meta":{"provider":"NetEbpfExtProvider","event":
"NetEbpfExtGenericMessage","time":"2023-04-28T17:31:41.3122142Z","cpu":3,"pid":4264,"tid":2644,"channel":11,"level":4,
"keywords":"0x20"}}
```

From this trace, you should look at the IP properties of the original connection (`src_ip`, `src_port`, `dst_ip`, and
`dst_port`) and also of the redirected remote address (`redirected_ip` and `redirected_port`). Note that the `src_ip`
value may be `0.0.0.0`, which is expected, as the source address may not be identified at the time of connect redirection.
There may be a few cases after looking for this trace:
1. This trace is present, but the IP properties are not as expected. In this case, please
   [verify eBPF maps are properly configured](#verify-ebpf-maps-are-properly-configured).
2. This trace is present and has the expected IP properties, but traffic is still not reaching the proxy. Please
   [check for interoperability issues with another WFP callout](#interoperability-issues-with-another-wfp-callout).
3. This trace is not present at all. First, check the [eBPF diagnostic traces](./Diagnostics.md#ebpf-diagnostic-traces)
   to identify if there were any issues within the callout itself. If there are no errors in this codepath,
   [check for interoperability issues with another WFP callout](#interoperability-issues-with-another-wfp-callout).

--------------------

#### Interoperability Issues With Another WFP Callout

Multiple WFP callouts at the connect redirect layer may cause unexpected results. This may surface as one of the
following symptoms:
1. The connection is not reaching the proxy. This can happen both even when the eBPF callout is getting invoked, but
   also when it does not get invoked.
2. The connection reaches the proxy, but does not reach the expected final destination.
3. Kernel crash

To check if there is another WFP callout at the connect redirect layer, you should search in the
[WFP state diagnostic file](./Diagnostics.md#wfp-state) for the string `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4` (or `V6`,
if applicable). Within this layer, you can look in the `callouts` section of the file. We expect to see only 1 eBPF
callout here. If you see more than 1, then another WFP callout driver may be attempting to redirect the same connections
that your eBPF program is, which may affect the final connection.

Sample output:
```xml
<callouts numItems="2">
    <item>
        <calloutKey>{98849e0f-b07d-11ec-9a30-18602489beee}</calloutKey>
        <displayData>
            <name>ALE Connect Redirect eBPF Callout v4</name>
            <description>ALE Connect Redirect callout for eBPF</description>
        </displayData>
        <flags numItems="1">
            <item>FWPM_CALLOUT_FLAG_REGISTERED</item>
        </flags>
        <providerKey/>
        <providerData/>
        <applicableLayer>FWPM_LAYER_ALE_CONNECT_REDIRECT_V4</applicableLayer>
        <calloutId>300</calloutId>
    </item>
    <item>
        <calloutKey>{c2a93a3e-cff4-5339-be53-21365ba19f35}</calloutKey>
        <displayData>
            <name>Another Connect Redirect callout</name>
            <description/>
        </displayData>
        <flags numItems="2">
            <item>FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT</item>
            <item>FWPM_CALLOUT_FLAG_REGISTERED</item>
        </flags>
        <providerKey/>
        <providerData/>
        <applicableLayer>FWPM_LAYER_ALE_CONNECT_REDIRECT_V4</applicableLayer>
        <calloutId>316</calloutId>
    </item>
</callouts>
```

**Mitigation:** If there are any issues observed and multiple WFP callouts are identified, it is recommended to
uninstall or disable the other WFP callouts. Note that the `name` field in the `wfpstate` output may differ from the
actual driver or product name.

--------------------
