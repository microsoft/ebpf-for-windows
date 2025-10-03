This document contains information about diagnostic tools and outputs used for debugging and diagnosing eBPF issues.

--------------------

- [WFP State](#wfp-state)
- [bpftool](#bpftool)
- [eBPF Diagnostic Traces](#ebpf-diagnostic-traces)
  - [Trace Providers](#trace-providers)
  - [Logman Trace Command](#logman-trace-command)
  - [Decoding Traces](#decoding-traces)
  - [Viewing Traces](#viewing-traces)

--------------------

## WFP State

netebpfext.sys uses the Windows Filtering Platform (WFP) to implement certain eBPF program types. Depending on the
program and attach type, different WFP objects are expected to be created.

The following program types rely on WFP:
- BPF_PROG_TYPE_BIND
- BPF_PROG_TYPE_CGROUP_SOCK_ADDR
- BPF_PROG_TYPE_SOCK_OPS

Use the command `netsh wfp show state` to produce a `wfpstate.xml`. This file shows the WFP state on the system,
including all WFP `sublayer`, `callout`, and `filter` objects. This can be used to determine if eBPF objects are
correctly configured or if there are other callout objects present that may interfere with eBPF behavior.

--------------------
## bpftool

`bpftool.exe` can be used to show eBPF object state. This is useful when checking if your eBPF program is loaded,
attached, and any maps used are properly configured.

--------------------

## eBPF Diagnostic Traces

For some issues, Event Trace Logs (ETL) are necessary to further root cause and resolve the issue.

--------------------

### Trace Providers

- `NetEbpfExtProvider`
    - {f2f2ca01-ad02-4a07-9e90-95a2334f3692}
    - This provider is part of the eBPF platform. This traces content from NetEbpfExt.sys.
- `EbpfForWindowsProvider`
    - {394f321c-5cf4-404c-aa34-4df1428a7f9c}
    - This provider is part of the eBPF platform. This traces content from ebpfCore.sys.
- `Microsoft.Windows.Networking.WFP.Callout`
    - {00e7ee66-5b24-5c41-22cb-af98f63e2f90}
    - This provider is part of the Windows OS. This traces content from WFP callout actions.

--------------------

### Logman Trace Command

You can use the following trace commands to collect traces. This uses maximum verbosity:
```
logman create trace "ebpf_diag_manual" -o C:\ebpf_trace.etl -f bincirc -max 1024 -ets
logman update trace "ebpf_diag_manual" -p "{f2f2ca01-ad02-4a07-9e90-95a2334f3692}" 0xffffffffffffffff 0xff -ets
logman update trace "ebpf_diag_manual" -p "{394f321c-5cf4-404c-aa34-4df1428a7f9c}" 0xffffffffffffffff 0xff -ets
logman update trace "ebpf_diag_manual" -p "{00e7ee66-5b24-5c41-22cb-af98f63e2f90}" 0xffffffffffffffff 0xff -ets

<repro>

logman stop "ebpf_diag_manual" -ets
```

--------------------

### Decoding Traces

Once you have the `.etl` file captured with the above providers, you will need to first decode the traces before viewing
them.

One method for decoding traces is to use the `netsh` tool. The following command can be used for decoding:
```
netsh trace convert <etl file>
```

--------------------

### Viewing Traces
Once decoded, you can open the file with any text viewing tool. One option for viewing text files is:
https://textanalysistool.github.io/

--------------------