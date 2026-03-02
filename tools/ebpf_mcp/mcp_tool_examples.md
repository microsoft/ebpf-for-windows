# PREVAIL MCP Server — Query Examples

This document demonstrates the `prevail-verifier` MCP server's capabilities through
worked examples. Each example shows the tool call and its response.

The examples use two programs:
- **droppacket.o** (`x64/Debug/droppacket.o`) — a passing XDP program that filters UDP packets
- **nullmapref.o** (`tests/verifier_diagnosis/build/nullmapref.o`) — a failing program with a null pointer dereference
- **packet_reallocate.o** (`tests/verifier_diagnosis/build/packet_reallocate.o`) — a failing program with stale pointers
- **dependent_read.o** (`tests/verifier_diagnosis/build/dependent_read.o`) — a failing program with lost correlations

---

## 1. Quick Pass/Fail Check

```
verify_program: { "elf_path": "x64/Debug/droppacket.o" }
```

```json
{
  "passed": true,
  "error_count": 0,
  "exit_value": "[1, 2]",
  "function": "DropPacket",
  "section": "xdp",
  "instruction_count": 45
}
```

The program passes verification. The return value is proven to be in `[1, 2]`
(XDP_PASS or XDP_DROP — no other values possible).

---

## 2. Failure Summary with Source Line

```
verify_program: { "elf_path": "tests/verifier_diagnosis/build/nullmapref.o" }
```

```json
{
  "passed": false,
  "error_count": 1,
  "first_error": {
    "pc": 7,
    "message": "Possible null access (valid_access(r0.offset, width=4) for write)",
    "source": {
      "file": "...nullmapref.c",
      "line": 23,
      "source": "    *value = 1; // BUG: value may be NULL"
    }
  }
}
```

One error: null pointer dereference at line 23. The source annotation shows exactly
which C statement failed.

---

## 3. One-Call Diagnosis with Failure Slice

```
get_slice: {
  "elf_path": "tests/verifier_diagnosis/build/nullmapref.o",
  "trace_depth": 3
}
```

```json
{
  "pc": 7,
  "instruction": "*(u32 *)(r0 + 0) = r6",
  "error": { "message": "Possible null access ..." },
  "pre_invariant": [
    "r0.svalue=[0, 2147418112]",
    "r0.type=shared",
    "r0.shared_region_size=4",
    "r6.svalue=1", "r6.type=number"
  ],
  "assertions": [
    "r0.type in {ctx, stack, packet, shared}",
    "valid_access(r0.offset, width=4) for write"
  ],
  "source": { "line": 23, "source": "    *value = 1; ..." },
  "failure_slice": [
    { "pc": 3, "text": "r2 += -4" },
    { "pc": 4, "text": "r1 = map_fd 1" },
    { "pc": 6, "text": "r0 = bpf_map_lookup_elem:1(...)",
      "post_invariant": ["r0.svalue=[0, 2147418112]", "r0.type=shared"] }
  ]
}
```

The Failure Slice shows `bpf_map_lookup_elem` at PC 6 returned `r0.svalue=[0, ...]`
(includes NULL). The pre-invariant at PC 7 confirms the verifier can't prove r0
is non-null when the write happens. Diagnosis: §4.4, add a null check.

---

## 4. Diff: Before vs After Bounds Check

```
get_invariant: { "elf_path": "x64/Debug/droppacket.o", "pcs": [18, 20] }
```

At PC 18 (before `if data+42 > data_end`):
```
  packet_size = 0           ← no minimum established
  r1.type = packet
  r3.type = packet          ← r3 = data (about to add 42)
```

At PC 20 (after bounds check passes):
```
  packet_size = 42          ← PROVEN: at least 42 bytes
  r1.type = packet
  r3.packet_offset = 42    ← r3 = data + 42 (validated end)
```

The bounds check `if (data + 42 > data_end) goto exit` establishes
`packet_size >= 42`. The verifier uses this to allow safe reads of
Ethernet (14) + IPv4 (20) + UDP (8) = 42 bytes.

---

## 5. Diff: Before vs After Null Check

```
get_invariant: { "elf_path": "x64/Debug/droppacket.o", "pcs": [8, 10] }
```

At PC 8 (before `if (interface_index == NULL)` branch):
```
  r0.type = shared
  r0.svalue = [0, 2147418112]    ← INCLUDES zero (could be NULL)
  r0.shared_region_size = 4
```

At PC 10 (after null check, fall-through path):
```
  r1.type = shared
  r1.svalue = [1, 2147418112]    ← EXCLUDES zero (proven non-NULL)
  r1.shared_region_size = 4
```

The null check branch at PC 9 splits the domain. On the fall-through (non-null)
path, `svalue` lower bound changes from 0 → 1. The dereference at PC 11 is now
provably safe.

---

## 6. Diff: Before vs After Helper Call (Register Scrubbing)

```
get_instruction: {
  "elf_path": "tests/verifier_diagnosis/build/packet_reallocate.o",
  "pcs": [10]
}
```

Pre-invariant (before `bpf_xdp_adjust_head`):
```
  r1.type = ctx              r3.type = packet
  r2.type = number           r6.type = packet ← packet pointers exist
  packet_size = 4
```

Post-invariant (after `bpf_xdp_adjust_head`):
```
  r0.type = number           ← only return value
  r10.type = stack            ← only frame pointer
  packet_size = 0             ← reset to 0
                              ← r3, r6 GONE (scrubbed)
```

The helper may reallocate the packet buffer. ALL packet-derived registers
(`r3`, `r6`) and `packet_size` are invalidated. Only `r0` (return value)
and `r10` (frame pointer) survive.

---

## 7. Diff: Proven Constraint at Two Points

```
check_constraint: {
  "elf_path": "tests/verifier_diagnosis/build/packet_reallocate.o",
  "checks": [
    { "pc": 9,  "constraints": ["r6.type=packet"], "mode": "proven" },
    { "pc": 10, "constraints": ["r6.type=packet"], "mode": "proven", "point": "post" }
  ]
}
```

```json
{
  "results": [
    { "pc": 9,  "ok": true,  "message": "" },
    { "pc": 10, "ok": false, "message": "Invariant does not prove the constraint..." }
  ]
}
```

Same constraint, two points. Before the helper call: **proven** (r6 IS a packet
pointer). After the helper call: **not proven** (r6 was scrubbed). One batch call
pinpoints the exact instruction where the constraint was lost.

---

## 8. Prove Return Value Range

```
check_constraint: {
  "elf_path": "x64/Debug/droppacket.o",
  "pc": 46,
  "constraints": ["r0.svalue=[1, 2]"],
  "mode": "proven"
}
```

```json
{
  "ok": true,
  "invariant": ["r0.svalue=[1, 2]", "r0.type=number", ...]
}
```

At the exit instruction, the verifier **proves** `r0` is exactly 1 or 2
(XDP_PASS or XDP_DROP). No other return values are reachable on any path.

---

## 9. Source Line → BPF Instructions

```
get_source_mapping: {
  "elf_path": "tests/verifier_diagnosis/build/packet_overflow.c",
  "source_file": "packet_overflow.c",
  "source_line": 16
}
```

```json
{
  "source_line": 16,
  "matches": [
    {
      "pc": 3,
      "instruction": "if r2 > r1 goto label <8>",
      "source": { "line": 16, "source": "    if (data > data_end) // BUG: ..." }
    }
  ]
}
```

C line 16 compiles to a single BPF branch instruction at PC 3. The `source_file`
filter accepts a filename substring.

---

## 10. BPF Instruction → Source Line

```
get_source_mapping: { "elf_path": "x64/Debug/droppacket.o", "pc": 20 }
```

```json
{
  "pc": 20,
  "instruction": "r3 = *(u16 *)(r1 + 12)",
  "source": {
    "file": "...droppacket.c",
    "line": 70,
    "source": "    if (ntohs(ethernet_header->Type) == 0x0800) {"
  }
}
```

PC 20 reads the 2-byte Ethernet type field at offset 12 — this corresponds to
`ntohs(ethernet_header->Type)` on line 70 of the C source.

---

## 11. Disassembly with Source (Range)

```
get_disassembly: {
  "elf_path": "x64/Debug/droppacket.o",
  "from_pc": 15,
  "to_pc": 20
}
```

```json
{
  "count": 6,
  "instructions": [
    { "pc": 15, "text": "r1 = *(u64 *)(r6 + 0)",
      "source": { "line": 65, "source": "    if ((char*)ctx->data + ... > (char*)ctx->data_end) {" } },
    { "pc": 16, "text": "r2 = *(u64 *)(r6 + 8)", "source": { "line": 65 } },
    { "pc": 17, "text": "r3 = r1",               "source": { "line": 65 } },
    { "pc": 18, "text": "r3 += 42",               "source": { "line": 65 } },
    { "pc": 19, "text": "if r3 > r2 goto <46>",   "source": { "line": 65 } },
    { "pc": 20, "text": "r3 = *(u16 *)(r1 + 12)", "source": { "line": 70 } }
  ]
}
```

PCs 15–19 all correspond to the single C bounds check on line 65. PC 20 is the
first packet read (line 70), which is safe because PC 19's branch guard
established `packet_size >= 42`.

---

## 12. Control-Flow Graph

```
get_cfg: {
  "elf_path": "tests/verifier_diagnosis/build/dependent_read.o",
  "format": "json"
}
```

```json
{
  "basic_blocks": [
    { "pcs": [0,1,2,3,4,5], "successors": [5, 5] },
    { "pcs": [5, 6],        "successors": [7] },
    { "pcs": [5],            "successors": [7] },
    { "pcs": [7, 8],        "successors": [9] },
    { "pcs": [7],            "successors": [9] },
    { "pcs": [9, 10],       "successors": [exit] }
  ]
}
```

The CFG reveals the diamond pattern: PC 5 is a branch that splits into two paths
(fall-through: PCs 5→6, taken: PC 5 alone), both merging at PC 7 (another branch).
This is the join point where correlations are lost.

---

## 13. Program Type Override

```
verify_program: {
  "elf_path": "external/ebpf-verifier/ebpf-samples/build/nullmapref.o",
  "section": "test",
  "program_type": "xdp"
}
```

```json
{
  "passed": false,
  "error_count": 1,
  "first_error": {
    "pc": 7,
    "message": "Possible null access (valid_access(r0.offset, width=4) for write)"
  }
}
```

The original PREVAIL test sample uses `SEC("test")` which isn't a Windows program
type. The `program_type: "xdp"` override makes it analyzable on the Windows
platform, producing the same verification error.

---

## 14. Prove a Type at Entry

```
check_constraint: {
  "elf_path": "x64/Debug/droppacket.o",
  "pc": 0,
  "constraints": ["r1.type=ctx"],
  "mode": "proven"
}
```

```json
{
  "ok": true,
  "invariant": [
    "r1.type=ctx",
    "r1.ctx_offset=0",
    "r10.type=stack",
    "packet_size=0"
  ]
}
```

At program entry, the verifier **proves** `r1` is a valid context pointer.
The invariant also shows `packet_size=0` — no packet access is safe until
a bounds check is performed.

---

## 15. Slice: What Makes This Packet Read Safe?

```
get_slice: { "elf_path": "x64/Debug/droppacket.o", "pc": 20 }
```

```json
{
  "pc": 20,
  "instruction": "r3 = *(u16 *)(r1 + 12)",
  "assertions": [
    "r1.type in {ctx, stack, packet, shared}",
    "valid_access(r1.offset+12, width=2) for read"
  ],
  "pre_invariant": ["packet_size=42", "r1.type=packet", "r1.packet_offset=0", ...],
  "source": { "line": 70, "source": "    if (ntohs(ethernet_header->Type) == 0x0800) {" },
  "failure_slice": [
    { "pc": 0,  "text": "r6 = r1", "relevant_registers": ["r1"] },
    { "pc": 15, "text": "r1 = *(u64 *)(r6 + 0)",
      "relevant_registers": ["r6"],
      "post_invariant": ["packet_size=0", "r1.type=packet", ...] },
    { "pc": 16, "text": "r2 = *(u64 *)(r6 + 8)",
      "post_invariant": ["r2.packet_offset=packet_size", "r2.type=packet", ...] },
    { "pc": 17, "text": "r3 = r1" },
    { "pc": 18, "text": "r3 += 42",
      "post_invariant": ["r3.packet_offset=42", ...] },
    { "pc": 19, "text": "if r3 > r2 goto label <46>",
      "post_invariant": ["packet_size=0", ...] },
    { "pc": 19, "text": "assume r3 <= r2",
      "post_invariant": ["packet_size=42", ...] }
  ]
}
```

---

## 18. Verify Assembly: Bounded Loop Analysis

Test whether a loop terminates within bounds — no ELF file needed.

```
verify_assembly: {
  "code": "r0 = 0\n<loop>:\nr0 += 1\nif r0 < 10 goto <loop>\nexit",
  "check_termination": true
}
```

```json
{
  "passed": true,
  "instruction_count": 4,
  "exit_value": { "text": "[10, 10]" },
  "post_invariant": ["r0.svalue=pc[1]", "r0.type=number", "pc[1]=10", ...]
}
```

The verifier proves the loop executes exactly 10 times and `r0` is exactly 10 at exit.
Remove the bound (`goto <loop>` unconditionally) and it fails:

```
verify_assembly: {
  "code": "r0 = 0\n<loop>:\nr0 += 1\ngoto <loop>\nexit",
  "check_termination": true
}
```

```json
{
  "passed": false,
  "errors": [{ "pc": 1, "message": "Loop counter is too large (pc[1] < 100000)" }]
}
```

---

## 19. Verify Assembly: Division by Zero Detection

Test whether a divisor can be zero, using the `allow_division_by_zero` option.

```
verify_assembly: {
  "code": "r0 = 10\nr0 /= r1\nexit",
  "pre": ["r1.type=number", "r1.svalue=[0, 5]", "r1.uvalue=[0, 5]"],
  "allow_division_by_zero": false
}
```

```json
{
  "passed": false,
  "errors": [{
    "pc": 1,
    "message": "Possible division by zero (r1 != 0)",
    "pre_invariant": ["r0.svalue=10", "r0.type=number", "r1.svalue=[0, 5]", ...]
  }]
}
```

The range `[0, 5]` includes zero. Narrowing to `[1, 5]` makes it pass.

---

## 20. Verify Assembly: Safe Map Lookup Pattern

Verify that a map lookup with a null check is safe.

```
verify_assembly: {
  "code": "r2 = r10\nr2 += -4\nr3 = 0\n*(u32 *)(r10 - 4) = r3\ncall 1\nif r0 == 0 goto <out>\nr1 = *(u32 *)(r0 + 0)\n<out>:\nr0 = 0\nexit",
  "pre": ["r1.type=map_fd", "r1.map_fd=1", "r10.type=stack", "r10.stack_offset=512"]
}
```

```json
{
  "passed": true,
  "instruction_count": 9,
  "exit_value": { "text": "[0, 0]" }
}
```

Removing the `if r0 == 0 goto <out>` null check causes a "Possible null access" failure.

The slice traces backward from the 2-byte Ethernet type read. The critical
transition is at PC 19: on the branch's taken path `packet_size` stays 0 (bail
out), but on the fall-through `assume r3 <= r2` establishes **`packet_size=42`**.
Since the read needs only 14 bytes (offset 12, width 2), 42 ≥ 14 proves safety.

---

## 16. Slice: What Makes This Map Value Dereference Safe?

```
get_slice: { "elf_path": "x64/Debug/droppacket.o", "pc": 11 }
```

```json
{
  "pc": 11,
  "instruction": "r1 = *(u32 *)(r1 + 0)",
  "assertions": [
    "r1.type in {ctx, stack, packet, shared}",
    "valid_access(r1.offset, width=4) for read"
  ],
  "pre_invariant": [
    "r1.type=shared", "r1.svalue=[1, 2147418112]",
    "r1.shared_offset=0", "r1.shared_region_size=4", ...
  ],
  "source": { "line": 59, "source": "        if (ctx->ingress_ifindex != *interface_index) {" },
  "failure_slice": [
    { "pc": 3, "text": "r2 = r10" },
    { "pc": 4, "text": "r2 += -8" },
    { "pc": 5, "text": "r1 = map_fd 1" },
    { "pc": 7, "text": "r0 = bpf_map_lookup_elem:1(map_fd r1, map_key r2)",
      "post_invariant": ["r0.type=shared", "r0.svalue=[0, 2147418112]", ...] },
    { "pc": 8, "text": "r1 = r0",
      "post_invariant": ["r1.svalue=[0, 2147418112]", ...] },
    { "pc": 9, "text": "if r1 == 0 goto label <14>" },
    { "pc": 9, "text": "assume r1 != 0",
      "post_invariant": ["r1.svalue=[1, 2147418112]", ...] }
  ]
}
```

The slice shows the null-check pattern: `bpf_map_lookup_elem` at PC 7 returns
`r0.svalue=[0, ...]` (includes NULL). After `assume r1 != 0` at PC 9, the lower
bound narrows from 0 → **1**, proving non-null. The 4-byte read is then safe
because `shared_region_size=4` covers the access width.

---

## 17. Slice: How Are Helper Call Arguments Verified?

```
get_slice: { "elf_path": "x64/Debug/cgroup_sock_addr.o", "pc": 30 }
```

```json
{
  "pc": 30,
  "instruction": "r0 = bpf_map_update_elem:2(map_fd r1, map_key r2, map_value r3, uint64_t r4)",
  "assertions": [
    "r1.type == map_fd", "r2.type in {stack, packet, shared}",
    "within(r2:key_size(r1))", "r3.type in {stack, packet, shared}",
    "within(r3:value_size(r1))", "r4.type == number"
  ],
  "pre_invariant": [
    "r1.map_fd=3", "r1.type=map_fd",
    "r2.stack_offset=4032", "r2.stack_numeric_size=64", "r2.type=stack",
    "r3.stack_offset=4088", "r3.stack_numeric_size=8", "r3.type=stack",
    "r4.svalue=0", "r4.type=number",
    "s[4032...4095].type=number", ...
  ],
  "source": { "line": 45, "source": "    bpf_map_update_elem(&socket_cookie_map, tuple_key, &socket_cookie, 0);" },
  "failure_slice": [
    { "pc": 22, "text": "r6 = r10" },
    { "pc": 23, "text": "r6 += -64",
      "post_invariant": ["r6.stack_offset=4032", "r6.stack_numeric_size=64", ...] },
    { "pc": 24, "text": "r3 = r10" },
    { "pc": 25, "text": "r3 += -8",
      "post_invariant": ["r3.stack_offset=4088", "r3.stack_numeric_size=8", ...] },
    { "pc": 26, "text": "r1 = map_fd 3" },
    { "pc": 28, "text": "r2 = r6" },
    { "pc": 29, "text": "r4 = 0" }
  ]
}
```

The slice shows all 4 arguments being assembled: `r1` (map fd), `r2` (64-byte
key on stack at offset 4032), `r3` (8-byte value on stack at offset 4088), and
`r4` (flags = 0). The verifier checks `stack_numeric_size` against the map's
declared `key_size` and `value_size` via the `within()` assertions, and confirms
`s[4032...4095].type=number` (all stack bytes are initialized).
