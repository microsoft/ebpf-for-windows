# PREVAIL MCP Server — Example Queries

Natural-language queries you can ask in a Copilot CLI session to understand
or diagnose eBPF programs using the `prevail-mcp` skill. Each query is shown
with the response produced by the MCP tools.

## Table of Contents

### Verification
- [Does droppacket.o pass the verifier?](#q1-does-droppacketo-pass-the-verifier)
- [What errors does nullmapref.o produce?](#q2-what-errors-does-nullmaprefo-produce)

### Diagnosis
- [Why does nullmapref.o fail verification?](#q3-why-does-nullmaprefo-fail-verification)
- [What does the verifier know about r0 at the failure point?](#q4-what-does-the-verifier-know-about-r0-at-the-failure-point)
- [Is r0 possibly NULL?](#q5-is-r0-possibly-null)
- [What safety property is missing in packet_overflow.o?](#q6-what-safety-property-is-missing-in-packet_overflowo)

### Understanding Passing Programs
- [What is the proven return value range of DropPacket?](#q7-what-is-the-proven-return-value-range-of-droppacket)
- [How many packet bytes are accessible after the bounds check?](#q8-how-many-packet-bytes-are-accessible-after-the-bounds-check)
- [What changes across the null check?](#q9-what-changes-across-the-null-check)

### Backward Slicing on Passing Programs
- [What chain of instructions makes the Ethernet type read safe?](#q17-what-chain-of-instructions-makes-the-ethernet-type-read-safe)
- [What makes the map value dereference safe?](#q18-what-makes-the-map-value-dereference-safe)
- [How does the verifier validate helper call arguments?](#q19-how-does-the-verifier-validate-helper-call-arguments)

### Tracing State Changes
- [Is r6 still valid after bpf_xdp_adjust_head?](#q10-is-r6-still-valid-after-bpf_xdp_adjust_head)
- [What registers survive the helper call?](#q11-what-registers-survive-the-helper-call)
- [Where is packet_size >= 4 lost between the check and the read?](#q12-where-is-packet_size--4-lost-between-the-check-and-the-read)

### Source ↔ Assembly
- [What instructions does a C source line compile to?](#q13-what-instructions-does-a-c-source-line-compile-to)
- [Which C line does a BPF instruction come from?](#q14-which-c-line-does-a-bpf-instruction-come-from)
- [Annotated disassembly of a code range](#q15-annotated-disassembly-of-a-code-range)

### Program Structure
- [Where are the branch and join points?](#q16-where-are-the-branch-and-join-points)

### Assembly Snippets
- [Does this loop terminate?](#q20-does-this-loop-terminate)
- [Can this division trigger a divide-by-zero?](#q21-can-this-division-trigger-a-divide-by-zero)
- [Is this map lookup pattern safe?](#q22-is-this-map-lookup-pattern-safe)

---

### Q1: Does droppacket.o pass the verifier?

> Does droppacket.o pass the verifier?

Yes. The `DropPacket` function in section `xdp` passes verification with 0 errors
and 45 instructions. The exit value is `[1, 2]`.

---

### Q2: What errors does nullmapref.o produce?

> What errors does nullmapref.o produce?

It produces 1 error at PC 7: **"Possible null access (valid_access(r0.offset,
width=4) for write)"**. The failing source line is `*value = 1;` at
nullmapref.c:23 — the code dereferences the return value of
`bpf_map_lookup_elem` without a NULL check.

---

### Q3: Why does nullmapref.o fail verification?

> Why does nullmapref.o fail verification? Trace back from the error.

At PC 5–6, `bpf_map_lookup_elem(&test_map, &key)` returns a result in `r0` that
may be NULL (`svalue=[0, 2147418112]`). At PC 7, the program writes
`*(u32 *)(r0 + 0) = r6` without checking if `r0` is NULL. Fix: add
`if (value != NULL)` before the dereference.

---

### Q4: What does the verifier know about r0 at the failure point?

> What does the verifier know about r0 at the point where nullmapref.o fails?

At PC 7: `r0.type=shared`, `r0.svalue=[0, 2147418112]`, `r0.shared_offset=0`,
`r0.shared_region_size=4`. The value range starting at 0 means `r0` could be a
valid shared pointer **or** NULL — and the verifier requires a NULL check before
dereferencing.

---

### Q5: Is r0 possibly NULL?

> Is r0 possibly NULL at PC 7 in nullmapref.o?

**Yes.** A `check_constraint` call with `r0.svalue=[0, 0]` in `consistent` mode
returned `ok: true`, confirming that r0 being NULL (value 0) is consistent with
the invariant at PC 7.

---

### Q6: What safety property is missing in packet_overflow.o?

> What safety property is missing that causes the failure in packet_overflow.o?

The 4-byte read needs `packet_size >= 4`, but the bounds check on line 16
(`data > data_end`) only establishes `data <= data_end`, which allows zero-length
packets. The invariant shows `packet_size=0` at the read. Fix: change to
`if (data + sizeof(int) > data_end)` to prove at least 4 bytes are accessible.

---

### Q7: What is the proven return value range of DropPacket?

> What does the verifier prove about the return value of DropPacket in droppacket.o?

At the exit (PC 46): `r0.svalue=[1, 2]`. The return value is always either
1 (XDP_PASS) or 2 (XDP_DROP) — the program never returns 0 (XDP_ABORTED) or any
other value on any execution path.

---

### Q8: How many packet bytes are accessible after the bounds check?

> After the bounds check on line 65 of droppacket.c, how many bytes of packet
> data are proven accessible?

Before the check (PC 18): `packet_size=0`. After (PC 20): **`packet_size=42`**.
The check `data + 42 > data_end` establishes that at least 42 bytes
(Ethernet + IPv4 + UDP headers) are available for safe reading.

---

### Q9: What changes across the null check?

> Show me what the verifier knows before and after the null check at PC 9 in
> droppacket.o.

Before (PC 8): `r0.svalue=[0, 2147418112]` — could be NULL (lower bound 0).
After (PC 10): `r0.svalue=[1, 2147418112]` — NULL excluded (lower bound 1).
The null check narrows the range to prove the pointer is non-NULL before
it's dereferenced.

---

### Q10: Is r6 still valid after bpf_xdp_adjust_head?

> In packet_reallocate.o, is r6 still a valid packet pointer after the call to
> bpf_xdp_adjust_head?

**Before** (PC 9): `r6.type=packet` is **proven**. **After** (PC 10 post): the
check **fails** — r6 is completely wiped from the abstract state. Only `r0`
and `r10` survive. The helper invalidates all packet pointers because the buffer
may be reallocated.

---

### Q11: What registers survive the helper call?

> What registers survive the bpf_xdp_adjust_head call in packet_reallocate.o?
> Compare the pre and post invariants at PC 10.

**Pre**: r0, r1 (ctx), r2 (number), r3 (packet), r6 (packet), r10 (stack) —
rich constraints, `packet_size=4`. **Post**: only `r0.type=number` and
`r10.type=stack` survive. All packet-derived registers (r3, r6) are wiped and
`packet_size` resets to 0.

---

### Q12: Where is packet_size >= 4 lost between the check and the read?

> In dependent_read.o, is packet_size >= 4 proven at the packet read (PC 8)?
> What about right after the bounds check (PC 6)?

At **PC 6**: `packet_size=4` is **proven** — the bounds check works. At **PC 8**:
the check **fails** with `packet_size=1`. The correlation between the flag
variable `r5=1` and `packet_size>=4` is lost at the join point between the
checked and unchecked paths.

---

### Q13: What instructions does a C source line compile to?

> What BPF instructions does line 65 of droppacket.c compile to?

Line 65 (`if (data + 42 > data_end)`) compiles to **5 instructions** at
PCs 15–19: load `ctx->data` (r1), load `ctx->data_end` (r2), copy to r3,
add 42, and conditionally jump if `r3 > r2`.

---

### Q14: Which C line does a BPF instruction come from?

> Which C source line does PC 20 in droppacket.o correspond to?

PC 20 (`r3 = *(u16 *)(r1 + 12)`) corresponds to **line 70**: `if
(ntohs(ethernet_header->Type) == 0x0800)`. It reads the 2-byte EtherType field
at offset 12 from the start of the packet.

---

### Q15: Annotated disassembly of a code range

> Show me the disassembly from PC 15 to PC 20 in droppacket.o with source
> annotations.

```
PC 15: r1 = *(u64 *)(r6 + 0)       // line 65: ctx->data
PC 16: r2 = *(u64 *)(r6 + 8)       // line 65: ctx->data_end
PC 17: r3 = r1                      // line 65: copy data ptr
PC 18: r3 += 42                     // line 65: + sizeof(ETH+IP+UDP)
PC 19: if r3 > r2 goto <46>        // line 65: bounds check
PC 20: r3 = *(u16 *)(r1 + 12)      // line 70: ethernet_header->Type
```

PCs 15–19 implement the bounds check from line 65. PC 20 is the first packet
read (line 70), safe because PC 19's guard established `packet_size >= 42`.

---

### Q16: Where are the branch and join points?

> Show me the control-flow graph of dependent_read.o. Where are the branch
> points and join points?

The CFG has 7 basic blocks in a diamond pattern:

- **Branch points**: PC 5 (bounds check: `if r2 > r3`) and PC 7 (flag check:
  `if r5 == 0`)
- **Join points**: PC 7 (merges the checked/unchecked paths from PC 5) and PC 9
  (merges the read/skip paths from PC 7)
- **Exit**: PCs 9–10 terminate the program

The two sequential branch-merge pairs form the pattern that causes the lost
correlation — `packet_size=4` is established on one branch of PC 5 but lost
when paths merge at PC 7.

---

### Q17: What chain of instructions makes the Ethernet type read safe?

> In droppacket.o, what chain of instructions makes the packet read at PC 20
> safe? Trace backward from the read.

The `get_slice` at PC 20 reveals **7 instructions** in the backward slice:

1. **PC 0**: `r6 = r1` — saves the context pointer
2. **PCs 15–16**: Load `ctx->data` (r1, packet pointer) and `ctx->data_end` (r2)
3. **PCs 17–18**: Compute `data + 42` in r3 (`r3.packet_offset=42`)
4. **PC 19**: Branch `if r3 > r2 goto exit` — packets too small bail out
5. **PC 19**: `assume r3 <= r2` — on fall-through, **`packet_size` jumps from 0 → 42**

The 2-byte read at offset 12 needs `packet_size ≥ 14`. Since the bounds check
establishes `packet_size = 42`, the access is provably safe. The `assume`
pseudo-instruction at PC 19 is the critical moment — it's where the C code's
`if (data + 42 > data_end)` guard becomes a proven constraint.

---

### Q18: What makes the map value dereference safe?

> In droppacket.o, what makes the dereference of `*interface_index` at PC 11
> safe? Show me the backward slice.

The `get_slice` at PC 11 reveals **7 instructions**:

1. **PCs 3–5**: Set up map key pointer (r2 → stack) and map fd (r1 = map_fd 1)
2. **PC 7**: `bpf_map_lookup_elem` returns `r0.svalue=[0, 2147418112]` — **may
   be NULL** (lower bound 0)
3. **PC 8**: Copy to r1 (`r1 = r0`)
4. **PC 9**: `if r1 == 0 goto <14>` / `assume r1 != 0` — null check narrows
   `r1.svalue` to **[1, 2147418112]** (lower bound 1, NULL excluded)

At PC 11, the verifier knows `r1.type=shared`, `r1.shared_region_size=4`, and
`r1.svalue ≥ 1` (non-null). The 4-byte read at offset 0 fits within the 4-byte
shared region. The `assume r1 != 0` at PC 9 is the critical instruction — it
transforms a maybe-null pointer into a provably-valid one.

---

### Q19: How does the verifier validate helper call arguments?

> In cgroup_sock_addr.o, how does the verifier validate the arguments to
> bpf_map_update_elem at PC 30?

The `get_slice` at PC 30 reveals **7 instructions** assembling 4 arguments, plus
**6 assertions** the verifier checks:

| Register | Setup | Assertion |
|----------|-------|-----------|
| r1 (map) | `r1 = map_fd 3` | `r1.type == map_fd` |
| r2 (key) | `r6 = r10; r6 += -64; r2 = r6` | `r2.type in {stack, ...}` + `within(r2:key_size(r1))` |
| r3 (value) | `r3 = r10; r3 += -8` | `r3.type in {stack, ...}` + `within(r3:value_size(r1))` |
| r4 (flags) | `r4 = 0` | `r4.type == number` |

The verifier tracks `stack_numeric_size` for each pointer: r2 has 64 bytes of
initialized stack data at offset 4032, r3 has 8 bytes at offset 4088. The
`within()` assertion checks that these sizes cover the map's declared key and
value sizes. The invariant `s[4032...4095].type=number` confirms every byte in
the range is initialized — no uninitialized memory is passed to the helper.

---

### Q20: Does this loop terminate?

> Use verify_assembly to check if this loop terminates:
> `r0 = 0; <loop>: r0 += 1; if r0 < 10 goto <loop>; exit`

Yes. With `check_termination: true`, the verifier proves the loop executes exactly
10 iterations. The exit value is `[10, 10]` and the loop counter `pc[1]` reaches
exactly 10. If you remove the bound condition (unconditional `goto <loop>`), the
verifier rejects it with "Loop counter is too large".

---

### Q21: Can this division trigger a divide-by-zero?

> Use verify_assembly with allow_division_by_zero=false to check:
> `r0 = 10; r0 /= r1; exit` where r1 is in [0, 5]

Yes — the verifier reports "Possible division by zero (r1 != 0)" because `r1`'s
range `[0, 5]` includes zero. Narrowing the pre-condition to `r1.svalue=[1, 5]`
eliminates the zero and the program passes.

---

### Q22: Is this map lookup pattern safe?

> Use verify_assembly to check a map lookup with a null check:
> Set up r1 as map_fd, store a key, call bpf_map_lookup_elem, check for null, then read.

Yes — the standard pattern (call 1, if r0 == 0 goto out, read r0) passes verification.
The null check splits the state: the read only happens when `r0.type=shared` (non-null
map value pointer). Removing the null check produces "Possible null access".
