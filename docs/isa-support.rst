eBPF Instruction Set
====================

The following table shows which
[eBPF instructions](https://github.com/dthaler/ebpf-docs/blob/update/isa/kernel.org/instruction-set.rst)
are currently supported by PREVAIL, uBPF, and bpf2c, and which bpf_conformance test covers it.

======  ====  ====  ===================================================  =======  ====  =====  ======================
opcode  src   imm   description                                          PREVAIL  uBPF  bpf2c  conformance
======  ====  ====  ===================================================  =======  ====  =====  ======================
0x00    0x0   any   (additional immediate value)                            Y      Y      Y    arsh32-high-shift
0x04    0x0   any   dst = (uint32_t)(dst + imm)                             Y      Y      Y    add
0x05    0x0   0x00  goto +offset                                            Y      Y      Y    exit-not-last
0x07    0x0   any   dst += imm                                              Y      Y      Y    add64
0x0c    any   0x00  dst = (uint32_t)(dst + src)                             Y      Y      Y    add
0x0f    any   0x00  dst += src                                              Y      Y      Y    alu64-arith
0x14    0x0   any   dst = (uint32_t)(dst - imm)                             Y      Y      Y    alu-arith
0x15    0x0   any   if dst == imm goto +offset                              Y      Y      Y    jeq-imm
0x16    0x0   any   if (uint32_t)dst == imm goto +offset                    Y      Y      Y    jeq32-imm
0x17    0x0   any   dst -= imm                                              Y      Y      Y    alu64-arith
0x18    0x0   any   dst = imm64                                             Y      Y      Y    lddw
0x18    0x1   any   dst = map_by_fd(imm)                                    no     no     no   ???
0x18    0x2   any   dst = mva(map_by_fd(imm)) + next_imm                    no     no     no   ???
0x18    0x3   any   dst = variable_addr(imm)                                no     no     no   ???
0x18    0x4   any   dst = code_addr(imm)                                    no     no     no   ???
0x18    0x5   any   dst = map_by_idx(imm)                                   no     no     no   ???
0x18    0x6   any   dst = mva(map_by_idx(imm)) + next_imm                   no     no     no   ???
0x1c    any   0x00  dst = (uint32_t)(dst - src)                             Y      Y      Y    alu-arith
0x1d    any   0x00  if dst == src goto +offset                              Y      Y      Y    jeq-reg
0x1e    any   0x00  if (uint32_t)dst == (uint32_t)src goto +offset          Y      Y      Y    jeq32-reg
0x1f    any   0x00  dst -= src                                              Y      Y      Y    alu64-arith
0x20    any   any   (deprecated, implementation-specific)                   no     no     no   (none)
0x24    0x0   any   dst = (uint32_t)(dst \* imm)                            Y      Y      Y    mul32-imm
0x25    0x0   any   if dst > imm goto +offset                               Y      Y      Y    jgt-imm
0x26    0x0   any   if (uint32_t)dst > imm goto +offset                     Y      Y      Y    jgt32-imm
0x27    0x0   any   dst \*= imm                                             Y      Y      Y    mul64-imm
0x28    any   any   (deprecated, implementation-specific)                   no     no     no   (none)
0x2c    any   0x00  dst = (uint32_t)(dst \* src)                            Y      Y      Y    mul32-reg
0x2d    any   0x00  if dst > src goto +offset                               Y      Y      Y    jgt-reg
0x2e    any   0x00  if (uint32_t)dst > (uint32_t)src goto +offset           Y      Y      Y    jgt32-reg
0x2f    any   0x00  dst \*= src                                             Y      Y      Y    mul64-reg
0x30    any   any   (deprecated, implementation-specific)                   no     no     no   (none)
0x34    0x0   any   dst = (uint32_t)((imm != 0) ? (dst / imm) : 0)          Y      Y      Y    alu-arith
0x35    0x0   any   if dst >= imm goto +offset                              Y      Y      Y    jge-imm
0x36    0x0   any   if (uint32_t)dst >= imm goto +offset                    Y      Y      Y    jge32-imm
0x37    0x0   any   dst = (imm != 0) ? (dst / imm) : 0                      Y      Y      Y    alu64-arith
0x38    any   any   (deprecated, implementation-specific)                   no     no     no   (none)
0x3c    any   0x00  dst = (uint32_t)((imm != 0) ? (dst / src) : 0)          Y      Y      Y    alu-arith
0x3d    any   0x00  if dst >= src goto +offset                              Y      Y      Y    prime
0x3e    any   0x00  if (uint32_t)dst >= (uint32_t)src goto +offset          Y      Y      Y    jge32-reg
0x3f    any   0x00  dst = (src !+ 0) ? (dst / src) : 0                      Y      Y      Y    alu64-arith
0x40    any   any   (deprecated, implementation-specific)                   no     no     no   (none)
0x44    0x0   any   dst = (uint32_t)(dst \| imm)                            Y      Y      Y    alu-bit
0x45    0x0   any   if dst & imm goto +offset                               Y      Y      Y    jset-imm
0x46    0x0   any   if (uint32_t)dst & imm goto +offset                     Y      Y      Y    jset32-imm
0x47    0x0   any   dst \|= imm                                             Y      Y      Y    alu64-bit
0x48    any   any   (deprecated, implementation-specific)                   no     no     no   (none)
0x4c    any   0x00  dst = (uint32_t)(dst \| src)                            Y      Y      Y    alu-bit
0x4d    any   0x00  if dst & src goto +offset                               Y      Y      Y    jset-reg
0x4e    any   0x00  if (uint32_t)dst & (uint32_t)src goto +offset           Y      Y      Y    jset32-reg
0x4f    any   0x00  dst \|= src                                             Y      Y      Y    alu64-bit
0x50    any   any   (deprecated, implementation-specific)                   no     no     no   (none)
0x54    0x0   any   dst = (uint32_t)(dst & imm)                             Y      Y      Y    alu-bit
0x55    0x0   any   if dst != imm goto +offset                              Y      Y      Y    alu-arith
0x56    0x0   any   if (uint32_t)dst != imm goto +offset                    Y      Y      Y    jne32-imm
0x57    0x0   any   dst &= imm                                              Y      Y      Y    alu64-bit
0x58    any   any   (deprecated, implementation-specific)                   no     no     no   (none)
0x5c    any   0x00  dst = (uint32_t)(dst & src)                             Y      Y      Y    alu-bit
0x5d    any   0x00  if dst != src goto +offset                              Y      Y      Y    jne-reg
0x5e    any   0x00  if (uint32_t)dst != (uint32_t)src goto +offset          Y      Y      Y    jne32-reg
0x5f    any   0x00  dst &= src                                              Y      Y      Y    alu64-bit
0x61    any   0x00  dst = \*(uint32_t \*)(src + offset)                     Y      Y      Y    ldxw
0x62    0x0   any   \*(uint32_t \*)(dst + offset) = imm                     Y      Y      Y    stw
0x63    any   0x00  \*(uint32_t \*)(dst + offset) = src                     Y      Y      Y    stxw
0x64    0x0   any   dst = (uint32_t)(dst << imm)                            Y      Y      Y    alu-bit
0x65    0x0   any   if dst s> imm goto +offset                              Y      Y      Y    jsgt-imm
0x66    0x0   any   if (int32_t)dst s> (int32_t)imm goto +offset            Y      Y      Y    jsgt32-imm
0x67    0x0   any   dst <<= imm                                             Y      Y      Y    alu64-bit
0x69    any   0x00  dst = \*(uint16_t \*)(src + offset)                     Y      Y      Y    ldxh
0x6a    0x0   any   \*(uint16_t \*)(dst + offset) = imm                     Y      Y      Y    sth
0x6b    any   0x00  \*(uint16_t \*)(dst + offset) = src                     Y      Y      Y    stxh
0x6c    any   0x00  dst = (uint32_t)(dst << src)                            Y      Y      Y    alu-bit
0x6d    any   0x00  if dst s> src goto +offset                              Y      Y      Y    jsgt-reg
0x6e    any   0x00  if (int32_t)dst s> (int32_t)src goto +offset            Y      Y      Y    jsgt32-reg
0x6f    any   0x00  dst <<= src                                             Y      Y      Y    lsh-reg
0x71    any   0x00  dst = \*(uint8_t \*)(src + offset)                      Y      Y      Y    ldxb
0x72    0x0   any   \*(uint8_t \*)(dst + offset) = imm                      Y      Y      Y    stb
0x73    any   0x00  \*(uint8_t \*)(dst + offset) = src                      Y      Y      Y    stxb
0x74    0x0   any   dst = (uint32_t)(dst >> imm)                            Y      Y      Y    rsh32
0x75    0x0   any   if dst s>= imm goto +offset                             Y      Y      Y    jsge-imm
0x76    0x0   any   if (int32_t)dst s>= (int32_t)imm goto +offset           Y      Y      Y    jsge32-imm
0x77    0x0   any   dst >>= imm                                             Y      Y      Y    alu64-bit
0x79    any   0x00  dst = \*(uint64_t \*)(src + offset)                     Y      Y      Y    ldxdw
0x7a    0x0   any   \*(uint64_t \*)(dst + offset) = imm                     Y      Y      Y    stdw
0x7b    any   0x00  \*(uint64_t \*)(dst + offset) = src                     Y      Y      Y    stxdw
0x7c    any   0x00  dst = (uint32_t)(dst >> src)                            Y      Y      Y    alu-bit
0x7d    any   0x00  if dst s>= src goto +offset                             Y      Y      Y    jsge-reg
0x7e    any   0x00  if (int32_t)dst s>= (int32_t)src goto +offset           Y      Y      Y    jsge32-reg
0x7f    any   0x00  dst >>= src                                             Y      Y      Y    rsh-reg
0x84    0x0   0x00  dst = (uint32_t)-dst                                    Y      Y      Y    neg
0x85    0x0   any   call helper function imm                                Y      Y      Y    call_unwind_fail
0x85    0x1   any   call PC += offset                                       no     no     no   call_local
0x85    0x2   any   call runtime function imm                               no     no     no   ???
0x87    0x0   0x00  dst = -dst                                              Y      Y      Y    neg64
0x94    0x0   any   dst = (uint32_t)((imm != 0) ? (dst % imm) : dst)        Y      Y      Y    mod
0x95    0x0   0x00  return                                                  Y      Y      Y    exit
0x97    0x0   any   dst = (imm != 0) ? (dst % imm) : dst                    Y      Y      Y    mod64
0x9c    any   0x00  dst = (uint32_t)((src != 0) ? (dst % src) : dst)        Y      Y      Y    mod
0x9f    any   0x00  dst = (src != 0) ? (dst % src) : dst                    Y      Y      Y    mod64
0xa4    0x0   any   dst = (uint32_t)(dst ^ imm)                             Y      Y      Y    alu-bit
0xa5    0x0   any   if dst < imm goto +offset                               Y      Y      Y    jlt-imm
0xa6    0x0   any   if (uint32_t)dst < imm goto +offset                     Y      Y      Y    jlt32-imm
0xa7    0x0   any   dst ^= imm                                              Y      Y      Y    alu64-bit
0xac    any   0x00  dst = (uint32_t)(dst ^ src)                             Y      Y      Y    alu-bit
0xad    any   0x00  if dst < src goto +offset                               Y      Y      Y    jlt-reg
0xae    any   0x00  if (uint32_t)dst < (uint32_t)src goto +offset           Y      Y      Y    jlt32-reg
0xaf    any   0x00  dst ^= src                                              Y      Y      Y    alu64-bit
0xb4    0x0   any   dst = (uint32_t) imm                                    Y      Y      Y    mov
0xb5    0x0   any   if dst <= imm goto +offset                              Y      Y      Y    jle-imm
0xb6    0x0   any   if (uint32_t)dst <= imm goto +offset                    Y      Y      Y    jle32-imm
0xb7    0x0   any   dst = imm                                               Y      Y      Y    mov64-sign-extend
0xbc    any   0x00  dst = (uint32_t) src                                    Y      Y      Y    mov
0xbd    any   0x00  if dst <= src goto +offset                              Y      Y      Y    jle-reg
0xbe    any   0x00  if (uint32_t)dst <= (uint32_t)src goto +offset          Y      Y      Y    jle32-reg
0xbf    any   0x00  dst = src                                               Y      Y      Y    ldxb-all
0xc3    any   0x00  lock \*(uint32_t \*)(dst + offset) += src               no     no     no   lock_add32
0xc3    any   0x01  lock::                                                  no     no     no   lock_fetch_add32

                       *(uint32_t *)(dst + offset) += src
                       src = *(uint32_t *)(dst + offset)
0xc3    any   0x40  \*(uint32_t \*)(dst + offset) \|= src                   no     no     no   lock_or32
0xc3    any   0x41  lock::                                                  no     no     no   lock_fetch_or32

                       *(uint32_t *)(dst + offset) |= src
                       src = *(uint32_t *)(dst + offset)
0xc3    any   0x50  \*(uint32_t \*)(dst + offset) &= src                    no     no     no   lock_and32
0xc3    any   0x51  lock::                                                  no     no     no   lock_fetch_and32

                       *(uint32_t *)(dst + offset) &= src
                       src = *(uint32_t *)(dst + offset)
0xc3    any   0xa0  \*(uint32_t \*)(dst + offset) ^= src                    no     no     no   lock_xor32
0xc3    any   0xa1  lock::                                                  no     no     no   lock_fetch_xor32

                       *(uint32_t *)(dst + offset) ^= src
                       src = *(uint32_t *)(dst + offset)
0xc3    any   0xe1  lock::                                                  no     no     no   lock_xchg32

                       temp = *(uint32_t *)(dst + offset)
                       *(uint32_t *)(dst + offset) = src
                       src = temp
0xc3    any   0xf1  lock::                                                  no     no     no   lock_cmpxchg32

                       temp = *(uint32_t *)(dst + offset)
                       if *(uint32_t)(dst + offset) == R0
                          *(uint32_t)(dst + offset) = src
                       R0 = temp
0xc4    0x0   any   dst = (uint32_t)(dst s>> imm)                           Y      Y      Y    arsh
0xc5    0x0   any   if dst s< imm goto +offset                              Y      Y      Y    jslt-imm
0xc6    0x0   any   if (int32_t)dst s< (int32_t)imm goto +offset            Y      Y      Y    jslt32-imm
0xc7    0x0   any   dst s>>= imm                                            Y      Y      Y    arsh64
0xcc    any   0x00  dst = (uint32_t)(dst s>> src)                           Y      Y      Y    arsh-reg
0xcd    any   0x00  if dst s< src goto +offset                              Y      Y      Y    jslt-reg
0xce    any   0x00  if (int32_t)dst s< (int32_t)src goto +offset            Y      Y      Y    jslt32-reg
0xcf    any   0x00  dst s>>= src                                            Y      Y      Y    arsh64
0xd4    0x0   0x10  dst = htole16(dst)                                      Y      Y      Y    le16
0xd4    0x0   0x20  dst = htole32(dst)                                      Y      Y      Y    le32
0xd4    0x0   0x40  dst = htole64(dst)                                      Y      Y      Y    le64
0xd5    0x0   any   if dst s<= imm goto +offset                             Y      Y      Y    jsle-imm
0xd6    0x0   any   if (int32_t)dst s<= (int32_t)imm goto +offset           Y      Y      Y    jsle32-imm
0xdb    any   0x00  lock \*(uint64_t \*)(dst + offset) += src               no     no     no   lock_add
0xdb    any   0x01  lock::                                                  no     no     no   lock_fetch_add

                       *(uint64_t *)(dst + offset) += src
                       src = *(uint64_t *)(dst + offset)
0xdb    any   0x40  \*(uint64_t \*)(dst + offset) \|= src                   no     no     no   lock_or
0xdb    any   0x41  lock::                                                  no     no     no   lock_fetch_or

                       *(uint64_t *)(dst + offset) |= src
                       lock src = *(uint64_t *)(dst + offset)
0xdb    any   0x50  \*(uint64_t \*)(dst + offset) &= src                    no     no     no   lock_and
0xdb    any   0x51  lock::                                                  no     no     no   lock_fetch_and

                       *(uint64_t *)(dst + offset) &= src
                       src = *(uint64_t *)(dst + offset)
0xdb    any   0xa0  \*(uint64_t \*)(dst + offset) ^= src                    no     no     no   lock_xor
0xdb    any   0xa1  lock::                                                  no     no     no   lock_fetch_xor

                       *(uint64_t *)(dst + offset) ^= src
                       src = *(uint64_t *)(dst + offset)
0xdb    any   0xe1  lock::                                                  no     no    no    lock_xchg

                       temp = *(uint64_t *)(dst + offset)
                       *(uint64_t *)(dst + offset) = src
                       src = temp
0xdb    any   0xf1  lock::                                                  no     no    no    lock_cmpxchg

                       temp = *(uint64_t *)(dst + offset)
                       if *(uint64_t)(dst + offset) == R0
                          *(uint64_t)(dst + offset) = src
                       R0 = temp
0xdc    0x0   0x10  dst = htobe16(dst)                                      Y      Y     Y     be16
0xdc    0x0   0x20  dst = htobe32(dst)                                      Y      Y     Y     be32
0xdc    0x0   0x40  dst = htobe64(dst)                                      Y      Y     Y     be64
0xdd    any   0x00  if dst s<= src goto +offset                             Y      Y     Y     jsle-reg
0xde    any   0x00  if (int32_t)dst s<= (int32_t)src goto +offset           Y      Y     Y     jsle32-reg
======  ====  ====  ===================================================  =======  ====  =====  ======================

**Some takeaways:**

* Some ldx instruction conformance issues still exist in the PREVAIL verifier, where instructions
  fail verification that shouldn't.  This is not a security issue, it might simply prevent some valid
  programs from being verified (https://github.com/vbpf/ebpf-verifier/issues/420).
* Atomic instructions are not supported by any of the components, though this is not a major problem
  as they will not be generated by clang when an older "cpu version" is specified on the command line.
* The conformance suite does not support most 64-bit immediate instructions
  (https://github.com/Alan-Jowett/bpf_conformance/issues/59).
