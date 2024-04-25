eBPF Instruction Set
====================

The following table shows which
`eBPF instructions <https://github.com/dthaler/ebpf-docs/blob/update/isa/kernel.org/instruction-set.rst>`_
are currently supported by PREVAIL, uBPF, and bpf2c, and a bpf_conformance test (potentially among others)
that covers it.

======  =======  ======  ====  ======================================================  =======  ====  =====  ======================
opcode  src_reg  offset  imm   description                                             PREVAIL  uBPF  bpf2c  conformance
======  =======  ======  ====  ======================================================  =======  ====  =====  ======================
0x00    0x0      0       any   (additional immediate value)                            Y        Y     Y      arsh32-high-shift
0x04    0x0      0       any   dst = (u32)((u32)dst + (u32)imm)                        Y        Y     Y      add
0x05    0x0      any     0x00  goto +offset                                            Y        Y     Y      exit-not-last
0x06    0x0      0       any   goto +imm                                               Y        no    Y      ja32
0x07    0x0      0       any   dst += imm                                              Y        Y     Y      add64
0x0c    any      0       0x00  dst = (u32)((u32)dst + (u32)src)                        Y        Y     Y      add
0x0f    any      0       0x00  dst += src                                              Y        Y     Y      alu64-arith
0x14    0x0      0       any   dst = (u32)((u32)dst - (u32)imm)                        Y        Y     Y      alu-arith
0x15    0x0      any     any   if dst == imm goto +offset                              Y        Y     Y      jeq-imm
0x16    0x0      any     any   if (u32)dst == imm goto +offset                         Y        Y     Y      jeq32-imm
0x17    0x0      0       any   dst -= imm                                              Y        Y     Y      alu64-arith
0x18    0x0      0       any   dst = (next_imm << 32) | imm                            Y        Y     Y      lddw
0x18    0x1      0       any   dst = map_by_fd(imm)                                    no       no    no     ???
0x18    0x2      0       any   dst = mva(map_by_fd(imm)) + next_imm                    no       no    no     ???
0x18    0x3      0       any   dst = variable_addr(imm)                                no       no    no     ???
0x18    0x4      0       any   dst = code_addr(imm)                                    no       no    no     ???
0x18    0x5      0       any   dst = map_by_idx(imm)                                   no       no    no     ???
0x18    0x6      0       any   dst = mva(map_by_idx(imm)) + next_imm                   no       no    no     ???
0x1c    any      0       0x00  dst = (u32)((u32)dst - (u32)src)                        Y        Y     Y      alu-arith
0x1d    any      any     0x00  if dst == src goto +offset                              Y        Y     Y      jeq-reg
0x1e    any      any     0x00  if (u32)dst == (u32)src goto +offset                    Y        Y     Y      jeq32-reg
0x1f    any      0       0x00  dst -= src                                              Y        Y     Y      alu64-arith
0x20    0x0      0       any   (deprecated, implementation-specific)                   Y        no    no     (none)
0x24    0x0      0       any   dst = (u32)(dst \* imm)                                 Y        Y     Y      mul32-imm
0x25    0x0      any     any   if dst > imm goto +offset                               Y        Y     Y      jgt-imm
0x26    0x0      any     any   if (u32)dst > imm goto +offset                          Y        Y     Y      jgt32-imm
0x27    0x0      0       any   dst \*= imm                                             Y        Y     Y      mul64-imm
0x28    0x0      0       any   (deprecated, implementation-specific)                   Y        no    no     (none)
0x2c    any      0       0x00  dst = (u32)(dst \* src)                                 Y        Y     Y      mul32-reg
0x2d    any      any     0x00  if dst > src goto +offset                               Y        Y     Y      jgt-reg
0x2e    any      any     0x00  if (u32)dst > (u32)src goto +offset                     Y        Y     Y      jgt32-reg
0x2f    any      0       0x00  dst \*= src                                             Y        Y     Y      mul64-reg
0x30    0x0      0       any   (deprecated, implementation-specific)                   Y        no    no     (none)
0x34    0x0      0       any   dst = (u32)((imm != 0) ? ((u32)dst / (u32)imm) : 0)     Y        Y     Y      alu-arith
0x34    0x0      1       any   dst = (u32)((imm != 0) ? ((s32)dst s/ imm) : 0)         Y        no    Y      sdiv32-imm
0x35    0x0      any     any   if dst >= imm goto +offset                              Y        Y     Y      jge-imm
0x36    0x0      any     any   if (u32)dst >= imm goto +offset                         Y        Y     Y      jge32-imm
0x37    0x0      0       any   dst = (imm != 0) ? (dst / (u32)imm) : 0                 Y        Y     Y      alu64-arith
0x37    0x0      1       any   dst = (imm != 0) ? (dst s/ imm) : 0                     Y        no    Y      sdiv64-imm
0x3c    any      0       0x00  dst = (u32)((src != 0) ? ((u32)dst / (u32)src) : 0)     Y        Y     Y      alu-arith
0x3c    any      1       0x00  dst = (u32)((src != 0) ? ((s32)dst s/ (s32)src) : 0)    Y        no    Y      sdiv32-reg
0x3d    any      any     0x00  if dst >= src goto +offset                              Y        Y     Y      prime
0x3e    any      any     0x00  if (u32)dst >= (u32)src goto +offset                    Y        Y     Y      jge32-reg
0x3f    any      0       0x00  dst = (src !+ 0) ? (dst / src) : 0                      Y        Y     Y      alu64-arith
0x3f    any      1       0x00  dst = (src !+ 0) ? (dst s/ src) : 0                     Y        no    Y      sdiv64-reg
0x40    any      0       any   (deprecated, implementation-specific)                   Y        no    no     (none)
0x44    0x0      0       any   dst = (u32)(dst \| imm)                                 Y        Y     Y      alu-bit
0x45    0x0      any     any   if dst & imm goto +offset                               Y        Y     Y      jset-imm
0x46    0x0      any     any   if (u32)dst & imm goto +offset                          Y        Y     Y      jset32-imm
0x47    0x0      0       any   dst \|= imm                                             Y        Y     Y      alu64-bit
0x48    any      any     any   (deprecated, implementation-specific)                   Y        no    no     (none)
0x4c    any      0       0x00  dst = (u32)(dst \| src)                                 Y        Y     Y      alu-bit
0x4d    any      any     0x00  if dst & src goto +offset                               Y        Y     Y      jset-reg
0x4e    any      any     0x00  if (u32)dst & (u32)src goto +offset                     Y        Y     Y      jset32-reg
0x4f    any      0       0x00  dst \|= src                                             Y        Y     Y      alu64-bit
0x50    any      0       any   (deprecated, implementation-specific)                   Y        no    no     (none)
0x54    0x0      0       any   dst = (u32)(dst & imm)                                  Y        Y     Y      alu-bit
0x55    0x0      any     any   if dst != imm goto +offset                              Y        Y     Y      alu-arith
0x56    0x0      any     any   if (u32)dst != imm goto +offset                         Y        Y     Y      jne32-imm
0x57    0x0      0       any   dst &= imm                                              Y        Y     Y      alu64-bit
0x5c    any      0       0x00  dst = (u32)(dst & src)                                  Y        Y     Y      alu-bit
0x5d    any      any     0x00  if dst != src goto +offset                              Y        Y     Y      jne-reg
0x5e    any      any     0x00  if (u32)dst != (u32)src goto +offset                    Y        Y     Y      jne32-reg
0x5f    any      0       0x00  dst &= src                                              Y        Y     Y      alu64-bit
0x61    any      any     0x00  dst = \*(u32 \*)(src + offset)                          Y        Y     Y      ldxw
0x62    0x0      any     any   \*(u32 \*)(dst + offset) = imm                          Y        Y     Y      stw
0x63    any      any     0x00  \*(u32 \*)(dst + offset) = src                          Y        Y     Y      stxw
0x64    0x0      0       any   dst = (u32)(dst << imm)                                 Y        Y     Y      alu-bit
0x65    0x0      any     any   if dst s> imm goto +offset                              Y        Y     Y      jsgt-imm
0x66    0x0      any     any   if (s32)dst s> (s32)imm goto +offset                    Y        Y     Y      jsgt32-imm
0x67    0x0      0       any   dst <<= imm                                             Y        Y     Y      alu64-bit
0x69    any      any     0x00  dst = \*(u16 \*)(src + offset)                          Y        Y     Y      ldxh
0x6a    0x0      any     any   \*(u16 \*)(dst + offset) = imm                          Y        Y     Y      sth
0x6b    any      any     0x00  \*(u16 \*)(dst + offset) = src                          Y        Y     Y      stxh
0x6c    any      0       0x00  dst = (u32)(dst << src)                                 Y        Y     Y      alu-bit
0x6d    any      any     0x00  if dst s> src goto +offset                              Y        Y     Y      jsgt-reg
0x6e    any      any     0x00  if (s32)dst s> (s32)src goto +offset                    Y        Y     Y      jsgt32-reg
0x6f    any      0       0x00  dst <<= src                                             Y        Y     Y      lsh-reg
0x71    any      any     0x00  dst = \*(u8 \*)(src + offset)                           Y        Y     Y      ldxb
0x72    0x0      any     any   \*(u8 \*)(dst + offset) = imm                           Y        Y     Y      stb
0x73    any      any     0x00  \*(u8 \*)(dst + offset) = src                           Y        Y     Y      stxb
0x74    0x0      0       any   dst = (u32)(dst >> imm)                                 Y        Y     Y      rsh32
0x75    0x0      any     any   if dst s>= imm goto +offset                             Y        Y     Y      jsge-imm
0x76    0x0      any     any   if (s32)dst s>= (s32)imm goto +offset                   Y        Y     Y      jsge32-imm
0x77    0x0      0       any   dst >>= imm                                             Y        Y     Y      alu64-bit
0x79    any      any     0x00  dst = \*(u64 \*)(src + offset)                          Y        Y     Y      ldxdw
0x7a    0x0      any     any   \*(u64 \*)(dst + offset) = imm                          Y        Y     Y      stdw
0x7b    any      any     0x00  \*(u64 \*)(dst + offset) = src                          Y        Y     Y      stxdw
0x7c    any      0       0x00  dst = (u32)(dst >> src)                                 Y        Y     Y      alu-bit
0x7d    any      any     0x00  if dst s>= src goto +offset                             Y        Y     Y      jsge-reg
0x7e    any      any     0x00  if (s32)dst s>= (s32)src goto +offset                   Y        Y     Y      jsge32-reg
0x7f    any      0       0x00  dst >>= src                                             Y        Y     Y      rsh-reg
0x84    0x0      0       0x00  dst = (u32)-dst                                         Y        Y     Y      neg
0x85    0x0      0       any   call helper function by static ID                       Y        Y     Y      call_unwind_fail
0x85    0x1      0       any   call PC += imm                                          no       no    no     call_local
0x85    0x2      0       any   call helper function by BTF ID                          no       no    no     ???
0x87    0x0      0       0x00  dst = -dst                                              Y        Y     Y      neg64
0x8d    0x0      0       0x00  call helper function by static ID in register           Y        Y     no     callx
0x94    0x0      0       any   dst = (u32)((imm != 0) ? ((u32)dst % (u32)imm) : dst)   Y        Y     Y      mod
0x94    0x0      1       any   dst = (u32)((imm != 0) ? ((s32)dst s% imm) : dst)       Y        no    Y      smod32-neg-by-neg-imm
0x95    0x0      0       0x00  return                                                  Y        Y     Y      exit
0x97    0x0      0       any   dst = (imm != 0) ? (dst % (u32)imm) : dst               Y        Y     Y      mod64
0x97    0x0      1       any   dst = (imm != 0) ? (dst s% imm) : dst                   Y        no    Y      smod64-neg-by-neg-imm
0x9c    any      0       0x00  dst = (u32)((src != 0) ? ((u32)dst % (u32)src) : dst)   Y        Y     Y      mod
0x9c    any      1       0x00  dst = (u32)((src != 0) ? ((s32)dst s% (s32)src) : dst)  Y        no    Y      smod32-neg-by-neg-reg
0x9f    any      0       0x00  dst = (src != 0) ? (dst % src) : dst                    Y        Y     Y      mod64
0x9f    any      1       0x00  dst = (src != 0) ? (dst s% src) : dst                   Y        no    Y      smod64-neg-by-neg-reg
0xa4    0x0      0       any   dst = (u32)(dst ^ imm)                                  Y        Y     Y      alu-bit
0xa5    0x0      any     any   if dst < imm goto +offset                               Y        Y     Y      jlt-imm
0xa6    0x0      any     any   if (u32)dst < imm goto +offset                          Y        Y     Y      jlt32-imm
0xa7    0x0      0       any   dst ^= imm                                              Y        Y     Y      alu64-bit
0xac    any      0       0x00  dst = (u32)(dst ^ src)                                  Y        Y     Y      alu-bit
0xad    any      any     0x00  if dst < src goto +offset                               Y        Y     Y      jlt-reg
0xae    any      any     0x00  if (u32)dst < (u32)src goto +offset                     Y        Y     Y      jlt32-reg
0xaf    any      0       0x00  dst ^= src                                              Y        Y     Y      alu64-bit
0xb4    0x0      0       any   dst = (u32) imm                                         Y        Y     Y      mov
0xb5    0x0      any     any   if dst <= imm goto +offset                              Y        Y     Y      jle-imm
0xb6    0x0      any     any   if (u32)dst <= imm goto +offset                         Y        Y     Y      jle32-imm
0xb7    0x0      0       any   dst = imm                                               Y        Y     Y      mov64-sign-extend
0xbc    any      0       0x00  dst = (u32) src                                         Y        Y     Y      mov
0xbc    any      8       0x00  dst = (u32) (s32) (s8) src                              Y        no    Y      movsx832-reg
0xbc    any      16      0x00  dst = (u32) (s32) (s16) src                             Y        no    Y      movsx1632-reg
0xbd    any      any     0x00  if dst <= src goto +offset                              Y        Y     Y      jle-reg
0xbe    any      any     0x00  if (u32)dst <= (u32)src goto +offset                    Y        Y     Y      jle32-reg
0xbf    any      0       0x00  dst = src                                               Y        Y     Y      ldxb-all
0xbf    any      8       0x00  dst = (s64) (s8) src                                    Y        no    Y      movsx864-reg
0xbf    any      16      0x00  dst = (s64) (s16) src                                   Y        no    Y      movsx1664-reg
0xbf    any      32      0x00  dst = (s64) (s32) src                                   Y        no    Y      movsx3264-reg
0xc3    any      any     0x00  lock \*(u32 \*)(dst + offset) += src                    Y        no    Y      lock_add32
0xc3    any      any     0x01  src = atomic_fetch_add_32((u32 \*)(dst + offset), src)  Y        no    Y      lock_fetch_add32
0xc3    any      any     0x40  lock \*(u32 \*)(dst + offset) \|= src                   Y        no    Y      lock_or32
0xc3    any      any     0x41  src = atomic_fetch_or_32((u32 \*)(dst + offset), src)   Y        no    Y      lock_fetch_or32
0xc3    any      any     0x50  lock \*(u32 \*)(dst + offset) &= src                    Y        no    Y      lock_and32
0xc3    any      any     0x51  src = atomic_fetch_and_32((u32 \*)(dst + offset), src)  Y        no    Y      lock_fetch_and32
0xc3    any      any     0xa0  lock \*(u32 \*)(dst + offset) ^= src                    Y        no    Y      lock_xor32
0xc3    any      any     0xa1  src = atomic_fetch_xor_32((u32 \*)(dst + offset), src)  Y        no    Y      lock_fetch_xor32
0xc3    any      any     0xe1  src = xchg_32((u32 \*)(dst + offset), src)              Y        no    Y      lock_xchg32
0xc3    any      any     0xf1  r0 = cmpxchg_32((u32 \*)(dst + offset), r0, src)        Y        no    Y      lock_cmpxchg32
0xc4    0x0      0       any   dst = (u32)(dst s>> imm)                                Y        Y     Y      arsh
0xc5    0x0      any     any   if dst s< imm goto +offset                              Y        Y     Y      jslt-imm
0xc6    0x0      any     any   if (s32)dst s< (s32)imm goto +offset                    Y        Y     Y      jslt32-imm
0xc7    0x0      0       any   dst s>>= imm                                            Y        Y     Y      arsh64
0xcc    any      0       0x00  dst = (u32)(dst s>> src)                                Y        Y     Y      arsh-reg
0xcd    any      any     0x00  if dst s< src goto +offset                              Y        Y     Y      jslt-reg
0xce    any      any     0x00  if (s32)dst s< (s32)src goto +offset                    Y        Y     Y      jslt32-reg
0xcf    any      0       0x00  dst s>>= src                                            Y        Y     Y      arsh64
0xd4    0x0      0       0x10  dst = htole16(dst)                                      Y        Y     Y      le16
0xd4    0x0      0       0x20  dst = htole32(dst)                                      Y        Y     Y      le32
0xd4    0x0      0       0x40  dst = htole64(dst)                                      Y        Y     Y      le64
0xd5    0x0      any     any   if dst s<= imm goto +offset                             Y        Y     Y      jsle-imm
0xd6    0x0      any     any   if (s32)dst s<= (s32)imm goto +offset                   Y        Y     Y      jsle32-imm
0xd7    0x0      0       0x10  dst = bswap16(dst)                                      Y        no    Y      swap16
0xd7    0x0      0       0x20  dst = bswap32(dst)                                      Y        no    Y      swap32
0xd7    0x0      0       0x40  dst = bswap64(dst)                                      Y        no    Y      swap64
0xdb    any      any     0x00  lock \*(u64 \*)(dst + offset) += src                    Y        no    Y      lock_add
0xdb    any      any     0x01  src = atomic_fetch_add_64((u64 \*)(dst + offset), src)  Y        no    Y      lock_fetch_add
0xdb    any      any     0x40  lock \*(u64 \*)(dst + offset) \|= src                   Y        no    Y      lock_or
0xdb    any      any     0x41  src = atomic_fetch_or_64((u64 \*)(dst + offset), src)   Y        no    Y      lock_fetch_or
0xdb    any      any     0x50  lock \*(u64 \*)(dst + offset) &= src                    Y        no    Y      lock_and
0xdb    any      any     0x51  src = atomic_fetch_and_64((u64 \*)(dst + offset), src)  Y        no    Y      lock_fetch_and
0xdb    any      any     0xa0  lock \*(u64 \*)(dst + offset) ^= src                    Y        no    Y      lock_xor
0xdb    any      any     0xa1  src = atomic_fetch_xor_64((u64 \*)(dst + offset), src)  Y        no    Y      lock_fetch_xor
0xdb    any      any     0xe1  src = xchg_64((u64 \*)(dst + offset), src)              Y        no    Y      lock_xchg
0xdb    any      any     0xf1  r0 = cmpxchg_64((u64 \*)(dst + offset), r0, src)        Y        no    Y      lock_cmpxchg
0xdc    0x0      0       0x10  dst = htobe16(dst)                                      Y        Y     Y      be16
0xdc    0x0      0       0x20  dst = htobe32(dst)                                      Y        Y     Y      be32
0xdc    0x0      0       0x40  dst = htobe64(dst)                                      Y        Y     Y      be64
0xdd    any      any     0x00  if dst s<= src goto +offset                             Y        Y     Y      jsle-reg
0xde    any      any     0x00  if (s32)dst s<= (s32)src goto +offset                   Y        Y     Y      jsle32-reg
======  =======  ======  ====  ======================================================  =======  ====  =====  ======================

**Some takeaways:**

* The conformance suite does not support most 64-bit immediate instructions
  (https://github.com/Alan-Jowett/bpf_conformance/issues/59).
