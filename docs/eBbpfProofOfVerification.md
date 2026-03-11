# eBPF Proof of Verification

## Overview
A key difference between eBPF for Linux vs eBPF for Windows is where and when the verification process is run. On
Linux, verification is performed in the kernel when the BPF program is loaded, with the verifier performing both
verification and generation of native machine code (JIT). On Windows when using JIT mode the verification and
generation of machine code occurs in a user mode service. On Windows when using native images, the verification and
generation of machine code is performed offline as part of the build process.

## Problem statement
For native images, verification of the BPF program is decoupled from the loading of the BPF program. Verification occurs
ahead of time as part of the build process and the data required to perform the verification is not available at
runtime. Without a mechanism to validate that the BPF program being loaded has been verified, the goal of ensuring that
all BPF programs operate in a statically enforced sandbox is weakened.

## Proposed solution
All BPF programs that are executed in kernel are accompanied by proof of verification, in the form of a digital
signature that has been generated after the BPF program was verified and the native image generated.

### Certificate used for signing
PE images can contain multiple embedded signatures as well as being signed via a catalog signature. Kernel code
integrity policy verifies that there is at least one signature that has been issued by a known trusted certificate
authority and contains one of the following sets of EKUs (Extended Key Usage). It is possible other combinations may be
supported.
•	Code Signing EKU (1.3.6.1.5.5.7.3.3) + Windows System Component Verification EKU (1.3.6.1.4.1.311.10.3.6)
•	Code Signing EKU (1.3.6.1.5.5.7.3.3) + Windows Hardware Driver Verification EKU (1.3.6.1.4.1.311.10.3.5)
The proposal is for eBPF for Windows to have a new type of code signing certificate created and hosted by Microsoft.
The certificate would contain the Code Signing EKU along with a newly defined EKU that is used to denote that the
associated PE image was generated from a verified BPF program. The issuing authority for the certificate will be a new
issuing authority that chains up to one of the existing trusted roots.

### Build pipeline
To ensure that BPF programs are verified, the verification and native image generation needs to be performed atomically
in a tamper-resistant manner. For developers, the aspirational goal is to have a new Microsoft hosted service (similar
to Hardware Development Center) that will own and maintain the pipeline, with developers submitting their eBPF programs
to the pipeline in the form of an ELF file containing the BPF byte code.
The pipeline would invoke the verifier, generate the native image, sign it using the new certificate type, and then
finally return the generated and signed native image to the developer. In the short term the pipeline would be owned
and managed by the eBPF for Windows team at Microsoft.

### Signature Verification
Prior to loading an native BPF program, the following sequence is performed:
1) eBPF user-mode calls into the eBPF service to request verification of the native image.
2) eBPF service validates the signature of the native image using WinVerifyTrust.
3) eBPF service computes the cryptographic hash of the native image and calls into the eBPF kernel-mode to authorize
this native image, passing the hash.
4) After the native image is loaded and during the NMR attach, eBPF kernel-mode resolves the path of the native image,
computes the cryptographic hash and checks if it is has been authorized.
5) If the hash is authorized, the eBPF kernel mode permits the native image to attach.

Note:
The eBPF kernel-mode validates that the call is coming from the eBPF service by checking that it has the correct
service SID and only allows authorization from that service.

### Program Info Hash Contents

The program info hash computed during verification includes all invariants that affect program safety. This ensures
that a signed native module cannot be used in an environment different from the one it was verified against.

The hash includes:
1. `ebpf_program_type_descriptor_t` fields (name, context_descriptor, program_type, bpf_prog_type, is_privileged)
2. Count of helper IDs being used
3. For each helper function used (in order of ID):
   - `ebpf_helper_function_prototype_t` fields (helper_id, name, return_type, arguments, and flags when
     `reallocate_packet` is set)

#### Planned BTF-resolved Function Dependencies

Current implementation hashes program type descriptor information and helper prototypes as described above.
BTF-resolved function dependencies are a planned extension for BTF-resolved function support.

Once implemented, if the program uses BTF-resolved functions, the hash will also include:

4. Count of BTF-resolved functions being used
5. For each BTF-resolved function used (in deterministic order by module GUID, then function name):
   - `btf_resolved_function_entry_t::name`
   - `btf_resolved_function_entry_t::module_guid`
   - `ebpf_btf_resolved_function_prototype_t::return_type`
   - Each element of `ebpf_btf_resolved_function_prototype_t::arguments`
   - `ebpf_btf_resolved_function_prototype_t::flags` (only if non-default)

Including BTF-resolved function dependencies in the hash will ensure that:
- A native module verified with BTF-resolved function provider version X cannot run with version Y if signatures differ
- The module GUID ties the verification to a specific BTF-resolved function provider
- Changes to BTF-resolved function prototypes invalidate the verification

For more information on BTF-resolved functions, see [BtfResolvedFunctions.md](BtfResolvedFunctions.md).
