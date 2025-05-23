# eBPF Proof of Verification

## Overview
A key difference between eBPF for Linux vs eBPF for Windows is where and when the verification process is run. On
Linux, verification is performed in the kernel when the BPF program is loaded, with the verifier performing both
verification and generation of native machine code (JIT). On Windows, the verification and generation of native
machine code is performed offline as part of the build process.

## Problem statement
Unlike Linux, verification of the BPF program is decoupled from the loading of the BPF program. Verification occurs
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
in a tamper resistant manner. For developers, the aspirational goal is to have a new Microsoft hosted service (similar
to Hardware Development Center) that will own and maintain the pipeline, with developers submitting their eBPF programs
to the pipeline in the form of an ELF file containing the BPF byte code.
The pipeline would invoke the verifier, generate the native image, sign it using the new certificate type, and then
finally return the generated and signed native image to the developer. In the short term the pipeline would be owned
and managed by the Microsoft component of the eBPF for Windows team.

### Signature Verification
The check will be performed in user mode prior to loading the PE image into kernel using the standard WinVerifyTrust
API.
