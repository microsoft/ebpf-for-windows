# Pre-Authoring Analysis

## Ambiguities in this area

- [KNOWN] The source states that providers must be signed according to Windows driver signing requirements, but it does not restate those external signing requirements in this document. (Source: `docs/BtfResolvedFunctions.md:470-473`)
- [KNOWN] The source requires providers not to expose security-sensitive operations without proper authorization, but it does not define the authorization mechanism in this document. (Source: `docs/BtfResolvedFunctions.md:487-490`)

## Implicit requirements in this area

- [INFERRED] Security guarantees depend on both verifier-time validation and provider-side runtime discipline, because the source assigns some checks to the verifier and others to the provider. (Source: `docs/BtfResolvedFunctions.md:475-490`)

## Actual or possible conflicts

- [KNOWN] Future per-program authorization is explicitly described as a future consideration, so current-scope requirements must not assume that such a mechanism already exists. (Source: `docs/BtfResolvedFunctions.md:499-502`)

## Coverage statement

- **Examined:** Section 11 Security Considerations.
- **Method:** extracted provider-authentication, verification-guarantee, and isolation/security-duty requirements.
- **Excluded:** roadmap items described only in the future-considerations section.
- **Limitations:** external Windows signing and authorization mechanisms are not defined in this source.

# Security Considerations — Requirements Document

## 1. Overview

[KNOWN] This area defines the security posture of the BTF-resolved function feature. The source assigns authentication to Windows driver-signing enforcement, verification-time callable-contract checks to the verifier, and argument-validation plus authorization discipline to providers. (Source: `docs/BtfResolvedFunctions.md:470-490`)

[KNOWN] The source also ties proof-of-verification security to the inclusion of BTF-resolved function dependencies in the program-info hash. (Source: `docs/BtfResolvedFunctions.md:477-483`)

## 2. Scope

### 2.1 In Scope

- [KNOWN] Provider authentication model. (Source: `docs/BtfResolvedFunctions.md:470-473`)
- [KNOWN] Verifier security guarantees for prototypes, argument types, and return-value handling. (Source: `docs/BtfResolvedFunctions.md:475-480`)
- [KNOWN] Proof-of-verification dependency coverage. (Source: `docs/BtfResolvedFunctions.md:482-483`)
- [KNOWN] Provider isolation responsibilities. (Source: `docs/BtfResolvedFunctions.md:485-490`)

### 2.2 Out of Scope

- [KNOWN] Future per-program authorization mechanisms, because the source marks them as future considerations rather than baseline scope. (Source: `docs/BtfResolvedFunctions.md:499-502`)
- [KNOWN] Dynamic function discovery, because the source marks it as a future consideration. (Source: `docs/BtfResolvedFunctions.md:504-507`)

## 3. Definitions and Glossary

| Term | Definition |
| --- | --- |
| Provider authentication | [KNOWN] The source model in which Windows driver-signing requirements authenticate provider drivers, with no additional authentication performed by the eBPF runtime. (Source: `docs/BtfResolvedFunctions.md:470-473`) |
| Isolation duty | [KNOWN] The provider-side responsibility to validate arguments, honor execution-IRQL safety, and avoid exposing sensitive operations without authorization. (Source: `docs/BtfResolvedFunctions.md:487-490`) |

## 4. Requirements

### 4.1 Functional Requirements

[KNOWN] REQ-SEC-001: A BTF-resolved function provider MUST be a kernel driver that satisfies Windows driver-signing requirements, so that provider authentication is delegated to the Windows kernel-driver trust model. (Source: `docs/BtfResolvedFunctions.md:470-473`)

Acceptance Criteria:
- [INFERRED] AC-1: The security requirements identify Windows driver signing as the required authentication basis for providers. (Source: `docs/BtfResolvedFunctions.md:470-473`)

[KNOWN] REQ-SEC-002: The eBPF runtime MUST NOT perform additional provider authentication beyond what Windows enforces for signed drivers, so that the authentication model matches the documented source scope. (Source: `docs/BtfResolvedFunctions.md:472-473`)

Acceptance Criteria:
- [INFERRED] AC-1: The security requirements do not introduce an extra runtime-side provider-authentication layer absent from the source. (Source: `docs/BtfResolvedFunctions.md:472-473`)

[KNOWN] REQ-SEC-003: The verifier MUST validate that every BTF-resolved function call has a valid registered prototype, so that programs cannot call undeclared provider functions. (Source: `docs/BtfResolvedFunctions.md:477-479`)

Acceptance Criteria:
- [INFERRED] AC-1: The security requirements treat registered-prototype validation as a mandatory verifier check. (Source: `docs/BtfResolvedFunctions.md:477-479`)

[KNOWN] REQ-SEC-004: The verifier MUST validate that argument types match the declared prototype and that return values are handled correctly, so that verified programs conform to provider callable contracts. (Source: `docs/BtfResolvedFunctions.md:478-480`)

Acceptance Criteria:
- [INFERRED] AC-1: The security requirements preserve argument-type validation and return-value handling as distinct mandatory checks. (Source: `docs/BtfResolvedFunctions.md:478-480`)

[KNOWN] REQ-SEC-005: The proof-of-verification material MUST include BTF-resolved function dependencies, so that a signed native module cannot call BTF-resolved functions that were absent during verification. (Source: `docs/BtfResolvedFunctions.md:482-483`)

Acceptance Criteria:
- [INFERRED] AC-1: The security requirements explicitly tie proof-of-verification protection to dependency inclusion rather than to provider signing alone. (Source: `docs/BtfResolvedFunctions.md:482-483`)

[KNOWN] REQ-SEC-006: Each BTF-resolved function provider MUST validate arguments received from eBPF programs, so that provider implementations do not rely solely on eBPF-side behavior for runtime safety. (Source: `docs/BtfResolvedFunctions.md:487-488`)

Acceptance Criteria:
- [INFERRED] AC-1: The security requirements assign argument-validation responsibility to providers, not only to the verifier. (Source: `docs/BtfResolvedFunctions.md:487-488`)

[KNOWN] REQ-SEC-007: Each BTF-resolved function provider MUST ensure safe execution at the IRQL where eBPF programs run, so that provider implementations remain safe in the runtime execution context. (Source: `docs/BtfResolvedFunctions.md:488-489`)

Acceptance Criteria:
- [INFERRED] AC-1: The security requirements retain IRQL safety as a provider obligation in addition to the callable-signature constraint documented elsewhere. (Source: `docs/BtfResolvedFunctions.md:488-489`)

[KNOWN] REQ-SEC-008: Each BTF-resolved function provider MUST NOT expose security-sensitive operations without proper authorization, so that callable functionality does not bypass provider-defined access controls. (Source: `docs/BtfResolvedFunctions.md:489-490`)

Acceptance Criteria:
- [INFERRED] AC-1: The security requirements define a negative requirement prohibiting unauthorized exposure of sensitive operations. (Source: `docs/BtfResolvedFunctions.md:489-490`)

### 4.2 Non-Functional Requirements

[KNOWN] REQ-SEC-009: Security guarantees for BTF-resolved functions MUST combine verifier-time callable-contract enforcement with provider-side runtime validation duties, so that no single layer is treated as a complete security boundary. (Source: `docs/BtfResolvedFunctions.md:475-490`)

Acceptance Criteria:
- [INFERRED] AC-1: The security requirements include at least one verifier-side control and at least one provider-side control. (Source: `docs/BtfResolvedFunctions.md:475-490`)

### 4.3 Constraints

- [UNKNOWN: the specific external Windows driver-signing rules are not defined in this source document.] (Source: `docs/BtfResolvedFunctions.md:470-473`)
- [UNKNOWN: the authorization mechanism for security-sensitive operations is not defined in this source document.] (Source: `docs/BtfResolvedFunctions.md:489-490`)

## 5. Dependencies

- DEP-SEC-001: This requirement set depends on `04-verifier-integration.md`, `05-bpf2c-integration.md`, and `08-runtime-execution.md` because security guarantees rely on verification behavior, proof-of-verification hashing, and runtime/provider behavior. Impact if unavailable: security obligations cannot be traced to concrete feature areas. (Source: `docs/BtfResolvedFunctions.md:477-490`)

## 6. Assumptions

- ASM-001: [ASSUMPTION] Providers have their own authorization model for sensitive operations even though the mechanism is not defined in this source. If this assumption is wrong, an explicit authorization-interface requirement is needed. Justification: the source requires proper authorization but does not define the mechanism. (Source: `docs/BtfResolvedFunctions.md:489-490`)

## 7. Risks

| Risk ID | Description | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- | --- |
| RISK-SEC-001 | [KNOWN] Provider-side failure to validate arguments or honor IRQL safety can undermine runtime safety even after verification succeeds. (Source: `docs/BtfResolvedFunctions.md:487-489`) | Medium | High | [INFERRED] Keep provider responsibilities explicit and non-optional. |
| RISK-SEC-002 | [KNOWN] Omitting BTF-resolved function dependencies from proof-of-verification material would allow a signed native module to drift from the verified callable set. (Source: `docs/BtfResolvedFunctions.md:482-483`) | Medium | High | [INFERRED] Trace this requirement directly to `05-bpf2c-integration.md`. |

## 8. Revision History

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 0.1 | 2026-06-02 | Copilot | Initial security requirements extracted from `docs/BtfResolvedFunctions.md`. |
