# Forge Crypto Design Note

## 1. Scope and Security Goals

This note defines the cryptographic design contract for Forge security-sensitive flows:

- secret custody and persistence
- key-wrapping and rewrap workflows
- integrity binding for high-trust release paths
- retained evidence artifacts for audit and release gates

Goals:

- fail closed when integrity or policy checks fail
- prevent plaintext secret persistence
- keep key material outside primary runtime state stores
- preserve operator-visible and machine-readable evidence

## 2. Threat Model

Primary threat classes:

- local storage disclosure (workspace, cache, logs, crash artifacts)
- process-introspection leakage (`/proc`, command-line, inherited env)
- tampered runtime/update artifacts
- policy bypass via persisted state or extension/MCP lanes
- replay and identity mismatch in confidential relay release binding

Out of scope for this note:

- physical attacks requiring compromised firmware plus invasive hardware access
- nation-state side-channel hardening beyond current platform controls

## 3. Secret Custody and Delivery

Forge uses brokered secret custody:

- secret values are stored in broker-managed memory, not inline in user prompts
- launch-time secret delivery uses stdin-style one-shot payloads for handle-backed values
- secret-like command-line and unsafe environment delivery paths are blocked

Required invariants:

- no plaintext secret persistence in standard runtime stores
- no secret-bearing CLI arguments
- revocation/rotation paths clear retained secret bytes

## 4. Envelope Encryption and KEK Model

Persisted broker state uses AES-256 envelope encryption.

- data encryption uses per-record material under broker control
- key-encryption keys (KEKs) remain external to primary persisted secret data
- platform-specific KEK custody adapters (including Linux custody chain) are supported
- rewrap workflows are explicit and auditable

## 5. Algorithms and Parameter Baseline

Current cryptographic baseline:

- AES-256-GCM for authenticated encryption
- Argon2id for passphrase-based KEK derivation flows
- Ed25519 signatures for signed extension manifest verification
- SHA-256 for deterministic digest artifacts and release binding inputs

Parameter tuning and benchmark evidence are retained via dedicated artifacts (for example Argon2id benchmark reports).

## 6. Integrity, Signing, and Release Binding

Integrity controls include:

- signed extension manifest verification against trusted signers
- runtime update artifact digest verification with optional signature/provenance enforcement
- deterministic release-binding artifacts for confidential relay records

Any attestation/policy/identity mismatch on confidential relay paths must fail closed.

## 7. Rotation, Revocation, and Recovery

Required operations:

- KEK rotation and encrypted-store rewrap without plaintext persistence
- token/session revocation on disable/quarantine/session-end events
- quarantine-aware restore/import controls with retained evidence digests

Restore paths must re-validate security policy contracts; persisted state cannot bypass signature or permission gates.

## 8. Evidence and Audit Artifacts

Required retained artifacts include:

- KEK custody matrix by OS
- Argon2id benchmark report
- nonce-uniqueness regression report
- secret-leak and process/coredump validation reports
- supply-chain/update integrity reports
- this crypto design note

Release gates consume these artifacts and fail closed if required evidence is missing or invalid.

## 9. Residual Risks and Follow-ups

Residual risks:

- platform variance in optional hardware-rooted custody capabilities
- operator misconfiguration for explicit opt-in remote egress and trust-policy controls

Follow-ups:

- periodically review algorithm/parameter choices against current guidance
- extend provenance/signature enforcement for additional runtime distribution paths
