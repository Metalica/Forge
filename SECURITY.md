# Security

Forge is built around three security rules:

- **local-first by default**
- **fail-closed on dangerous paths**
- **transparent execution and policy state**

Security in Forge is not hidden behind marketing language. If a task touches secrets, network, remote execution, fallback, or other high-trust actions, the user should be able to see what happened, why it happened, and which policy allowed it.

## Principles

Forge security follows these rules:

- no hidden telemetry
- no plaintext secret persistence
- no secrets on command line
- no silent network escalation
- no silent local-to-remote downgrade
- no hidden execution
- no policy bypass through sidecars, extensions, tools, or local APIs
- no trust of model output without validation
- all instruction-bearing external content is treated as untrusted input by default

This includes docs, prompts, tool outputs, manifests, configs, screenshots, MCP data, and retrieved content.

## Local-first

Forge is **local-first, not local-only**.

Local execution is the default path. Remote or API execution is allowed only when local fit, quality, or policy requires it. There is no hidden cloud execution.

Users should be able to see:

- whether execution was local, sidecar, remote, confidential, or fallback
- why that route was selected
- what policy allowed it

## Transparency

Forge treats transparency as a security feature.

Dangerous paths must produce visible and auditable evidence, including:

- where execution happened
- which policy allowed or denied it
- whether fallback occurred
- whether attestation and encryption were validated
- whether the action required approval

User-visible execution state must match actual runtime state.

## Secrets

Forge uses a brokered secret model.

Security direction includes:

- broker-based secret custody
- AES-256 envelope-encrypted secret persistence
- KEK kept outside LMDB
- audit metadata only, not plaintext secret bodies
- no plaintext provider secret storage
- no secret material in normal logs

Secrets must not be passed on the command line. Forge blocks secret-like CLI arguments and secret-bearing environment delivery paths. Secret injection is designed around stdin / pipe / memfd / fd-style delivery instead.

## Trust boundaries

Forge defaults to **workspace-only** boundaries.

Security hardening direction includes:

- canonical path re-checks
- blocking symlink, hardlink, and archive escapes
- isolated temp space per task
- explicit trust labels and provenance for model-visible inputs

Untrusted content may influence summaries or outputs, but it must not silently grant network, relay, secret, or host permissions.

## Extensions, MCP, and tools

Extensions and MCP integrations are not allowed to bypass:

- permissions
- runtime registry
- telemetry
- secret broker
- execution visibility
- policy checks

Security direction also includes:

- signed extension manifests
- capability-scoped permissions
- separate sandboxing for skills, workflows, and scripts
- no inherited secret or network access by default
- scoped MCP tokens
- audience checks
- revocation on session end

Unsigned or over-broad extensions should be blocked or require explicit approval.

## Confidential Relay

Forge may include an **optional** confidential relay mode.

This is not the default execution model and not a replacement for normal local execution.

Confidential relay is intended to remain:

- opt-in
- visibly remote
- attestation-gated
- fail-closed on mismatch
- separate from the normal local runtime path

If attestation, policy, or transport guarantees do not match expectations, prompt release must fail. No silent downgrade to a standard remote API is allowed.

Research reference:
- https://openreview.net/forum?id=ey87M5iKcX&utm_source=chatgpt.com
- https://openreview.net/pdf?id=ey87M5iKcX

## Reporting a vulnerability

Please **do not** open a public GitHub issue for suspected security vulnerabilities.

Use one of these channels instead:

1. **GitHub Private Vulnerability Reporting** for this repository, if enabled
2. **Email:** `security@replace-this-domain.example`

If neither exists yet, add one before public release.

When reporting, include:

- affected version, branch, or commit
- component or crate involved
- clear impact description
- reproduction steps
- proof of concept, logs, screenshots, or traces if safe to share
- whether secrets, remote execution, fallback, policy bypass, or workspace escape are involved
- any suggested fix or mitigation

Please avoid public disclosure until the issue has been reviewed and a fix or mitigation is ready.

## What maintainers should do

Maintainers should:

- acknowledge receipt quickly
- reproduce and validate the issue
- assess impact and affected trust boundaries
- fix with fail-closed behavior
- add regression coverage
- publish a clear remediation note once safe

High-severity issues should block release.

## Scope note

Forge does not claim security by language alone.

Nothing in Forge should be called secure, local-first, or hardware-aware unless the code path itself proves it through:

- explicit placement
- explicit policy
- visible execution state
- reviewed boundaries
- resource accounting
- fail-closed behavior
