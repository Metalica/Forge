# Forge

**Local-first AI workstation control plane for one PC.**

Forge is a Rust-native workstation built to make one machine, especially an older or constrained one. Do more useful work with less waste.

It combines coding, local AI, agents, media jobs, runtime management, and clear execution visibility in one native desktop app.

Forge treats **CPU, RAM, GPU, and VRAM as a coordinated execution fabric**, not a fake merged-memory claim.

## Status

Current direction already includes:

- native Rust desktop shell
- Egui UI
- managed `llama.cpp`
- Runtime Registry
- Agent Studio
- source routing
- media queue foundations
- Windows and Linux active scope

## What Forge is

Forge is:

- a local-first AI workstation
- a Rust-native desktop application
- a single-PC orchestration layer
- a hardware-aware execution system
- a runtime-managed local AI environment

## What Forge is not

- just a chat app
- just a model launcher
- just an IDE with AI glued on
- a browser shell pretending to be native
- cloud-first software disguised as local
- fake “unified memory” marketing

## Core principles

- local-first
- hardware-aware
- native desktop UI
- measured performance only
- safe defaults on weak hardware
- explicit runtime and fallback visibility

## What it includes

- coding workspace
- local LLM support
- agent workflows
- image job paths
- runtime lifecycle management
- source registry
- job queue
- resource telemetry
- optional confidential relay

### Work in progress

- **GPU execution layer - Backlog.**
- **macOS is planned for the future.**
- **AES-256 Encryption + Confidential Relay - Work in progress.**

## Security

Forge is privacy-first, but not dishonest.

Security direction includes:

- no hidden telemetry
- no silent local-to-remote downgrade
- broker-based secret handling
- AES-256 envelope-encrypted secret persistence
- no secrets on command line
- stdin / pipe / fd-based secret injection
- workspace boundary hardening
- explicit provenance and trust labels
- confidential relay kept separate from normal local execution

Confidential relay reference:
- https://openreview.net/pdf?id=ey87M5iKcX

## Product rule

Forge does not fake power.

It aims to make constrained PCs more organized, efficient, predictable, and useful.

## License

**Apache-2.0**
