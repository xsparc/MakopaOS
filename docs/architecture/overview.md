# MakopaOS architecture

- Status: Proposed
- Baseline: `507428c3d98a8b6cea06d6cd9800cb6f0aa002e1`
- Prepared: 2026-08-10

## Vision

MakopaOS is a small, inspectable systems laboratory for capability-oriented
workload isolation. It should teach the path from firmware entry to isolated
execution while exploring a practical question: how can an operating system
make delegated work safe by construction?

The answer belongs at ordinary systems boundaries. Code receives only the
handles it needs, high-impact effects require explicit authority, and every
accepted effect is observable. The kernel does not interpret natural-language
intent, choose a model provider, or trust a workload because of how it was
created.

## Product principles

1. **Boot something real.** Every milestone must produce a bootable image in
   QEMU before adding another abstraction.
2. **Mechanism below policy.** The kernel supplies isolation, IPC, capability
   checks, time, and event transport. User-space services decide policy.
3. **No ambient authority.** A task starts with an explicit capability set;
   absent capability means denied access.
4. **Small trusted core.** New kernel code uses `no_std` Rust, with assembly and
   `unsafe` Rust confined to documented architecture boundaries.
5. **Deterministic evidence.** Builds and tests produce machine-checkable
   results. Security-relevant state changes emit structured records.
6. **Protocol independence.** MCP, A2A, WASI, or future protocols may be exposed
   by replaceable user-space gateways, never coupled to the kernel ABI.
7. **Virtual-first development.** QEMU is the reference platform until a
   milestone explicitly adds tested hardware support.

## Target structure

```text
firmware
  legacy BIOS diagnostic      UEFI x86-64 loader
              \               /
               boot handoff contract
                         |
              memory-safe kernel core
       memory | tasks | IPC | capabilities | events
                         |
       isolated services and workload supervisor
       console | storage | clock | audit | policy
                         |
              optional protocol gateways
                WASI | MCP | A2A | others
```

### Boot boundary

The existing BIOS sector remains a minimal diagnostic and historical first
milestone. A separate UEFI loader becomes the primary x86-64 path. Both paths
must eventually produce a versioned handoff structure rather than exposing
firmware details throughout the kernel.

### Kernel core

The kernel owns page allocation, address spaces, interrupt dispatch, task
scheduling, IPC endpoints, and unforgeable capability handles. It does not own
network protocols, credentials, model inference, package resolution, or
workflow policy.

### Service boundary

Drivers and services run outside the smallest privileged core when the
architecture can support it. The first service contract covers console output,
a monotonic clock, and an append-only event channel. Services receive
capabilities at launch and may pass attenuated capabilities through IPC.

### Workload boundary

The first portable workload target is a deliberately small component ABI. A
WASI component host is a later candidate because its typed imports map naturally
to explicit capabilities, but it is not part of the kernel and is not required
for early milestones.

External agent and tool protocols terminate in user space. Gateways translate
protocol requests into typed local operations, validate inputs, and request
capabilities from policy. Content received from repositories, web pages, or
messages remains untrusted data and cannot grant itself authority.

## Security model

The initial threat model assumes a malformed or hostile workload, malicious
external content, confused-deputy attempts, replayed requests, and accidental
overreach by otherwise valid software. It does not initially claim resistance
to physical attacks, hostile firmware, side channels, or a compromised compiler.

Security invariants:

- capability identifiers cannot be guessed or forged;
- capabilities are scoped, transferable only by policy, and revocable where
  the underlying resource permits it;
- network, storage, device, and credential access are absent by default;
- protocol input and model output never bypass typed validation;
- high-impact or irreversible operations cross an explicit approval boundary;
- audit records describe accepted effects without storing secret values;
- the boot image and later release artifacts are reproducible and attributable
  to a reviewed source revision.

## Non-goals

- competing with Linux, Windows, or production microkernels;
- running a language model in kernel space;
- providing an autonomous system with unrestricted machine authority;
- supporting legacy hardware beyond the maintained diagnostic path;
- promising formal verification before the kernel contracts stabilize.

## Research basis

The direction reflects developments observed through 2026-08-10:

- long-running software agents increase the value of explicit repository
  contracts, fast feedback, and reviewable work units;
- MCP and A2A standardize tool and peer interoperability above the operating
  system boundary;
- prompt injection and confused-deputy attacks make least privilege, approval,
  and untrusted-input handling core requirements;
- UEFI 2.11 is the current firmware baseline for modern x86-64 systems;
- memory-safe kernels increasingly isolate unsafe code in a small trusted core;
- WASI components provide typed host imports suitable for capability mediation;
- SLSA and OpenSSF guidance favor pinned automation, minimal permissions, and
  verifiable build provenance.

These inputs justify the boundary design, not a dependency on any particular
vendor. Protocol and runtime adoption remains milestone-gated and replaceable.

## Evolution rules

- Change one boundary at a time and keep the previous bootable milestone.
- Introduce an interface only with an executable contract test.
- Record architecture changes before implementation and link them from the
  affected roadmap item.
- Prefer a narrow vertical slice over parallel subsystem scaffolding.
- Revisit this design when a phase gate closes or a relevant protocol publishes
  a breaking stable revision.

## References

- [OpenAI: Harness engineering](https://openai.com/index/harness-engineering/)
- [NIST: AI agent security red-team findings](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition)
- [Model Context Protocol 2025-11-25 specification](https://modelcontextprotocol.io/specification/2025-11-25/basic)
- [Agent2Agent protocol 1.0 specification](https://github.com/a2aproject/A2A/blob/main/docs/specification.md)
- [UEFI specifications](https://uefi.org/specifications)
- [Asterinas framekernel overview](https://github.com/asterinas/asterinas)
- [WebAssembly Component Model and WASI](https://component-model.bytecodealliance.org/)
- [SLSA 1.2 specification](https://slsa.dev/spec/v1.2/)
- [OpenSSF Scorecard](https://github.com/ossf/scorecard)
