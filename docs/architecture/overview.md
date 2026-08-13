# MakopaOS architecture

- Status: Proposed
- Baseline: `77a3bfd2f1b35a319665a92693f4e405277e50e1`
- Prepared: 2026-08-10
- Reviewed: 2026-08-10

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
   results. Security-relevant state changes emit structured records. External
   benchmark scores never substitute for repository-native acceptance evidence.
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

- guessing a task-local selector cannot mint a capability-table entry or alter
  its typed rights;
- capabilities are scoped, transferable only by policy, and revocable where
  the underlying resource permits it;
- delegated authority remains attributable to an initiating principal, task,
  capability, and approval without storing secret values;
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

The direction was reviewed against developments available on 2026-08-10:

- long-running software agents increase the value of explicit repository
  contracts, fast feedback, and reviewable work units;
- MCP `2026-07-28` establishes a stateless protocol core with header-based
  routing, authorization hardening, cacheable discovery, extensions, and a
  minimum deprecation window;
- A2A `1.0.1` is the current stable peer-interoperability patch baseline;
- NIST work on agent identity, delegation, authorization, auditing, and prompt
  injection reinforces least privilege and explicit effect attribution;
- UEFI 2.11 is the current firmware baseline for modern x86-64 systems;
- stable Rust 1.97.1 and `uefi-rs` 0.39 are candidates for the OS010 decision,
  not dependencies or pins established by this architecture review;
- memory-safe kernels increasingly isolate unsafe code in a small trusted core;
- stable WASI 0.3 adds native asynchronous component semantics while preserving
  typed host imports suitable for capability mediation;
- coding-agent benchmark audits reinforce the need for local executable
  acceptance criteria instead of relying on aggregate benchmark claims;
- SLSA 1.2 and GitHub artifact attestations provide future provenance options,
  but become actionable only when MakopaOS publishes release artifacts.

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
- [OpenAI: Coding evaluation audit](https://openai.com/index/separating-signal-from-noise-coding-evaluations/)
- [GitHub: Agentic workflow security architecture](https://github.blog/ai-and-ml/generative-ai/under-the-hood-security-architecture-of-github-agentic-workflows/)
- [NIST: AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
- [NIST: Software and AI agent identity and authorization](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf)
- [NIST: AI agent security red-team findings](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition)
- [Model Context Protocol 2026-07-28 release](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [Agent2Agent protocol 1.0.1 release](https://github.com/a2aproject/A2A/releases/tag/v1.0.1)
- [UEFI specifications](https://uefi.org/specifications)
- [Rust stable release notes](https://doc.rust-lang.org/stable/releases.html)
- [`uefi-rs` 0.39](https://docs.rs/crate/uefi/0.39.0)
- [Asterinas framekernel overview](https://github.com/asterinas/asterinas)
- [WASI 0.3](https://wasi.dev/releases/wasi-p3)
- [SLSA 1.2 specification](https://slsa.dev/spec/v1.2/)
- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [OpenSSF Scorecard](https://github.com/ossf/scorecard)
