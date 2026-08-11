# Threat model

Status: Initial

MakopaOS is educational software, not a production security boundary. Its
architecture nevertheless treats isolation claims as testable contracts.

## Protected properties

- kernel memory is inaccessible to unprivileged tasks;
- one task cannot use another task's authority without an explicit transfer;
- external content cannot grant authority;
- accepted effects are attributable to a task and capability without exposing
  secret values;
- build inputs and generated images are reviewable and reproducible.

## Initial adversaries and failures

- malformed or hostile binaries;
- overlapping, truncated, misaligned, or incorrectly addressed kernel ELF
  segments;
- malformed, overlapping, overflowing, or incorrectly classified boot memory
  regions and framebuffer ranges;
- firmware protocol handles, allocations, or references used after boot
  services exit;
- invalid pointers, lengths, handles, and IPC messages;
- confused-deputy requests through a privileged service;
- replayed, expired, or duplicated approvals;
- malicious instructions embedded in repository, web, or message content;
- compromised dependencies or mutable CI actions;
- accidental contributor overreach and undocumented architecture drift.

## Required controls

- memory-safe implementation outside narrow reviewed architecture shims;
- bounded ELF parsing before allocation, with an executable entry constrained
  to a loaded segment at or above 1 MiB;
- no live firmware protocols or heap-backed values across `ExitBootServices`;
- a versioned, fixed-layout handoff held in loader-owned storage until kernel
  entry;
- bounded final-map normalization that keeps live kernel and framebuffer pages
  outside usable memory and defers loader-page reclamation;
- deny-by-default capability manifests;
- typed validation at every privilege and protocol boundary;
- bounded queues, timeouts, cancellation, and replay protection;
- separate approval for irreversible or externally visible effects;
- read-only automation permissions unless a work item requires more;
- pinned workflow actions and explicit build-tool versions;
- deterministic tests for every security invariant before phase promotion.

## Deferred threats

Physical access, hostile firmware, speculative-execution side channels,
availability under resource exhaustion, compiler compromise, cryptographic
identity, secure boot, and hardware attestation remain deferred until the
relevant subsystem exists. A roadmap item that introduces one of those
boundaries must update this document before claiming coverage.
