# ADR-0008: Own the console component-host contract above the kernel

- **Status:** Accepted
- **Date:** 2026-08-30
- **Refined:** 2026-09-03
- **Work item:** OS040
- **Baseline:** `06efaa7ac0acb5c0cd10de47713db98ce6113221`

## Context

OS032 closes the first explicit-authority phase with two fixed tasks, task-local
capability tables, a staged workload, one approval broker, one synthetic effect,
and a bounded redacted journal. The runtime still executes only linked probe
code. It has no arbitrary artifact loader, general heap, component runtime,
linear-memory owner, clock, preemption, filesystem, network stack, credential
store, or user-space console service.

The next phase needs a portable workload boundary without turning a changing
ecosystem interface into a kernel ABI. WASI 0.2.12 and 0.3.1 both use the
WebAssembly Component Model and typed WIT interfaces, but they make different
execution assumptions. WASI 0.2.12 is the current stable 0.2 patch on the
superseded, broadly supported line; its asynchronous behavior is expressed
through `wasi:io` resources and pollables. WASI 0.3.1 is the current stable
release. It moves `future`, `stream`, and asynchronous lift and lower into the
Component Model and adopts the `map<K, V>`, `implements`, and `external-id`
features.

Those additions are useful for composition, but MakopaOS cannot yet provide the
executor, cancellation, resource ownership, or memory substrate needed to make
native asynchronous components safe. Selecting either complete WASI world now
would also grant or emulate interfaces that the first console-only workload
does not need.

Wasmtime 48 is an LTS line with 24 months of security support. Patch 48.0.1 is
the exact host-side compile-only measurement baseline. Its embedded
`wasmparser` 0.254.0 family is retained as a differential baseline, never as
the admission authority. The independent OS041A admission path instead pins
the `wasmparser`, `wit-component`, and `wit-parser` 0.258.0 family published
with `wasm-tools` 1.258.0. It must compare raw import and export enumeration
with decoded component metadata and the separately supplied WIT, and fail
closed on disagreement between representations or parser families. Wasmtime's
`no_std` support is not an immediate
target-runtime fit: it requires an allocator and panic boundary, AOT artifacts,
embedder-provided TLS and platform operations, and custom virtual-memory and
executable-code publication hooks whose interface is not stable. Its resource
limiter does not account for every host allocation, and its precompiled
artifacts must be treated as trusted code. Recent advisories concerning
guest-controlled resource exhaustion reinforce the need for explicit admission
and execution limits rather than default runtime configuration.

OS040 records the boundary and evidence contract only. It does not add a
component runtime or select a dependency. Later implementation work requires
separate approval for each prerequisite slice.

## Decision

MakopaOS will own a versioned `ComponentHostContractV1` at the user-space
workload boundary. The contract is independent of the kernel trap ABI and of
any complete WASI release. A user-space component host may translate the
contract to a maintained Component Model runtime, but the kernel continues to
see only task identity, address spaces, IPC, capability handles, approval
state, and bounded event transport.

The first contract admits one immutable, image-bundled component with one
console import and one task export. It does not admit runtime downloads,
filesystem paths, network locations, environment variables, clocks, devices,
credentials, sockets, or arbitrary host functions.

### Contract identity and WIT surface

The normative package is `makopa:component@1.0.0`. Its logical WIT surface is:

```wit
package makopa:component@1.0.0;

interface console {
  enum write-error {
    limit-exceeded,
    unavailable,
  }

  write-line: func(value: string) -> result<_, write-error>;
}

interface task {
  enum run-error {
    denied,
    exhausted,
    host-failure,
  }

  run: func() -> result<_, run-error>;
}

world console-workload {
  import console;
  export task;
}
```

The checked-in WIT bytes, not this illustrative block, will be the future
machine-readable authority. Their SHA-256 digest is bound by artifact admission.
Version one has these fixed semantic limits:

- `console.write-line` accepts a WIT `string` whose UTF-8 encoding is at most
  64 bytes;
- the host appends exactly one LF byte and does not accept embedded carriage
  return, line feed, or NUL characters;
- one run may complete at most one accepted console call;
- the component exports exactly one `task.run` operation;
- neither interface defines a host or guest resource; and
- every undeclared import or export is an admission error.

Contract versions follow semantic versioning. A host rejects an unsupported
major version. A minor or patch version is accepted only when the host knows its
exact WIT digest and declared feature set; numeric compatibility alone is not
authority. A future interface change cannot alter the kernel ABI implicitly.

### WASI profile comparison

`ComponentAdmissionV1` records one explicit component profile:

| Value | Profile | Meaning |
| ---: | --- | --- |
| `0` | `MakopaConsoleV1` | The component imports only the owned console contract. |
| `2` | `WasiP2` | A separately approved adapter targets exact WASI 0.2.12 semantics. |
| `3` | `WasiP3` | A separately approved adapter targets exact WASI 0.3.1 semantics. |

The first runnable slice must use profile `0`. Values `2` and `3` reserve study
lanes; they do not approve an adapter or make either release a kernel ABI.

| Concern | WASI 0.2.12 | WASI 0.3.1 | OS040 disposition |
| --- | --- | --- | --- |
| Stability | Stable, superseded, broadly implemented | Stable and current | Compare; adopt neither as the owned ABI |
| Async model | `wasi:io` resources and explicit polling | Native async functions, futures, and streams | Defer async until execution and cancellation ownership exist |
| Component features | Base Component Model without native async | Adds native async plus `map`, `implements`, and `external-id` | Measure only the exact selected study masks; permit later adapters behind the owned contract |
| Tooling | Wider language and runtime coverage | Wasmtime 46+ and a smaller current tool set | Measure both with the same fixture |
| Capability mapping | Typed imports can map to host capabilities | Same, with better composition expressiveness | Keep mapping in the user-space host |
| Migration | Adapter or regeneration required | Natural successor for composed async services | Preserve raw component and WIT evidence so adapters can be replaced |

Profile zero and the WASI 0.2.12 study reject `implements`, `version_suffix`,
`external_id`, maps, duplicate named interface imports, external instance
identifiers, futures, streams, and every other Component Model extension. The
WASI 0.3.1 study adds only the native asynchronous baseline; it does not admit
the other new extensions. Their absence is a scope decision, not a rejection
of WASI 0.3.1. Reconsider them when a workload needs composition or concurrent
I/O and MakopaOS has an executor and cancellation contract.

### Signed artifact admission

One admitted workload bundle contains:

1. the portable Component Model artifact;
2. one target executable produced from that artifact, if the selected runtime
   requires AOT preparation;
3. the exact WIT package;
4. a fixed `ExecutionProfileV1` plus its exact target, runtime-configuration,
   and compiler-configuration documents;
5. a fixed `BuildEvidenceV1` plus its exact source-revision, builder-identity,
   command-transcript, dependency-lock, and tool-version documents;
6. a fixed `ComponentAdmissionV1`; and
7. a detached signature over the admission record.

The bundle is this logical set of separately supplied byte sequences, not an
archive or path-based container. The offline checker receives each member
through one named argument, never enumerates an input directory, and rejects
missing, repeated, symlinked, or directory inputs. The optional executable
argument is absent exactly when its admitted length and digest are zero. No
archive extraction, filename normalization, search path, network lookup, or
environment-variable expansion participates in admission.

`ComponentAdmissionV1` is a 288-byte fixed-width serialized record with this
exact little-endian byte layout:

| Offset | Field | Type |
| ---: | --- | --- |
| 0 | `schema_version` (`1`) | `u32` |
| 4 | `byte_size` (`288`) | `u32` |
| 8 | `component_id` | `u64` |
| 16 | contract major | `u32` |
| 20 | contract minor | `u32` |
| 24 | contract patch | `u32` |
| 28 | component profile | `u32` |
| 32 | portable artifact length | `u64` |
| 40 | target executable length | `u64` |
| 48 | portable artifact SHA-256 | `[u8; 32]` |
| 80 | target executable SHA-256 | `[u8; 32]` |
| 112 | WIT package SHA-256 | `[u8; 32]` |
| 144 | `ExecutionProfileV1` SHA-256 | `[u8; 32]` |
| 176 | `BuildEvidenceV1` SHA-256 | `[u8; 32]` |
| 208 | maximum linear-memory bytes | `u64` |
| 216 | maximum execution-stack bytes | `u64` |
| 224 | maximum deterministic fuel | `u64` |
| 232 | maximum component instances | `u32` |
| 236 | maximum linear memories | `u32` |
| 240 | maximum tables | `u32` |
| 244 | maximum component resources | `u32` |
| 248 | maximum accepted console calls | `u32` |
| 252 | maximum console bytes per call | `u32` |
| 256 | signature scheme (`1`: Ed25519) | `u32` |
| 260 | detached signature size (`64`) | `u32` |
| 264 | signing-key ID | `[u8; 16]` |
| 280 | reserved zero | `[u8; 8]` |

The schema version, byte size, component ID, contract major, portable-artifact
length, required digests, memory, stack, fuel, instance, memory, and console
bounds, signature scheme and size, and signing-key ID are mandatory and
nonzero. Contract minor and patch values and profile zero are valid. Table and
resource ceilings may be zero only when the inspected artifact uses neither
object class. Target-executable length and digest may both be zero for an
inspection-only admission. A later executable admission may retain that zero
pair only when an approved runtime consumes portable bytes directly. Other zero
or unknown profiles, schemes, fields, target features, or nonzero reserved
bytes fail closed.

#### Execution profile

`ExecutionProfileV1` is a 224-byte fixed-width serialized record with this
exact little-endian byte layout:

| Offset | Field | Type |
| ---: | --- | --- |
| 0 | `schema_version` (`1`) | `u32` |
| 4 | `byte_size` (`224`) | `u32` |
| 8 | target architecture | `u32` |
| 12 | target environment | `u32` |
| 16 | runtime family | `u32` |
| 20 | runtime major | `u32` |
| 24 | runtime minor | `u32` |
| 28 | runtime patch | `u32` |
| 32 | compiler family | `u32` |
| 36 | compiler major | `u32` |
| 40 | compiler minor | `u32` |
| 44 | compiler patch | `u32` |
| 48 | component profile | `u32` |
| 52 | code-publication mode | `u32` |
| 56 | trap mode | `u32` |
| 60 | memory mode | `u32` |
| 64 | MakopaOS core-Wasm feature bitmap | `u64` |
| 72 | MakopaOS Component Model feature bitmap | `u64` |
| 80 | MakopaOS CPU feature bitmap | `u64` |
| 88 | target-triple document length | `u32` |
| 92 | runtime-configuration document length | `u32` |
| 96 | compiler-configuration document length | `u32` |
| 100 | reserved zero | `u32` |
| 104 | target-triple document SHA-256 | `[u8; 32]` |
| 136 | runtime-configuration document SHA-256 | `[u8; 32]` |
| 168 | compiler-configuration document SHA-256 | `[u8; 32]` |
| 200 | reserved zero | `[u8; 24]` |

Architecture value `1` is `x86_64`. Environment value `1` is
`unknown-none`; value `2` is `unknown-linux-gnu`. Runtime value `1` is
Wasmtime and compiler value `1` is Cranelift. Component profile must equal the
admission record. Code-publication, trap, and memory mode zero mean
inspection-only and are valid only when target-executable length and digest are
both zero. Later nonzero modes require an accepted OS041B decision. Unknown
values, document-length mismatch, digest mismatch, or nonzero reserved bytes
fail closed. The OS041A positive fixture uses architecture `1`, environment
`2`, Wasmtime `48.0.1`, Cranelift `48.0.1`, and inspection-only modes.

The three supporting documents are exact bytes, not normalized strings. The
target triple is 1 to 96 printable ASCII bytes without whitespace. Runtime and
compiler configuration documents are each 1 to 4096 UTF-8 bytes, use LF line
endings, contain no NUL or carriage return, end in one LF, and contain only
sorted unique `name=value` lines. Names and values are nonempty printable ASCII
without `=`, whitespace, absolute paths, credentials, signatures, or secret
environment values.

Feature bit positions are MakopaOS-owned contract values and never reuse a
dependency's numeric discriminants. Core-Wasm bit zero denotes the WebAssembly
1.0 feature set; Component Model bit zero denotes the base Component Model.
Every other core-Wasm and Component Model bit is reserved in version one.
Profile zero admits both bit-zero values and CPU bitmap zero while no target
executable exists. OS041A maps that exact policy to
`WasmFeatures::WASM1 | WasmFeatures::COMPONENT_MODEL` in both the parser and
validator. The WASI 0.2.12 study uses that same mask. The WASI 0.3.1 study adds
only `WasmFeatures::CM_ASYNC`. All other Component Model extension bits remain
off, including `CM_MAP`, `CM_IMPLEMENTS`, `CM_THREADING`, `CM_VALUES`,
`CM_NESTED_NAMES`, `CM_CANON_NAMES`, `CM_ERROR_CONTEXT`,
`CM_FIXED_LENGTH_LISTS`, and `CM_GC`. `WasmFeatures::default()` and
`WasmFeatures::all()` are never admission authority. Post-WebAssembly-1.0 core
proposals and unselected Component Model extensions fail closed. WASI study
fixtures use separately recorded study masks and are never accepted as
profile-zero admission evidence.

#### Build evidence

`BuildEvidenceV1` is a 256-byte fixed-width serialized record with this exact
little-endian byte layout:

| Offset | Field | Type |
| ---: | --- | --- |
| 0 | `schema_version` (`1`) | `u32` |
| 4 | `byte_size` (`256`) | `u32` |
| 8 | build type | `u32` |
| 12 | source-revision kind | `u32` |
| 16 | source-revision document length | `u32` |
| 20 | builder-identity document length | `u32` |
| 24 | command-transcript document length | `u32` |
| 28 | dependency-lock document length | `u32` |
| 32 | tool-version document length | `u32` |
| 36 | command count | `u32` |
| 40 | tool count | `u32` |
| 44 | reserved zero | `u32` |
| 48 | source-revision document SHA-256 | `[u8; 32]` |
| 80 | builder-identity document SHA-256 | `[u8; 32]` |
| 112 | command-transcript document SHA-256 | `[u8; 32]` |
| 144 | dependency-lock document SHA-256 | `[u8; 32]` |
| 176 | tool-version document SHA-256 | `[u8; 32]` |
| 208 | reserved zero | `[u8; 48]` |

Build type `1` is a repository command transcript. Source-revision kind `1` is
`makopa-source-manifest-v1`. Its document is 1 to 65536 exact ASCII bytes, uses
LF line endings, ends in exactly one LF, and has this complete grammar, where
angle-bracketed values are replaced by their canonical encodings:

```text
schema=makopa-source-manifest-v1
repository=git+https://github.com/xsparc/MakopaOS
tree-path=<path>
git-tree-sha1=<40 lowercase hexadecimal bytes>
file-count=<canonical decimal>
<mode> <canonical decimal byte length> <64 lowercase hexadecimal SHA-256 bytes> <path>
...
```

The repository line is exact. `tree-path` and file paths are 1 to 128 ASCII
bytes drawn only from `A-Z`, `a-z`, `0-9`, `.`, `_`, `-`, and `/`. They are
relative, use `/` separators, and have no leading, trailing, or repeated `/`,
empty, `.` or `..` component, backslash, whitespace, or normalization step.
File paths are relative to `tree-path`, unique, and sorted in ascending raw byte
order. A file path cannot also be another entry's directory prefix. Canonical
decimal is `0` or a nonzero value with no leading zero. `file-count` is 1 to
256 and equals the number of file lines. Each declared file is at most 262144
bytes and their aggregate length is at most 1048576 bytes. The only permitted
modes are `100644` and `100755`, and every entry must resolve to a Git blob.
Trees are recursively enumerated; symlinks (`120000`), gitlinks (`160000`),
special modes, non-blob leaves, unlisted entries, and missing entries fail
closed.

The 40-byte SHA-1 tree object ID is only a locator in this repository's current
Git object format. Hashing that locator string with SHA-256 does not strengthen
the source bytes behind it. Integrity instead comes from the signed admission
record binding the exact manifest through `BuildEvidenceV1`, and from that
manifest binding every accepted source byte sequence by path, mode, exact
length, and SHA-256. The trusted parent resolves the declared subtree from the
explicit expected checkout revision, requires the resolved tree ID to equal the
locator, and reconstructs the source from committed Git objects rather than the
working tree. The build producer and admission checker independently enumerate,
parse, hash, and compare the complete manifest; agreement on the SHA-1 locator
alone is never sufficient.

The builder identity is 1 to 128 printable ASCII bytes on one line without a
trailing newline. The command transcript is 1 to 4096 UTF-8 bytes, uses LF line
endings, has one nonempty command per line, ends in one LF, and contains exactly
the declared command count. The dependency lock is 1 to 524288 exact bytes.
The tool-version document is 1 to 4096 printable ASCII bytes, contains sorted
unique `name=version` lines, ends in one LF, and contains exactly the declared
tool count. Unknown types or revision kinds, zero counts, length or digest
mismatch, nonzero reserved bytes, NUL, carriage return, or machine-local
absolute paths fail closed. These public evidence documents may describe only
repository-relative inputs and must not contain credentials, signatures, or
secret environment values.

The SHA-256 fields in `ComponentAdmissionV1` bind the two fixed records. Each
record in turn binds its supporting documents by exact length and digest. The
source manifest adds its own deliberately narrow path grammar and file-digest
inventory; no host path normalization, checkout metadata, or untracked byte can
participate in the transitive construction.

All three records are parsed and serialized with checked explicit byte offsets
and little-endian byte slices. An implementation must not deserialize them by
casting, transmuting, relying on `repr(C)`, native endianness, alignment, or
compiler padding.

The signature message is exactly the 30-byte domain separator
`b"MAKOPA-COMPONENT-ADMISSION-V1\0"` followed immediately by all 288 serialized
admission bytes: 318 bytes total, with no length prefix, framing, or
normalization. Because the admission record binds every accompanying byte
sequence by digest, the signature covers the portable artifact, executable,
WIT, both metadata records and their supporting documents, and the resource
bounds without parsing their contents inside the signature format.

Scheme 1 is Ed25519 with an exact 64-byte signature. OS041A pins
`ed25519-dalek = "=3.0.0"` and `sha2 = "=0.11.0"`, both with default features
disabled. No optional `ed25519-dalek` feature is enabled. The verifier uses
`VerifyingKey::verify_strict` and explicitly rejects weak public keys; legacy
compatibility and hazardous signing paths remain unavailable. The frozen
verifier-only positive fixture commits one public test trust root, its derived
16-byte key ID, records, supporting documents, artifacts, and detached
signature. It must not commit a private signing seed or expose `SigningKey`,
signer, or key-generation code in the repository. Unknown schemes, keys, weak
keys, non-canonical signatures, and wrong signature sizes remain invalid. The
reference signature proves integrity and admission by the declared test trust
root; it does not prove a human identity, production release, secure boot, or
protected key custody.

Precompiled runtime bytes are never accepted as ordinary untrusted component
input. The host-side verifier first validates the portable component and import
surface, then verifies the exact precompiled digest, runtime version, target,
CPU feature set, and execution-profile digest. The initial target may execute
only an immutable bundle admitted before image construction. Runtime download
or replacement requires a later storage, transport, target-side cryptography,
and revocation decision.

`BuildEvidenceV1` is repository-native provenance, not a SLSA level claim. Its
bounded documents must be sufficient to reproduce or explain the
portable-to-executable transformation. A later release may attach SLSA 1.2
provenance or another maintained envelope without changing the component-host
contract.

### Offline inspection policy

The positive fixture is produced with Rust `1.97.1` and that toolchain's
`wasm32v1-none` target. Guest bindings pin `wit-bindgen` 0.61.1 with default
features disabled and only the `macros` feature enabled. The generation macro
names the checked-in WIT path and exact `console-workload` world; it must not
use inline WIT, `with`, `generate_all`, `skip`, stubs, async options, ownership
overrides, runtime-path overrides, or binding remaps. The direct-final fixture
sets `disable_custom_section_link_helpers: true`. This retains the generated
`__WIT_BINDGEN_COMPONENT_TYPE` metadata static while breaking the helper chain
to `maybe_link_cabi_realloc`; it is not approved for library-like generation.
The fixture uses `wit_component::metadata::encode` to produce deterministic,
non-executable component-type metadata bytes, either directly or through the
documented `wit-bindgen` mechanism. Those metadata bytes describe an interface;
they do not prove executable behavior, and the final component bytes remain
subject to independent validation.

The resulting core module is componentized with `wit-component` 0.258.0.
Componentization explicitly calls `merge_imports_based_on_semver(false)` and
supplies no adapters, libraries, import-name maps, or other import remapping.
The pinned `wit-bindgen` 0.61.1 producer emits the legacy core-name encoding, so
this trusted production step calls `reject_legacy_names(false)` only while
wrapping the exact core module built from the verified source manifest. This is
a producer compatibility boundary, not an admission exception: supplied WIT,
raw final-component identities, decoded identities, aliases, and parallel names
remain subject to the exact comparison below and reject legacy forms. The
componentizer rejects `implements`, `version_suffix`, and `external_id`
metadata or features. The command transcript and tool-version document bind
those choices. An encoder's own validation option is only a generation-time
sanity check because it does not enforce the MakopaOS admission mask.

Independent admission pins `wasmparser = "=0.258.0"` with default Cargo
features disabled and only `std`, `validate`, `features`, and
`component-model` enabled. These compile-time Cargo features only make the
required parser and configurable validator facilities available; they do not
select what an artifact may contain. Runtime `WasmFeatures` masks remain the
admission authority: profile zero and the WASI 0.2.12 study use exactly
`WasmFeatures::WASM1 | WasmFeatures::COMPONENT_MODEL`, while the WASI 0.3.1
study adds only `WasmFeatures::CM_ASYNC`. No other Component Model extension is
enabled.

OS041A applies hard checker ceilings before hashing or parsing: 1048576
portable-component bytes, 65536 WIT bytes, eight nested module-or-component
levels, 256 total sections, 4096 total type entries, 256 imports, 256 exports,
32 custom sections, 65536 aggregate custom-section bytes, and 256 UTF-8 bytes
per import or export name. Its positive signed fixture has no target executable;
measurement artifacts remain separate evidence until OS041B selects target
limits. The 65536-byte WIT ceiling applies to profile-zero admission. Because
the exact WASI 0.2.12 and 0.3.1 dependency closures each exceed that aggregate
size, each study uses a distinct, non-admission WIT envelope capped at 131072
bytes. A study fixture or result can never satisfy or substitute for
profile-zero admission evidence.

The checker reads each named member once into a buffer whose ceiling comes from
this decision, never from an untrusted record length. An over-ceiling read stops
immediately. It validates the three fixed record sizes and reserved bytes,
resolves the configured public key, verifies the admission signature, and then
checks every actual length and digest before interpreting supporting documents
or component structure. No declared count or length is used for allocation,
indexing, slicing, or iteration without checked conversion and a prior hard-cap
comparison.

`wasmparser::Parser` and `Validator` receive the same explicit MakopaOS feature
mask. OS041A does not use parser or validator defaults, `WasmFeatures::default()`,
or `WasmFeatures::all()`. A bounded structural walk consumes every section
reader, treats the non-exhaustive payload wildcard and every unknown section as
errors, and checks each nested module or component range for containment within
both its parent and the original artifact before entering it. Depth, range,
section, entry, and name limits are checked with non-wrapping arithmetic. After
that walk, a separately constructed `Validator` using the same mask must run
`validate_all` over the exact final component bytes. Merely submitting parser
payloads is insufficient because function bodies require complete validation.
Both passes must reach the end of the same artifact; encoder, metadata, decoder,
or compiler success cannot substitute for this independent final-byte check.

Raw top-level component imports and exports are captured before WIT decoding.
Profile zero requires exactly the console import and task export from this
decision. The separately supplied WIT bytes are parsed in memory through
`wit_parser::SourceMap::new()`, `SourceMap::push_str(name, source)`,
`SourceMap::parse()`, and `Resolve::push_group(group)`, in that order. No
filesystem resolver, path, or loader participates. Neither admission path may
merge imports by semver, accept legacy names, or remap an import.

`wit_component::decode` runs only after independent validation and only in a
dedicated decoder worker. Wasmtime compilation runs only in a separate compiler
worker. The parent invokes each worker through a pinned absolute executable,
with a cleared inherited environment and fixed working directory. Each worker
self-applies the platform-appropriate CPU, address-space, file-size, open-file,
and process-count limits before sending the exact versioned `READY` frame. The
parent sends untrusted bytes only after receiving that frame. The
length-prefixed protocol and bounded standard-input, standard-output, and
standard-error pipes carry no input path, search path, URL, network endpoint,
adapter, library, or import map.

The parent enforces a watchdog and rejects a decoder or compiler error, nonzero
exit, signal, panic or abort, timeout, output overflow, incomplete or malformed
frame, unexpected protocol value, or trailing response bytes. On timeout,
overflow, or protocol fault it closes all pipes, kills the worker, and waits to
reap it. A decoder cannot publish partial inspection evidence; a complete
response is validated before any result is published. An internal unwind guard
may add diagnostics, but correctness cannot depend on unwinding because the
workspace development and release profiles abort on panic. Resource limits and
the process boundary contain faults but are not an operating-system sandbox.
A platform that cannot apply the required limits skips or fails closed and may
not claim equivalent containment.

The raw component surface, decoded component, and separately supplied WIT are
each converted independently into the same fixed profile-zero semantic record.
That record contains direction; exact package namespace, name, and version;
interface and function names; ordered parameter and result names; recursively
expanded types; and enum cases in declaration order. Only semantically
unordered maps are sorted, by raw UTF-8 bytes; every WIT-declared sequence keeps
its declaration order. The three records must be byte-for-byte equal after this
fixed encoding. The comparison does not use semver normalization or
compatibility, legacy-name aliases, import remapping, WIT printer output,
dependency-internal IDs, or a decoder-synthesized root package or world
identity. The signed WIT digest remains authoritative for the original WIT
bytes. Duplicate, semver-compatible parallel, decoded-only, WIT-only, raw-only,
`implements`, `version_suffix`, or `external_id` items, and any
0.258.0-versus-0.254.0 parser disagreement fail closed and produce one bounded
categorical result.

### Fixture build and compile-measurement controls

Fixture production runs in a separate environment-cleared build worker using
pinned absolute Cargo, rustc, and LLD executables, a fixed working directory,
an isolated Cargo home and configuration, exactly declared source inputs, and
locked offline dependencies. It rejects or clears ambient `RUSTFLAGS`,
`CARGO_ENCODED_RUSTFLAGS`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, target
linker or rustflags settings, source replacement, and ancestor or home Cargo
configuration. It explicitly sets `lto = false`, `codegen-units = 1`, and
`-C linker-plugin-lto=off`. Link-time optimization remains disabled because an
explicit linker-plugin-LTO path can emit post-WebAssembly-1.0 features for
`wasm32v1-none`; independent final-byte validation remains authoritative.

Before that worker starts, a trusted parent creates a fresh source-staging root
outside the checkout. It resolves the exact `tree-path` from the explicitly
supplied expected revision, then uses replacement-disabled Git object access and
NUL-delimited recursive tree enumeration without path-pattern arguments. It
rejects disallowed modes, object types, paths, counts, and byte ceilings before
materialization; streams each declared blob through SHA-256 with exact length
enforcement; and creates each destination once without following links. A
separate checker reads the staged regular files back and compares their complete
path, mode, length, and digest inventory with the signed manifest before the
worker receives that root read-only. The checkout's `.git` directory, hooks,
configuration, credential helper state, ignored files, untracked files, and
modified working-tree bytes are never staged. The future hosted checkout must
also disable persisted credentials. Any unsupported no-follow, object-access,
or containment primitive fails closed.

Rust 1.97.1 bundles LLD 22.1.6. The direct-final fixture keeps LLD's default
section garbage collection and records Cargo `-vv` output, effective compiler
and linker arguments, an LLD `--Map`, `--why-extract`, traced inputs,
garbage-collection diagnostics, and core-Wasm disassembly. It fails closed
unless final component-type metadata survives, exactly the pinned realloc
archive member supplies the expected `cabi_realloc` scaffold, exactly the
corresponding `cabi_realloc_wit_bindgen_0_61_1` Rust entry remains linked, and
no WASIp3 or other unexpected archive member, symbol, or data is extracted. It
records the exact final core imports, exports, functions, globals,
memories, tables, data segments, custom sections, target features, symbols, and
direct call graph before componentization.

The fixture owns one fail-closed allocation sentinel solely to satisfy Rust's
`no_std` link contract: allocation returns null, deallocation has no effect,
and the panic boundary traps. This sentinel, `cabi_realloc`, and its versioned
wrapper are producer scaffolding, not an approved workload allocator or runtime
surface. The exported task's transitive call graph must not reach either realloc
entry, the sentinel, or the panic path; the core module must contain no
`memory.grow`; and the final component must expose only the exact console import
and task export. The build must not disable linker garbage collection or
introduce any other allocator, adapter, library, or remapping.

The published `wit-bindgen` 0.61.1 package is pinned by `.crate` SHA-256
`e473fd0095479f9689ac7d2a52c427cc96bb2b973ace50238dfcc1ab1cd52d93` and
`.cargo_vcs_info.json` revision
`0b0069d6c29c605dd2bc8d10d55e49a0c6cb76d8`. Its complete binary-format
inventory is:

| Path | Bytes | SHA-256 |
| --- | ---: | --- |
| `wasi-cli@0.2.0.wasm` | 25587 | `60B274319C9DCE183269A0E3AD922B8EE4EAD915F34D171DE9DA23A390863119` |
| `src/rt/libwit_bindgen_cabi_realloc.a` | 490 | `8233B0DB2FDD4A524952357B9CC4A21EBB83B86B91E1D2E5A89FCBD38234C4B8` |
| `src/rt/libwit_bindgen_cabi_wasip3.a` | 782 | `0AEA7A729789D7789127AA28D008BB900E67A3D24D9A5309C50072CB51367C03` |
| `src/rt/wit_bindgen_cabi_realloc.o` | 251 | `FCD82DE149AB44E9F7F37E69AF45BE4C251C8CD8C9319F6075DDC5556B649BC2` |
| `src/rt/wit_bindgen_cabi_wasip3.o` | 462 | `43111A0AAD098795742BD72FC648097C31597F47673668A977AADC18A528372E` |

These bytes match the upstream `v0.61.1` tag. The WASI CLI component is a
documentation example and is never a build input. The build script offers both
archives for `wasm32v1-none` because its target environment is empty; the
package's `realloc` feature does not suppress that behavior and is not a build
control. The link evidence above must prove that exactly the pinned realloc
object contributes the expected `cabi_realloc` scaffold, that the corresponding
versioned Rust entry is present, that the WASIp3 archive contributes nothing,
and that no other archive contribution is hidden by the final component
surface.

The P0 and P2 compile-measurement worker pins `wasmtime = "=48.0.1"` with
default features disabled and only `component-model` and `cranelift` enabled.
It may compile, but never instantiate or execute, the admitted or study bytes.
The P3 study uses a separate worker and build that additionally records
`component-model-async` and its distinct dependency and feature evidence.
Neither worker produces runtime evidence or a runtime claim. Wasmtime's
embedded `wasmparser` 0.254.0 remains differential evidence only. OS040 approves
no Wasmtime dependency.

### Import enumeration and capability mapping

Admission enumerates the complete component import and export set before any
runtime instance or capability route is published. This is complete import
enumeration and exact console-only allowlisting, not zero-import denial. The
only permitted import is exactly `makopa:component/console@1.0.0`; the only
permitted export is exactly `makopa:component/task@1.0.0`. Filesystem, network,
clock, random, environment, process, device, credential, socket, generic WASI,
undeclared, and unknown imports fail before instantiation.

The component never receives a raw kernel capability selector. The user-space
host receives one task-local console-service capability through its immutable
launch manifest and implements the WIT import only after resolving that entry's
type, rights, object identity, and generation. The host copies and validates
the bounded text, invokes the local console service, and returns one categorical
result. An interface name, artifact signature, component ID, or WIT declaration
is not authority by itself.

A missing, stale, wrong-object, or wrong-right host capability makes the import
unavailable without changing component, console, journal, queue, or capability
state. Adding any import requires a new contract version, manifest route,
threat-model update, and executable denial evidence.

### Resource, execution, and cancellation contract

Every admitted resource bound is finite. The first component permits exactly
one instance and one linear memory, no table, no host or guest component
resource, one console call, and 64 console bytes. The first component cannot
use shared memory, threads, SIMD, memory64, multiple memories, reference types,
dynamic linking, or memory growth. OS041B must select measured nonzero ceilings
for linear memory, stack, fuel, portable bytes, executable bytes, runtime
metadata, and temporary host allocation before target integration is approved.

Runtime defaults do not establish the bound. Admission validation, static
component inspection, runtime configuration, and post-run measurement must
agree. A resource limiter that omits runtime or host allocations is incomplete
evidence; OS041B must account separately for code, runtime metadata, canonical
ABI temporaries, host-call buffers, and platform state.

Deterministic fuel is the version-one execution deadline. Exhaustion produces a
terminal, non-resumable trap. Wall-clock and epoch deadlines are excluded. Fuel
does not cancel a blocked host call, so the only admitted console host call must
be bounded, nonblocking, and cancellation-aware before it crosses into a local
service.

WASI 0.3.1 async execution is deferred until an approved slice owns the host
executor, pending futures and streams, wakeups, cancellation propagation,
blocked-call teardown, and task scheduling. Cooperative execution cannot claim
preemptive cancellation. Before invocation, cancellation rejects the run
without instantiation; during guest execution, version one cancellation is an
explicit deterministic trap at an admitted execution boundary.

### Failure, rollback, teardown, and repeated-run evidence

Artifact admission, code preparation, instance construction, capability-route
publication, and task scheduling are distinct states:

`Unverified -> Admitted -> Prepared -> Instantiating -> Runnable -> Running -> Terminal -> Reclaimed`

Only `Runnable` and `Running` may invoke an import. Failure is state-preserving
until the first owned resource is installed. After that point, rollback removes
only completed steps in reverse order: stop invocation, cancel bounded host
work, remove import bindings, destroy component resources and instance state,
unmap executable and linear memory, close host capability routes, remove task
and address-space references, invalidate mappings, and return frames.

Successful teardown follows the same reachability order. Executable or linear-
memory frames cannot be returned while an instance, canonical ABI temporary,
host call, import binding, capability entry, mapping, or task reference can
reach them. A trap cannot resume the faulting component, publish a second
terminal result, or retain a live import.

The reference scenario runs the same immutable admitted component twice in two
fresh instances. Each run must produce exactly one identical console record and
one terminal outcome, consume no more than its declared fuel and memory bounds,
and reach `Reclaimed` before the next instance is constructed. The second run
must not observe memory, resource, result, capability, or host-call state from
the first.

The component host records admission identity, start, one accepted console
call, terminal category, and reclamation through a bounded user-space evidence
channel. It records digests and categorical results, not console payload,
signature bytes, capability selectors, pointers, credentials, or arbitrary
component data. ADR-0007 remains the approval/effect journal and is not silently
redefined as a general component logger.

## Prerequisite-driven OS041 slices

OS041 is split so target execution cannot hide missing platform work:

1. **OS041A — Component admission verifier.** Pin Rust `1.97.1` fixture
   production to `wasm32v1-none` and `wit-bindgen` 0.61.1 with default features
   disabled and only `macros` enabled; disable custom-section link helpers,
   semver import merging, LTO, and linker-plugin LTO; confine legacy core-name
   compatibility to componentization of the exact verified producer output;
   reject legacy supplied-WIT and final-component identities; prohibit binding
   overrides, adapters, libraries, import remapping, and every allocator except
   the fixture-local trap-only sentinel; preserve independently validated
   component-type metadata; and prove that the task path cannot reach realloc,
   allocation, or panic scaffolding and that the core contains no `memory.grow`.
   Pin `ed25519-dalek` 3.0.0 and `sha2` 0.11.0 with default features disabled,
   no optional verifier features, strict weak-key-aware verification, and a
   frozen public verifier-only fixture. Pin the public test trust root, the
   `wasmparser`, `wit-component`, and `wit-parser` 0.258.0 inspection family,
   exact WASI 0.2.12 and 0.3.1 study inputs, and the host-side Wasmtime 48.0.1
   compile-only measurement baseline with its 0.254.0 parser family reported
   separately. Verify the fixed admission, execution-profile, and
   build-evidence byte layouts and documents, the bounded canonical source
   manifest and independent committed-object reconstruction, digests, exact
   318-byte signature message, raw, decoded, and supplied-WIT surfaces, complete
   import enumeration and exact console-only allowlisting, explicit runtime
   feature masks, independent final-byte validation, decoder and compiler worker
   containment, exact semantic interface comparison, nested-range containment,
   parser and WIT limits, isolated build inputs, and link provenance without
   changing boot behavior or running any component.
2. **OS041B — Memory and execution-substrate decision.** Use OS041A
   measurements to decide the allocator, image loading, AOT representation,
   W^X code publication, linear-memory ownership, stack, fuel, trap,
   cancellation, runtime metadata, and reverse teardown contract. Pin exact
   finite ceilings and rollback evidence before code is admitted on target.
3. **OS041C — Runtime platform experiment.** Integrate only the minimum
   separately approved runtime subset behind the decided platform hooks. Prove
   allocation failure, code and data permission changes, traps, fuel,
   cancellation boundaries, teardown, and repeated construction without
   exposing a component import.
4. **OS041D — Console-only component execution.** Admit the signed immutable
   profile-0 bundle, map only the console capability, run twice, deny every
   undeclared import, record bounded execution evidence, preserve earlier QEMU
   transcripts, and emit a new terminal record only after complete reclamation.

No slice may collapse into the next one because a host-side experiment passes.
Each requires explicit approval and preserves the previous bootable boundary.

## Verification contract

OS040 closes with documentation and project-evidence validation only. Future
implementation evidence must include:

- exact layout, enum, length, digest, transitive-document, and reserved-zero
  tests for `ComponentAdmissionV1`, `ExecutionProfileV1`, and
  `BuildEvidenceV1`;
- exact source-manifest grammar, repository, subtree, locator, sorted path,
  mode, file count, per-file length and SHA-256, aggregate length, and final-LF
  acceptance, with independent producer/checker reconstruction from committed
  Git objects and read-back verification of the staged regular files;
- rejection of a changed source byte, path, mode, length, digest, tree locator,
  repository, subtree, count, order, line ending, trailing byte, non-ASCII byte,
  NUL, absolute or non-canonical path, duplicate or prefix-colliding path,
  symlink, gitlink, special mode, non-blob leaf, missing or extra entry, object
  type or size mismatch, short or excess blob, exceeded path, file, aggregate,
  count or document bound, producer/checker disagreement, and any case where
  the SHA-1 locator agrees but the SHA-256-bound source inventory does not;
- proof that modified and untracked working-tree content, `.git`, hooks,
  configuration, credential state, and checkout-persisted credentials cannot
  enter staging or the build worker;
- altered manifest, artifact, executable, WIT, execution profile, build
  evidence, signature, key, target, runtime, and bound rejection;
- strict Ed25519 positive and mutation evidence, including wrong-size,
  non-canonical, weak-key, unknown-scheme, unknown-key, and key-ID rejection;
  the exact 30-byte domain separator plus 288 serialized bytes, with no private
  key, signer, or generation path in the repository;
- pinned Rust `1.97.1` `wasm32v1-none` fixture production using `wit-bindgen`
  0.61.1 with default features disabled and only `macros` enabled, the
  checked-in WIT path and exact world named, semver import merging and
  custom-section link helpers disabled, legacy core-name compatibility confined
  to componentization of the exact verified producer output, and no binding
  overrides, adapters, libraries, import remapping, or allocator other than the
  fixture-local trap-only sentinel; exact registry package, revision,
  binary-format inventory, build environment, Cargo, rustc, LLD, link-map,
  extraction, traced-input, garbage-collection, symbol, section, target-feature,
  direct-call-graph, and disassembly evidence, including the exact pinned
  realloc scaffold and versioned wrapper, zero `memory.grow`, no task-path
  reachability to realloc, allocation, or panic code, and strict final
  identities;
- `wasmparser` 0.258.0 with only its required compile-time Cargo features and
  exact WebAssembly 1.0 plus base Component Model runtime masks, with only
  `CM_ASYNC` added for the separate P3 study and all other extensions rejected;
  bounded artifact-byte, nesting-depth, parent-range, section, type, import,
  export, custom-section, and name inspection, followed by independent
  `validate_all` coverage of the exact final bytes before compilation;
- independent raw import and export enumeration, exact in-memory `SourceMap`
  WIT parsing, subprocess-contained WIT decoding, and byte-equal fixed semantic
  interface records, with worker setup failure, error, panic or abort, timeout,
  malformed, partial, oversized, or trailing output, extra items, forbidden
  metadata, semver-compatible parallel identities, and parser-family
  disagreement rejected and recorded rather than normalized;
- filesystem, network, clock, random, environment, process, device, credential,
  generic WASI, undeclared, and unknown imports denied by complete enumeration
  and exact console-only allowlisting before compilation;
- host-side comparison of equivalent WASI 0.2.12 and 0.3.1 fixtures using exact
  tool versions, distinct 131072-byte study envelopes, and reporting artifact,
  dependency, feature, compile, async-model, and migration differences without
  instantiation, execution, or a runtime claim;
- explicit accounting for allocator, code, linear memory, stack, tables,
  instances, resources, canonical ABI temporaries, host-call buffers, and
  runtime metadata;
- deterministic fuel exhaustion, component trap, host-call failure,
  cancellation, and state-preserving pre-publication failure;
- failure injection after every owned-resource installation with reverse-order
  rollback and no reachable code, data, handle, task, mapping, or frame;
- successful run, terminal evidence, teardown, and two-run isolation; and
- a pinned QEMU `qemu64` one-vCPU terminal record only after all prior serial
  evidence and complete component-host reclamation.

Wasmtime 48.0.1 is a host-side research and compile-only measurement baseline,
not an approved dependency, target runtime, ABI, runtime-evidence source, or
security claim. Any version or runtime selected by OS041C must undergo a fresh
advisory and feature audit.

## Alternatives considered

### Make WASI 0.3.1 the kernel workload ABI

Rejected. Native async is directionally useful, but its executor, cancellation,
resource, and scheduling requirements do not belong in the kernel ABI and do
not yet exist in MakopaOS.

### Adopt WASI 0.2 as the permanent component contract

Rejected. It has broader tooling today, but its pollable-resource async model
would still expose interfaces the first workload does not need and would make a
superseded ecosystem version the product boundary.

### Embed Wasmtime directly in the kernel

Rejected. The current runtime and platform requirements would expand the
trusted core, dependency graph, allocation surface, and unsafe platform hooks.
The component host remains a replaceable user-space service.

### Execute an unsigned raw or precompiled artifact

Rejected. Raw component validation does not establish artifact origin, and
deserializing untrusted precompiled code can cross the native-code boundary.
Admission must bind the portable input, target executable, configuration,
build evidence, and finite limits before image construction.

### Reuse the kernel effect journal as the component event stream

Rejected. ADR-0007 records one fixed approval and synthetic-effect lifecycle.
Changing its schema or capacity would invalidate the OS032 proof. A future
user-space host owns component execution evidence and may export it through a
separately approved service.

## Consequences

- MakopaOS gains a stable workload boundary without coupling the kernel to
  WASI, Wasmtime, or a provider-specific runtime.
- The first component is deliberately smaller than either full WASI world and
  has no ambient operating-system imports.
- Signature and provenance evidence covers exact bytes and configuration, but
  does not claim authenticated human identity, protected keys, secure boot, or
  release provenance.
- AOT execution remains possible, but precompiled bytes are admitted as trusted
  native-code inputs rather than parsed as ordinary untrusted Wasm.
- The explicit prerequisite chain makes allocator, memory, executable-code,
  cancellation, and teardown gaps visible before target integration.
- The initial profile cannot perform async composition, dynamic loading,
  filesystem, network, clock, random, environment, credential, or device work.

## Rollback and reconsideration

Replace this decision before OS041A if the 288-byte admission record cannot
bind every executable input without ambiguous canonicalization, if the selected
signature verifier cannot run deterministically offline, or if complete import
enumeration cannot precede AOT preparation. A replacement must preserve exact
artifact identity, fail-closed unknown fields, finite resource declarations,
complete import enumeration with exact console-only allowlisting, and an
independently versioned user-space contract.

Reconsider the console limits only with measured fixture evidence. Reconsider
WASI 0.2 or 0.3.1 adapters when an approved workload needs a maintained
standard interface. Reconsider native async only after executor, cancellation,
blocked-host-call, and scheduler ownership are defined. Reconsider dynamic
artifact loading only after storage, transport, target-side verification,
revocation, and recovery exist. Reconsider Wasmtime after its custom-platform
surface, target footprint, security advisories, and required dependencies are
measured against the selected substrate.

## References

- [MakopaOS architecture](../overview.md)
- [ADR-0005: Task-local capability handles](0005-task-local-capability-handles.md)
- [ADR-0006: Fixed supervisor and approval broker](0006-fixed-supervisor-and-approval-broker.md)
- [ADR-0007: Fixed effect journal](0007-fixed-effect-journal.md)
- [WASI releases](https://wasi.dev/releases)
- [WASI 0.2](https://wasi.dev/releases/wasi-p2)
- [WASI 0.2.12 release](https://github.com/WebAssembly/WASI/releases/tag/v0.2.12)
- [WASI 0.3](https://wasi.dev/releases/wasi-p3)
- [WASI 0.3.1 release](https://github.com/WebAssembly/WASI/releases/tag/v0.3.1)
- [Wasmtime 48.0.1 crate](https://docs.rs/crate/wasmtime/48.0.1)
- [Wasmtime 48.0.1 release](https://github.com/bytecodealliance/wasmtime/releases/tag/v48.0.1)
- [Wasmtime release support](https://docs.wasmtime.dev/stability-release.html)
- [`wasm-tools` 1.254.0 release](https://github.com/bytecodealliance/wasm-tools/releases/tag/v1.254.0)
- [`wasm-tools` 1.258.0 release](https://github.com/bytecodealliance/wasm-tools/releases/tag/v1.258.0)
- [Rust `wasm32v1-none` target](https://doc.rust-lang.org/rustc/platform-support/wasm32v1-none.html)
- [`wit-bindgen` 0.61.1 release](https://github.com/bytecodealliance/wit-bindgen/releases/tag/v0.61.1)
- [`wit-bindgen` 0.61.1 build script](https://github.com/bytecodealliance/wit-bindgen/blob/v0.61.1/crates/guest-rust/build.rs)
- [`wit-bindgen` link-helper runtime](https://github.com/bytecodealliance/wit-bindgen/blob/v0.61.1/crates/guest-rust/src/rt/mod.rs)
- [`wit-bindgen` custom-section helper control](https://github.com/bytecodealliance/wit-bindgen/blob/v0.61.1/crates/rust/src/lib.rs)
- [`wit-bindgen` 0.61.1 legacy core-name emission](https://docs.rs/crate/wit-bindgen-rust/0.61.1/source/src/interface.rs)
- [`wit-bindgen` 0.61.1 versioned realloc entry](https://docs.rs/crate/wit-bindgen/0.61.1/source/src/rt/wit_bindgen_cabi_realloc.rs)
- [`wit-bindgen` custom-section helper fixture](https://github.com/bytecodealliance/wit-bindgen/tree/v0.61.1/tests/runtime/rust/disable-custom-section-link-helpers)
- [`wit-bindgen` feature flags](https://docs.rs/crate/wit-bindgen/0.61.1/features)
- [`wit-bindgen::generate!`](https://docs.rs/wit-bindgen/0.61.1/wit_bindgen/macro.generate.html)
- [`wasmparser` 0.258.0 Cargo features](https://docs.rs/crate/wasmparser/0.258.0/features)
- [`wasmparser` 0.258.0 feature sets](https://docs.rs/wasmparser/0.258.0/wasmparser/struct.WasmFeatures.html)
- [`wasmparser` 0.258.0 validator](https://docs.rs/wasmparser/0.258.0/wasmparser/struct.Validator.html)
- [`ComponentEncoder::reject_legacy_names`](https://docs.rs/wit-component/0.258.0/wit_component/struct.ComponentEncoder.html#method.reject_legacy_names)
- [Component Model standard core-name encoding](https://github.com/WebAssembly/component-model/pull/378)
- [`wit-component` 0.258.0 decoder](https://docs.rs/wit-component/0.258.0/wit_component/fn.decode.html)
- [`wit-component::metadata::encode`](https://docs.rs/wit-component/0.258.0/wit_component/metadata/fn.encode.html)
- [`wit-parser` 0.258.0 source map](https://docs.rs/wit-parser/0.258.0/wit_parser/struct.SourceMap.html)
- [`wit-parser` 0.258.0 resolver](https://docs.rs/wit-parser/0.258.0/wit_parser/struct.Resolve.html)
- [`wit-component` decoder containment regression](https://github.com/bytecodealliance/wasm-tools/issues/2506)
- [Rust `Command` process construction](https://doc.rust-lang.org/std/process/struct.Command.html)
- [Rust `Child::try_wait`](https://doc.rust-lang.org/std/process/struct.Child.html#method.try_wait)
- [`ed25519-dalek` 3.0.0](https://docs.rs/crate/ed25519-dalek/3.0.0)
- [`VerifyingKey::verify_strict`](https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict)
- [`sha2` 0.11.0](https://docs.rs/crate/sha2/0.11.0)
- [RFC 8032: EdDSA](https://www.rfc-editor.org/rfc/rfc8032.html)
- [Cargo configuration](https://doc.rust-lang.org/cargo/reference/config.html)
- [Cargo build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html)
- [Cargo registry checksums](https://doc.rust-lang.org/cargo/reference/registry-index.html)
- [Git hash-function transition](https://git-scm.com/docs/hash-function-transition.html)
- [Git tree enumeration](https://git-scm.com/docs/git-ls-tree)
- [Git object inspection](https://git-scm.com/docs/git-cat-file)
- [Git data model](https://git-scm.com/docs/gitdatamodel.html)
- [SLSA 1.2 source requirements](https://slsa.dev/spec/v1.2/source-requirements)
- [in-toto digest sets](https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md)
- [Rust code-generation options](https://doc.rust-lang.org/rustc/codegen-options/)
- [Rust `wasm32v1-none` linker-plugin-LTO issue](https://github.com/rust-lang/rust/issues/145491)
- [LLD WebAssembly linker](https://lld.llvm.org/WebAssembly.html)
- [LLD WebAssembly options](https://github.com/llvm/llvm-project/blob/main/lld/wasm/Options.td)
- [LLD WebAssembly extraction reporting](https://github.com/llvm/llvm-project/blob/main/lld/wasm/Driver.cpp)
- [Wasmtime platform support](https://docs.wasmtime.dev/stability-platform-support.html)
- [Wasmtime minimal embedding](https://docs.wasmtime.dev/examples-minimal.html)
- [Wasmtime deterministic execution](https://docs.wasmtime.dev/examples-deterministic-wasm-execution.html)
- [Wasmtime interruption](https://docs.wasmtime.dev/examples-interrupting-wasm.html)
- [Wasmtime precompiled-artifact guidance](https://docs.wasmtime.dev/examples-pre-compiling-wasm.html)
- [Wasmtime security advisories](https://github.com/bytecodealliance/wasmtime/security/advisories)
- [Wasmtime guest-resource exhaustion advisory](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-852m-cvvp-9p4w)
- [SLSA 1.2 artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts)
