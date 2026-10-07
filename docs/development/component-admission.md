# Component admission core

The OS041A host tool is an offline pre-admission checker for the fixed
profile-zero bundle selected by ADR-0008. It does not boot MakopaOS, compile or
instantiate a component, contact a network service, or grant workload
authority. A successful report has `admission_authority: false` until the
remaining OS041A producer, reconstruction, semantic-comparison, and containment
work is complete.

## Implemented feature set

This delivery adds ten bounded features:

1. checked explicit-offset parsing for the 288-byte
   `ComponentAdmissionV1` record;
2. checked explicit-offset parsing for the 224-byte `ExecutionProfileV1`
   record;
3. checked explicit-offset parsing for the 256-byte `BuildEvidenceV1` record;
4. exact length, digest, syntax, ordering, and public-evidence checks for the
   supporting documents;
5. SHA-256 binding for the component, optional executable, WIT, metadata
   records, source manifest, configuration, transcript, lock, and tool-version
   bytes;
6. domain-separated 16-byte signing-key identifiers;
7. strict Ed25519 verification of the exact 318-byte message, including weak
   key, wrong-key, key-ID, size, and mutation rejection;
8. the canonical `makopa-source-manifest-v1` parser plus independent staged-root
   path, mode, length, digest, missing-file, extra-file, and symlink checks;
9. independent final-byte validation with the exact WebAssembly 1.0 plus base
   Component Model mask and a raw top-level allowlist containing only
   `makopa:component/console@1.0.0` and
   `makopa:component/task@1.0.0`; and
10. deterministic single-line JSON success and failure reports with stable
    categorical error codes.

The implementation lives in its own locked host workspace under
`tools/component-admission`. The target runtime remains dependency-free and no
boot, kernel, QEMU, or runtime-execution path imports these crates.

## Command interface

Build or run the checker with Rust `1.97.1` and its committed lockfile:

```sh
cargo +1.97.1 run --locked --offline \
  --manifest-path tools/component-admission/Cargo.toml \
  --bin makopa-component-admission -- check \
  --admission component-admission-v1.bin \
  --signature component-admission-v1.sig \
  --public-key test-root.ed25519.pub \
  --component workload.component.wasm \
  --wit console-workload.wit \
  --execution-profile execution-profile-v1.bin \
  --target-triple target-triple.txt \
  --runtime-config runtime-config.txt \
  --compiler-config compiler-config.txt \
  --build-evidence build-evidence-v1.bin \
  --source-manifest source-manifest-v1.txt \
  --builder-identity builder-identity.txt \
  --command-transcript commands.txt \
  --dependency-lock Cargo.lock \
  --tool-versions tool-versions.txt \
  --source-root staged-source
```

`--executable FILE` is accepted only when the admission record declares a
nonzero executable length and digest. Every other input is required exactly
once. Unknown, duplicated, missing, non-file, symlinked, oversized, malformed,
or mismatched input fails closed. Input paths never appear in the JSON report.

A successful precheck emits this fixed field order:

```json
{"schema_version":1,"scope":"os041a-admission-core-v1","status":"pass","admission_authority":false,"component_id":7,"portable_sha256":"...","source_file_count":1,"source_byte_count":128,"section_count":4,"maximum_depth":0}
```

A failure is written to standard error and exits with status `2`:

```json
{"schema_version":1,"scope":"os041a-admission-core-v1","status":"fail","admission_authority":false,"error":"digest"}
```

## Verification

```sh
cargo +1.97.1 fmt \
  --manifest-path tools/component-admission/Cargo.toml --all -- --check
cargo +1.97.1 test --locked --offline \
  --manifest-path tools/component-admission/Cargo.toml
cargo +1.97.1 clippy --locked --offline \
  --manifest-path tools/component-admission/Cargo.toml \
  --all-targets -- -D warnings
```

The tests use one frozen public key and detached signature only. There is no
private seed, signing API, key generation, network lookup, component decoder,
runtime compiler, or execution engine in the repository.

## Remaining OS041A work

This checker intentionally does not yet reconstruct a declared tree from
committed Git objects, produce the pinned `wasm32v1-none` fixture, decode final
component metadata in a contained worker, compare raw, decoded, and supplied
WIT semantic graphs, run contained compile-only Wasmtime measurements, or
produce the specified link and disassembly evidence. Those gates remain on the
OS041A roadmap. Until they pass together, this tool is a deterministic
pre-admission check rather than authority to ship or execute component bytes.
