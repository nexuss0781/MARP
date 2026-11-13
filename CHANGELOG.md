# MAPR Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-11-09

### Added
- **Phase 0**: v1.0.1 Release - C++20 streaming encoder/decoder, Python reference decoder, structural bit-provenance analyzer
- **Phase 1**: C API + Adaptive Runtime - Hardware probe, thread pool, profile system (FAST/BALANCED/THOROUGH/MAX)
- **Phase 2**: SIMD Kernels + Algorithm Tuning - AVX2, AVX-512, NEON kernels for popcount, bitrev, mobius, splitmix64, crc32, minhash
- **Phase 2**: SHA-256 SIMD infrastructure with scalar fallback and SHA-NI/ARM crypto extensions ready
- **Phase 3**: Packaging & Distribution - Conan, vcpkg, Debian, RPM, Homebrew, Chocolatey, CI/CD
- **Phase 4**: Python bindings (ctypes-based) - encode/decode/inspect/verify with all 4 profiles
- **Phase 5**: Streaming encoder C API - zero-copy streaming with memory buffer output
- **Phase 5**: WASM infrastructure - CMake config, TypeScript/JS bindings, GitHub Actions workflow
- **Phase 5**: WASI infrastructure - CMake config for WebAssembly System Interface
- **Phase 6**: Production hardening - libFuzzer harnesses, sanitizer CI, Frama-C/ACSL annotations, SBOM generation, security policy

### Changed
- Refactored `BoundedChunkPipeline` into separate `pipeline.cpp`/`pipeline.hpp`
- Added `pipeline_helpers.hpp` for V_4 signature computation
- Container writer now supports both file and memory buffer output
- C API streaming encoder implemented with proper resource management

### Fixed
- Python ctypes struct layout to match C API exactly
- Duplicate symbol errors in SHA-256 kernel files
- NEON kernel compilation on non-ARM platforms
- Memory buffer overwrite in ContainerWriter finish()

### Security
- SECURITY.md with responsible disclosure policy
- SLSA Level 2 provenance generation
- CycloneDX SBOM generation
- GPG-signed releases
- Dependabot configuration for all ecosystems

## [1.0.0] - 2026-10-01 (Initial Release)

### Added
- Core compression engine with algebraic and compositional pattern representation
- Multi-mechanism encoding: ATOM_POS, ATOM_ZHEG, REPEAT, LFSR, INTERLEAVE, XOR_DIFF, MORPHIC_LIFT
- Bit-provenance tracking with 100% accountability
- Streaming encoder/decoder for large files
- C++20 implementation with C API

---

## Release Checklist

For each release:
- [ ] All tests pass (131071 exhaustive sequences)
- [ ] Sanitizer builds pass (ASan, UBSan, MSan, TSan)
- [ ] Fuzzing runs complete without crashes
- [ ] Formal verification passes
- [ ] SBOM generated (CycloneDX)
- [ ] Artifacts GPG-signed
- [ ] SLSA Level 2 provenance generated
- [ ] Release notes updated
- [ ] Package managers updated (Conan, vcpkg, npm, Cargo, etc.)
- [ ] Documentation updated

---

## Upgrade Guide

### From 1.0.0 to 1.0.1
- No breaking changes
- Python bindings now include `inspect_file` and `verify_file`
- C API includes streaming encoder
- All existing code continues to work

### From 0.x to 1.0.0
- Major API changes
- See migration guide (to be created)
## [Stage 2] - 2026-11-12 (complete, ledger-backed)

Source of truth for Stage 2 records: `MARP/LEDGER.md`. Handoff: `MARP/specs_and_reports/stage2/HANDOFF_MARP_STAGE2.md`.

### Defects closed (M-D1–M-D5)
- **M-D1**: Removed `ACTIVE_INTERLEAVE_BITS` from `node_counts` in inspection accounting (`engine/src/dag.cpp`).
- **M-D2**: Regenerated `test_full.mapr` from `test.zip`; decode+cmp verified. SHA-256 recorded in ledger.
- **M-D3**: `MARP/LEDGER.md` established as Stage 2 source of truth; `PHASES.md` reconciled; CHANGELOG maintained from ledger.
- **M-D4**: CLI banner/version output `MAPR v1.0.1 C++20`.
- **M-D5**: `RESEARCH.md` §A2 superseded; `RAW` legal (v1.1 additive).

### Implemented
- **RAW/noise (M-G1)**: RAW opcode end-to-end; noise detection and byte-boundary literal passthrough. 1 MiB random ratio **1.000849×–1.001060×**, exact round-trip.
- **IR v2 (M-G3)**: `IrProgram/IrNode/IrAtom`, `encode_to_ir(BitSeq|DAG)`, `decode_from_ir`, `ir_to_dag`, topological order and exact lengths. Conformance verified in test suite and on valid legacy fixtures.
- **Canonicalisation (C.1–C.5)**: 8 rewrite rules to fixed point (empty elim, concat flatten, adjacent literal merge with exact atom-bit concatenation, repeat norm, slice fold, morph fold, INTERLEAVE ordering, structural dedup/hash-consing). Idempotent and lossless.
- **Global dedup (M-G2, D.1–D.6)**: content-addressed index `(bit_length, sha256)`, deterministic serialization; near-duplicate detection via XOR density over aligned windows for XOR_DIFF. Measured: 10 near-duplicate 100 KiB docs 1,026,437 B → 483,715 B combined (2.1×), exact decode.
- **DEFLATE-aware front end (F.1–F.5)**: detects zlib/gzip/raw deflate, parses stored/fixed/dynamic Huffman block boundaries, exposes boundaries to DAG builder/analysis, lossless deflate-aware encoding. Measured: `test_1mb.zip` 1,000,000 B → 1,021,533 B (1.021533×), decode byte-identical.
- **Translator (M-G4, T.1–T.5)**: spec `mapr::translate::{Term,Program,fromIr}` with exact decimal params, `Unknown` for unexpressible nodes, pure; extended `MauProgram` preserves atom bit_length; lengths reconstructible.
- **3-DAG (X.1–X.4)**: 64 MiB payload SHA-256 `281e519df3077b557c6b03f5da83c4e8d397219259615dd7c3308f89cae8f2a6`. D1 5,498,976 B, D2 60,975,200 B, D3 67,438,688 B, all decode identical. Handoff artifact created.
- **Determinism (M-G7)**: identical input ⇒ byte-identical output; canonicalisation idempotent.

### Verification (Z.1–Z.5)
- `make test` PASS: KATs, algebra/LFSR, exhaustive n≤16 131071/131071, multi-chunk V4/streaming/determinism, 500/500 adversarial rejects, IR v2/canonicalisation/translator tests.
- Valid legacy fixtures decode; independent decoder byte-identical on tested valid fixtures; corrupt fixtures rejected by both.
- 100k-mutation fuzz campaign (`MARP/SPECS/fuzz_100k.py`, final Stage 2 binary): **100,000 rejected, 0 accepted, 0 crashes** (log `/tmp/marp_fuzz_100k.log`).
- Benchmark report and gate transcript updated: `MARP/specs_and_reports/BENCHMARK_REPORT.md`, `MARP/specs_and_reports/stage2/GATE_TRANSCRIPT_STAGE2.md`.

