# C08 `LEGACY` — Implementation Report (E3 WIRE)

**Scope:** read-only decoding of frozen MARP v1.0.1/v1.1 containers into canonical E2 IR. This report does not claim E3-G or V2-G13: the required W-V1 corpus is absent.

**Sources:** `SPECS/SPECS-V2.md`, `SPECS/COMPONENTS-V2.md` C08, `SPECS/COMPONENTS/e3-wire/SPECS.md`, and `engine/FORMAT_SPEC_v1_0_1_ERRATA.md`.

## Environment and validation

| Field | Value |
|---|---|
| Repository / branch | `nexuss0781/MARP` / `arena/198d1a9f-marp` |
| Base | `abe500b4a98725a214c7074ab0aa4ef90b0fbd18` (`h2-gates`) |
| Validated implementation and workflow | `b10fdc6803b6c81681f8bec2aee313043a700d15` |
| C08 CI | [run 43736556453](https://github.com/nexuss0781/MARP/actions/runs/43736556453), success, Ubuntu latest, GCC 15.2.0 |
| Sibling CI on same commit | H3 `43736556384`, C03 `43736556372`, C04 `43736556342`, C05 `43736556416`, C06 `43736556435`: success |
| E2-G CI on same commit | [run 43736556413](https://github.com/nexuss0781/MARP/actions/runs/43736556413): in progress at time of writing |

The C08 workflow validates source and binary isolation, strict C++20 build, 13 GoogleTest cases, committed evidence hash verification and byte-identical regeneration, schema and verdicts, independent determinism repeat, ASan+UBSan tests and evidence, and preservation of earlier evidence. The report commit changes documentation only; the above CI results refer to the stated commit, not to an unobserved later run.

## Implementation and wire behavior

`include/mapr/e3/e3_legacy.hpp` defines the boundary types, random-access `Source`, stable bounded `Arena`, `LegacyLimits`, magic probe and `decode_v1`; `engine/src/e3/e3_legacy.cpp` implements the reader. The decoder does not expose a v1 writer or require Stage 1/2 engine internals. `engine/tests/e3/` contains synthetic containers and tests; `engine/Makefile.c08`, `engine/src/e3/e3_c08_gate.cpp` and `.github/workflows/e3-c08.yml` provide isolated build and evidence checks.

The reader validates the 64-byte header, chunk frames, index, trailer, bounds and integrity. It supports the documented v1.0/v1.1 framing, chunk references and explicit DAGs, translating supported operations to E2 IR. DAG fields use LSB-first bits and minimal ULEB128. Logical bits are packed MSB-first for the byte digest; non-byte-aligned bit sequences are verified but returned as unsupported. Opcodes 11 (DEDUP_REF) and 12 (DEFLATE_HINT) are unsupported. The resulting supported payload is checked against the trailer SHA-256 and translated to well-formed canonical IR.

Errors are distinguished as `Invalid` (malformed input), `Unsupported` (unsupported version or feature), `Mismatch` (integrity mismatch), `Limit` (resource cap), and `Io` (source failure). The public boundary also defines `Ok` and `Usage`. Explicit limits bound chunks, payload, nodes, output and evaluation working memory; the caller-provided arena controls storage lifetime and capacity.

## Evidence and reproducibility

`specs_and_reports/v2/gates/C08-LEGACY.tsv` has 17 data rows: 16 PASS and one BLOCKED. Coverage includes both versions, streamed and multichunk references, repeat, magic probing, 500 malformed mutations, digest mismatch, resource and I/O errors, unsupported opcodes, versions and sub-byte output, and isolation. Synthetic vectors are not a substitute for the missing W-V1 corpus.

Committed SHA-256 manifest (`specs_and_reports/v2/evidence/C08/SHA256SUMS`):

```text
07f668993093f6b522dcb9b2567c9089744386e3c5c62516bac5a9e41d373694  include/mapr/e3/e3_legacy.hpp
4443a1a6f3cfc1212390bf7434ef0103ae33c421ba99f6a626542f428ac284c6  engine/src/e3/e3_legacy.cpp
08c7aeadf640272110c01b270687873fd165bdac6fd21f2f51606d2eb1525c7d  specs_and_reports/v2/gates/C08-LEGACY.tsv
a700c3b31e8bfbdbc033ee669d1b33b5615061d85ffae9bc27b77e589d478598  specs_and_reports/v2/logs/C08-LEGACY.log
```

Run locally from `engine/` with `make -f Makefile.c08 c08-check`; `c08-evidence` regenerates the evidence and `c08-verify-evidence` verifies it. The CI checks committed versus freshly generated TSV and log byte for byte, then repeats independently.

## Stage 2 cross-check and outstanding gate

A local, temporary Stage 2 encoder build was used to cross-decode six containers, including empty input, 1 MiB zeros, text, source, opaque bytes and multichunk repeated input; decoded digests matched their original inputs. This was an exploratory local cross-check, **not a committed reproducible CI assertion or W-V1 certification**. A subsequent attempt to build Stage 2 in C08 CI failed on the newer runner; the Stage 2 build step was removed to preserve isolated C08 CI, so the green C08 run does not validate this cross-check.

`specs_and_reports/v2/W-V1` is not present. Consequently the committed `c08.w_v1_corpus` row remains **BLOCKED**, and E3-G / V2-G13 cannot be claimed. Supplying the corpus and its manifest and running the gate with `--w-v1-dir` is necessary to assess that corpus; broader E3-G requirements remain separate.
