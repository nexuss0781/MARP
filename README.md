# MAPR v1.0.1 — Final Production Release & Technical Monograph

**Multi-Scale Algebraic & Compositional Pattern Representation (`MAPR v1.0.1`)**  
**Conformance Status:** `10 / 10` Phase 6 Audit Gates `PASS` (`215,770` fuzz cases, `19.91-Gbit` census, `0` remaining defects)

## Package Contents

- **`docs/`**
  - `MAPR_Technical_Monograph_Phases1_6.pdf` — 14-page typeset publication monograph (Phases 1–6 theory, proofs, `.mapr` wire spec, `2.104 GiB` benchmarks, and clean-room audit).
  - `MAPR_Technical_Monograph_Phases1_6.docx` — Editable Microsoft Word OOXML monograph.
  - `figures/` & `monograph_src/` — 300-DPI figures and Typst/Python monograph generators.
- **`engine/`** — Final remediated **`MAPR v1.0.1`** zero-dependency C++20 streaming engine:
  - `bin/mapr` & `bin/mapr_tests` (precompiled Linux `x86_64` binaries with `+x` set; rebuild anytime via `make -C engine`).
  - `include/`, `src/`, `tests/`, `Makefile`, and `FORMAT_SPEC_v1_0_1_ERRATA.md`.
- **`independent_decoder/`** — Zero-shared-code clean-room Python `.mapr` reference decoder (`./independent_decoder/mapr_indep_decode`).
- **`structural_census/`** — Exact non-double-counted structural bit-provenance & single-bit genealogy analyzer (`./structural_census/mapr_census`).
- **`specs_and_reports/`** — Complete Phases 1–6 specifications, benchmark reports, defect ledger, security audit, structural census, and final verdict.
- **`audit_suite/`** — `32` mathematical KATs, `119` boundary tests, sanitizer fuzzers, PoCs, and JSON audit telemetry.

## Quick Start

```bash
# 1. Run the C++20 v1.0.1 test suite (131,071 exhaustive n<=16 + adversarial fuzz checks)
./engine/bin/mapr_tests

# 2. Encode, verify, inspect, and decode any standard .zip archive
./engine/bin/mapr encode input.zip archive.mapr --threads 4
./engine/bin/mapr verify archive.mapr
./engine/bin/mapr inspect archive.mapr
./engine/bin/mapr decode archive.mapr recovered.zip

# 3. Cross-verify with the independent clean-room Python reference decoder
python3 ./independent_decoder/mapr_indep_decode decode archive.mapr recovered_cleanroom.zip
```
