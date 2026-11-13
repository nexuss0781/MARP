# MAPR Development Phases & Stage 2 Reconciliation

## Source of truth (reconciled, M-D3)

- **Stage 2 defects/gate measurements/artifacts:** `MARP/LEDGER.md`
- **Release/change record:** `MARP/CHANGELOG.md` (Stage 2 section maintained from `MARP/LEDGER.md`)
- **Stage 2 specification and acceptance:** `MARP/SPECS/SPECS.md`, `MARP/SPECS/Todo.md`

Historical phase roadmap items below v1.0.1 release are retained as context; where they conflict with Stage 2 measured records, the ledger/todo evidence takes precedence.

---

## Historical roadmap (v1.0.1+)

| Phase | Focus | Status |
|---|---|---|
| 0 | v1.0.1 Release | Complete (historical) |
| 1 | C API + Adaptive Runtime | Planned/historical |
| 2 | SIMD Kernels + Algorithm Tuning | Planned/historical |
| 3 | Packaging & Distribution | Planned/historical |
| 4 | Language Bindings | Planned/historical |
| 5 | Streaming & Edge Optimizations | Planned/historical |
| 6 | Production Hardening | Planned/historical |
| 7 | Ecosystem & Documentation | Planned/historical |

## Stage 2 (Expression Engine, 2026-11)

Stage 2 work is executed against `MARP/SPECS/SPECS.md` and tracked in `MARP/SPECS/Todo.md` with evidence recorded in `MARP/LEDGER.md`.

Key Stage 2 outcomes recorded to date (see ledger/todo for details): M-D1/M-D2/M-D3/M-D4/M-D5 addressed, RAW/noise path wired with measured 1 MiB random ratio 1.001060× and exact round-trips, determinism verified, engine `make test` PASS, 3-DAG experiment (X.1–X.3) generated/decoded with identical payload hashes.
