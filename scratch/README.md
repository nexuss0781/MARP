# `scratch/` — development probes for E2-G

These are throwaway single-file C++ probes used to answer specific questions while
building the E2-G gate. They are **not** part of any build, are not linked into
`bin/e2_g_gate`, and are not covered by any evidence manifest. They are kept because
`REPORT/E2/E2-GATE-REPORT.md` cites several of them as the reason for a recorded
decision:

| Probe | Question it answered | Report section |
|---|---|---|
| `probe19.cpp` | are all 64 T-BAD terms rejected with their named constraint? | §3 |
| `probe20.cpp` | are the 17 T-CRIT templates individually well formed and joinable? | §6.1 |
| `probe23.cpp` | does a described nested `Concat` ever produce a rule-1 redex? (no) | §6.2 |
| `probe24.cpp` | why did `slice-assoc` fail to join? (the two members denoted different terms) | §6.3 |
| `probe26.cpp` | is rule 1 reachable at all? (yes, via rule-5 `Repeat` expansion) | §6.2 |
| `probe27.cpp` | why did 10 `nc-gen` rows fail WF? (stride/morph-`k` preconditions) | §6.3 |
| `probe28.cpp`–`probe30.cpp` | which slice/repeat pairs actually fire rules 6 and 11 together? | §6.3 |
| `probe31.cpp` | does `oracle_range` bounds-check? (no) and what does the empty term admit? | §6.5 |
| `probe32.cpp` | which T-BIG terms have lengths above 2^40? | §6.5 |
| `probe33.cpp` | is `W8.atom-id` reachable from a patched `Ir`? (yes) | §6.4 |

Build any of them against the gate's objects, e.g.

```
cd engine
g++ -std=c++20 -O1 -I. -I../include -Isrc/e2 -o /tmp/probe33 ../scratch/probe33.cpp \
    obj/e2g_harness/e2/e2g_terms.o obj/e2g/e2/*.o obj/e2g/e1_*.o -pthread
```
