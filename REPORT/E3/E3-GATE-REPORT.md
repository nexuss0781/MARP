# E3-G integrated gate — W-V1 closure

**E3-G PASS (closed)** for the CI-verified gate and evidence below; integration
into `h2-gates` remains subject to merge.

## Corpus and provenance

The W-V1 files are byte-identical copies of the names in
`specs_and_reports/v2/W-V1/imported/`, imported from the local legacy artifacts at
`/home/nexuss0781/Desktop/Nex/MARP`. The three-column manifest at
`specs_and_reports/v2/W-V1/manifest.tsv` records every container and output hash in
full. These are SHA-256 of exact container bytes and the byte-exact evaluated root
term denotation, respectively; they are not hashes of a concatenated atom table.
No malformed, PoC, intentionally defective or `poc_defects` files are in this set.
The 10,388,756-byte fixture is under 10 MiB, covers a multi-node term, and is kept
for CI; the matching source copy is already committed.

| Fixture | Container SHA-256 | Denotation SHA-256 |
|---|---|---|
| small.mapr | 3c27af46e91f0fca361b04621882ca10992ae7efb77b8c9b0ae96bb979b7e3f5 | a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447 |
| test_10mb.mapr | 8e467480fbeeec6b4f0d227b8addbd0fd3c9ec765243bdff9ebc3c87eab2056b | a64e7a129a9a46650ba3287ba535404fe89656f67e21a4aeb746061d7b088327 |
| test_1mb.mapr | 1b721544e2e0a51e8aca6febccf1644082d47dc6cb368e353d365fb18e62108d | f268167f8ff792d9a7c7d13cd6eda9c5d5eb5ca61bd258436c057e6366a1da77 |
| test_simd.mapr | ba8fb0f26317ddba03b815ae67b823c2871093dd86375c9987ed54699e0c2fb4 | 144c7552b8c29a2abd00131f431000a129d173b88368fc81a233db5a5ed32cf5 |
| test_simd_out.mapr | 7f6f9285ff2cbaa64cf6f2818e117e29ce928da3555f45c073153b62e29238b6 | 144c7552b8c29a2abd00131f431000a129d173b88368fc81a233db5a5ed32cf5 |

The manifest describes the independent output-hash derivations and trailer
cross-check. `logs/E3-G-legacy.log` records individual decoded lengths and hashes.

## Integration decisions

* C08 and E3-G consume the same strict three-column manifest; missing or malformed
  entries cannot silently certify their own observed hash.
* Evaluate the decoded root using E2's streaming evaluator and independently hash
  that stream; compare with E2's digest and the pinned denotation. This is the
  narrow interpretation of §13.3 and §13.4 step 8, including nontrivial DAGs.
* Correct the structural transcript's eight-field node parser: the argument count,
  arguments, parameters and length are distinct fields. This fixes reconstruction
  of multi-argument nodes before v2 re-encoding.
* Keep C08 read-only and process-isolated from the v2 encoder. Hash the manifest
  and pinned fixture bytes in E3 evidence. Require the actual gate exit code and
  zero blocked rows in the final CI verdict.
* Verify each re-encoded W-V1 output with the independent H3 oracle against its
  pinned denotation; record a separate per-fixture oracle row.

## Verification and evidence

The reproducible full campaign uses 100,000 mutations, four fuzz workers and
thread counts 1 and 4. The evidence is generated under `specs_and_reports/v2/`:
`gates/E3-G.tsv`, `logs/E3-G*.log`, `corpus/E3/`, and `evidence/E3/`. C08 gate
evidence is also regenerated because its manifest reader changed. The gate rows
are the authoritative per-check results; `SHA256SUMS` and `MANIFEST.tsv` cover the
recorded artifacts and pinned inputs. GitHub Actions E3-G run [43851109530](https://github.com/nexuss0781/MARP/actions/runs/43851109530) passed on the pull request, including byte-identical evidence reproduction, sanitizer and final verdict checks. Push run [43851092856](https://github.com/nexuss0781/MARP/actions/runs/43851092856) also passed. These runs test commit `67e3f401bd980325096b916f9bad97e12ea6d08a`; this report-only update does not alter the measured artifacts. The PR and eventual merge record identify the integration commit.

Local full run: **PASS**, exit 0, 41,335 rows PASS, zero FAIL or BLOCKED;
5/5 W-V1 fixtures decoded and verified, with five H3 denotation-verification
rows PASS. W-CANON encoded 5,143/5,144 (one expected limit case), H3 agreed on
5,143; W-NONCANON rejected 48/48; W-SEED fixpoint 5,151/5,151. All 100,000
mutants were accounted for, with zero accepted-invalid, crashes, timeouts or
allocation violations. Binary isolation passed. C08 gate passed and independently
reproduced its evidence byte-for-byte. GoogleTest was not installed locally, so
unit tests requiring it must be verified in CI.
