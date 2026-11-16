# W-V1 legacy fixture inventory

The five pinned containers alongside this file are byte-for-byte copies of the
corresponding `imported/*.mapr`. Those files were imported from
`/home/nexuss0781/Desktop/Nex/MARP`, local legacy artifacts now committed in this
repository. The supported decode-success corpus consists only of these five; no
malformed, intentionally invalid, PoC or `poc_defects` container was included.

`manifest.tsv` is the authoritative inventory, with actual tab-separated fields
`filename`, container SHA-256 and SHA-256 of the evaluated root denotation. Blank
lines and `#` comments are permitted. Both the E3-G and C08 consumers read this
format. Hashes were measured from the file bytes and decoded output, not guessed;
the manifest records the cross-checks. C08's `looks_like_v1` and `decode_v1`,
canonical checks, and the independent v2 oracle are exercised by the gate.

`test_10mb.mapr` is 10,388,756 bytes (under 10 MiB); it supplies a larger,
multi-node example and is retained as a CI fixture rather than a build artifact.
All five source copies are already tracked in `imported/`. See the E3-G report for
results and CI status.
