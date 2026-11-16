# W-V1 inventory — BLOCKED

Inventory date: 2026-11-16. See `REPORT/E3/E3-GATE-REPORT.md` §10.

No legacy container is supplied in this directory. This is **not** a certified
empty corpus. E3-G must continue to exit 4 (BLOCKED).

## Required input

Supply the original, supported v1.0.1 and v1.1 legacy fixture containers with
traceable provenance. Do not substitute malformed PoCs or newly assembled smoke
tests for the legacy fixture set. No `audit_suite/**/poc_defects/**` container
belongs in the decode-success set merely because it has a `.mapr` suffix.

The E3-G reader discovers regular `*.mapr` files immediately in this directory,
sorted by path. Its `manifest.tsv` format is three tab-separated fields:

```
<filename.mapr>\t<container SHA-256>\t<decoded denotation SHA-256>
```

The separators must be actual tabs; hashes must be independently verified lowercase
hex SHA-256 values. Blank lines and lines beginning with `#` are ignored. There
is deliberately no manifest with invented entries or digests here. The directory
alone must never unblock the gate.

Before populating the corpus, resolve the evidence issues recorded in report §10:
C08's two-column manifest reader disagrees with E3-G's three-column reader, and
E3-G currently hashes atom-table payload concatenation rather than evaluating the
root denotation. These are not equivalent for general legacy terms. This inventory
change does not alter either implementation or claim those obligations are met.
