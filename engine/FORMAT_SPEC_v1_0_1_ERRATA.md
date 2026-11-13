# Normative Format & CLI Specification Errata (`MAPR v1.0.1`)

This self-contained normative addendum resolves `DEF-001` through `DEF-006` without modifying any valid `MAPR v1.0` container produced by the Phase 4/5 encoder. Every valid `.mapr` archive emitted by `v1.0.0` remains 100% valid and byte-identical under `v1.0.1`.

---

## 1. Envelope & Directory Validation Tightening (`FORMAT_SPEC.md` §3, §5, §6)

1. **Header `flags` (`offset 12..16`):** Bits `3..31` MUST be `0` (`(flags & ~0x00000007u) == 0`). Bit `1` (`FLAG_HAS_INDEX = 0x00000002`) MUST be `1` in v1.0. When `FLAG_STREAMED_HEADER` (`0x00000004`) is set, each of `hdr_total_bits`, `hdr_chunk_count`, and `hdr_index_offset` MUST be either `0` or equal to its authoritative `TRLR` counterpart.
2. **`StreamConfig` Bounds (`offset 32..52`):** `w_sync == 64`, `0 < l_min <= l_target <= l_max <= 16,777,216`, and `w_hist <= 4096`.
3. **Overflow-Safe `INDX` Bounds (§5):** Decoders MUST validate `index_offset >= 64`, `index_offset + 20 <= file_size - 72`, and:
   ```text
   avail = (file_size - 72) - index_offset - 20
   (avail % 32 == 0) AND (avail / 32 == chunk_count)
   ```
   prior to allocating `chunk_count` directory entries. For `CHUNK_REF` entries (`chunk_kind == 0`), `frame_bytes` MUST equal `36`.
4. **Trailer `trailer_flags` (`TRLR + 4`):** MUST equal `0x00000001` exactly (`!= 1` MUST be rejected).

---

## 2. Canonical `ULEB128` & Intermediate DAG Safety Cap (`FORMAT_SPEC.md` §4.2–§4.3)

1. **Canonical Minimal `ULEB128`:** A varint MUST occupy at most `10` bytes (`iter in 0..9`). On `iter == 9` (`shift == 63`), `byte` MUST equal `0x01` (any continuation bit `0x80` or value `> 1` overflows `uint64` and MUST be rejected). For `iter > 0`, a terminal byte `0x00` represents a redundant leading zero group (non-canonical overlong encoding) and MUST be rejected. Biased fields (`d = raw_d + 2`, `q = raw_q + 1`, `length = raw_ln + 1`) MUST check against `UINT64_MAX` wraparound before addition.
2. **DAG Node Count Cap:** `1 <= m_c <= 2 * ell_c + 16`.
3. **Static Intermediate Length Cap:** For every node $v \in [0, m_c)$ in an `EXPLICIT_DAG` of superchunk bit-length $\ell_c$, the static output bit-length $|v|$ (including `AtomSpanNode`, `ConcatNode`, `RepeatNode`, `InterleaveNode`, and `LfsrNode`, checked via division before 64-bit multiplication) MUST satisfy:
   $$|v| \le \max(4 \cdot \ell_c + 4096,\; 67,108,864).$$

---

## 3. Inline Self-Contained Operator & Digest Formulas (`FORMAT_SPEC.md` §4.3 & §6)

1. **Colexicographic `unrank(b, w, rho)` (`0 <= rho < comb(b, w)`):** Iterate $j = w, w-1, \dots, 1$; choose the largest $i_j \in [j-1, i_{j+1}-1]$ (with $i_{w+1} = b$) such that $\binom{i_j}{j} \le r$, set output bit $i_j \leftarrow 1$, and update $r \leftarrow r - \binom{i_j}{j}$.
2. **Dyadic Zhegalkin Transform (`beta == 1`, $b = 2^k \in \{1,2,4,8,16,32,64\}$):** Starting from the unranked $b$-bit coefficient word $c$, for each stage $s \in \{0, \dots, k-1\}$ (step $2^s$), replace every block of $2^{s+1}$ bits $(L, H)$ by $(L, L \oplus H)$; bit $i \in [0, b)$ of the resulting word is output bit $i$.
3. **Stride-$s$ `INTERLEAVE` ($s \in \{8,16,32,64\}$ lanes $L_0,\dots,L_{s-1}$ of length $m \ge 1$):** Output length is $s \cdot m$, with output bit $t \in [0, sm)$ given by $L_{t \bmod s}[\lfloor t / s \rfloor]$.
4. **LFSR Evaluation (`1 <= L <= 64`, `1 <= conn_mask < 2^L`, `0 <= init_mask < 2^L`, `length >= 2L + 1`):**
   - For $0 \le i < L$: $y_i = (\text{init\_mask} \gg i) \ \& \ 1$.
   - For $L \le t < \text{length}$: $y_t = \bigoplus_{j=1}^{L} \big(((\text{conn\_mask} \gg (j - 1)) \ \& \ 1) \cdot y_{t - j}\big)$.
5. **Stream `SHA-256` (`TRLR + 32`):**
   - If `FLAG_RAW_BYTES_MSB == 1` (`N mod 8 == 0` required): `SHA256(MSB_packed_bytes(X))` (`N / 8` bytes, where bit $0$ of $X$ is bit $7$ `[0x80]` of byte $0$).
   - If `FLAG_RAW_BYTES_MSB == 0`: `SHA256(uint64_be(N) || MSB_zero_padded_bytes(X))` (`8 + ceil(N / 8)` bytes, with unused low bits `0 .. (7 - ((N-1) mod 8))` of the final byte set to `0`).

---

## 4. CLI Specification Alignment (`REPRODUCE.md` §3.1)

`mapr encode` accepts `--input <file>` (raw bytes by default, `--bitseq` for `uint64_be(N) || MSB_padded_bytes`) **or** `--bitstring "<01...>"`; `mapr decode` accepts `--output <file>` (`--bitseq` optional) **or** `--out-bitstring` (ASCII `'0'`/`'1'` to `stdout`).
