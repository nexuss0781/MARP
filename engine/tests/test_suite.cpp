#include "mapr/bitio.hpp"
#include "mapr/bitseq.hpp"
#include "mapr/common.hpp"
#include "mapr/container.hpp"
#include "mapr/crypto.hpp"
#include "mapr/dag.hpp"
#include "mapr/decoder.hpp"
#include "mapr/encoder.hpp"
#include "mapr/math_core.hpp"

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <random>
#include <vector>

using namespace mapr;

#define REQUIRE(cond)                                                                     \
    do {                                                                                  \
        if (!(cond)) {                                                                    \
            std::cerr << "TEST FAILURE at " << __FILE__ << ":" << __LINE__ << ": " #cond  \
                      << "\n";                                                            \
            std::exit(1);                                                                 \
        }                                                                                 \
    } while (0)

namespace {

void test_crypto_vectors() {
    // IEEE 802.3 CRC-32 standard check value for "123456789" is 0xCBF43926
    const char* s = "123456789";
    REQUIRE(crc32_compute(reinterpret_cast<const uint8_t*>(s), 9) == 0xCBF43926u);

    // FIPS 180-4 SHA-256 standard vectors
    auto h_empty = Sha256::to_hex(Sha256::hash(nullptr, 0));
    REQUIRE(h_empty == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    const char* abc = "abc";
    auto h_abc = Sha256::to_hex(Sha256::hash(reinterpret_cast<const uint8_t*>(abc), 3));
    REQUIRE(h_abc == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // Multi-chunk streaming SHA-256 test
    std::string long_msg(10000, 'a');
    Sha256 s1;
    for (size_t i = 0; i < long_msg.size(); i += 137) {
        size_t take = std::min<size_t>(137, long_msg.size() - i);
        s1.update(reinterpret_cast<const uint8_t*>(long_msg.data() + i), take);
    }
    REQUIRE(s1.finalize() == Sha256::hash(reinterpret_cast<const uint8_t*>(long_msg.data()), long_msg.size()));
    std::cout << "  [PASS] IEEE CRC-32 & FIPS 180-4 SHA-256 vectors\n";
}

void test_tier1_algebra_and_combinatorics() {
    // 1. Proposition 2.1: C(64, 32) exact
    REQUIRE(binom64(64, 32) == 1832624140942590534ULL);
    REQUIRE(binom64(64, 0) == 1ULL && binom64(64, 64) == 1ULL);

    // 2. Colex rank/unrank across b = 1..64 including extreme 64-bit boundaries
    std::mt19937_64 rng(20261108ULL);
    for (int b = 1; b <= 64; ++b) {
        std::vector<uint64_t> samples = {0ULL, low_mask(b), 1ULL, low_mask(b) ^ 1ULL};
        for (int t = 0; t < 20; ++t) samples.push_back(rng() & low_mask(b));
        for (uint64_t wval : samples) {
            auto [w, rho] = rank_word_colex(wval, b);
            REQUIRE(unrank_word_colex(b, w, rho) == wval);
            DualBasisAtom a = encode_micro_atom(wval, b);
            REQUIRE(decode_micro_atom(a) == wval);
        }
    }

    // 3. Möbius involution M_k^2 == I for all dyadic b in {1,2,4,8,16,32,64}
    for (int b : {1, 2, 4, 8, 16, 32, 64}) {
        for (int t = 0; t < 50; ++t) {
            uint64_t x = rng() & low_mask(b);
            REQUIRE(mobius_word(mobius_word(x, b), b) == x);
        }
    }

    // 4. BitSeq byte bijection, unaligned slice/concat, and V4 group laws on odd 131-bit sequence
    std::vector<uint8_t> raw(257);
    for (size_t i = 0; i < raw.size(); ++i) raw[i] = static_cast<uint8_t>((i * 73 + 19) & 0xFFu);
    BitSeq bseq = BitSeq::from_bytes_msb(raw.data(), raw.size());
    REQUIRE(bseq.to_bytes_msb() == raw);

    BitSeq odd = bseq.slice(13, 131);
    REQUIRE(odd.bit_len() == 131);
    REQUIRE(BitSeq::concat({odd.slice(0, 67), odd.slice(67, 64)}) == odd);
    for (uint8_t op1 = 0; op1 < 4; ++op1) {
        V4Op o1 = static_cast<V4Op>(op1);
        REQUIRE(odd.apply_v4(o1).apply_v4(o1) == odd);
        for (uint8_t op2 = 0; op2 < 4; ++op2) {
            V4Op o2 = static_cast<V4Op>(op2);
            REQUIRE(odd.apply_v4(o1).apply_v4(o2) == odd.apply_v4(compose_v4(o2, o1)));
        }
    }

    // 5. 8x8 SWAR transpose & stride {8,16,32,64} bit-planes
    for (int t = 0; t < 100; ++t) {
        uint64_t x = rng();
        REQUIRE(transpose8x8_swar(transpose8x8_swar(x)) == x);
    }
    BitSeq sseq = bseq.slice(0, 1024);
    for (int s : {8, 16, 32, 64}) {
        auto lanes = deinterleave_bitplanes(sseq, s);
        REQUIRE(interleave_bitplanes(lanes, s) == sseq);
    }

    // 6. Berlekamp-Massey & LFSR evaluation including degree L = 64 boundary!
    for (int L : {1, 3, 16, 31, 63, 64}) {
        uint64_t conn = (1ULL << (L - 1)) | 1ULL; // 1 + x + x^L (with c_L = 1)
        uint64_t init = (rng() & low_mask(L)) | 1ULL;
        BitSeq lf = evaluate_lfsr(L, conn, init, 300);
        auto spec = verify_and_measure_lfsr(lf, 64, 256);
        REQUIRE(spec.has_value());
        REQUIRE(evaluate_lfsr(spec->degree, spec->conn_mask, spec->init_mask, 300) == lf);
    }
    std::cout << "  [PASS] Tier-1 algebra, 64-bit CNS, Möbius SWAR, V4, bit-planes, & L<=64 LFSR\n";
}

void test_exhaustive_131071_small_sequences() {
    auto t0 = std::chrono::steady_clock::now();
    uint64_t count = 0;

    // n = 0
    {
        BitSeq e = BitSeq::empty();
        auto dag = encode_chunk_dag(e);
        auto payload = serialize_chunk_dag_payload(dag);
        auto d2 = deserialize_chunk_dag_payload(payload.data(), payload.size(), 16);
        REQUIRE(evaluate_chunk_dag(d2, 0) == e);
        ++count;
    }

    for (int n = 1; n <= 16; ++n) {
        uint32_t lim = 1u << n;
        for (uint32_t v = 0; v < lim; ++v) {
            BitSeq s = BitSeq::from_word(v, n);
            auto dag = encode_chunk_dag(s);
            auto payload = serialize_chunk_dag_payload(dag);
            auto d2 = deserialize_chunk_dag_payload(payload.data(), payload.size(), 64);
            InspectionSummary isum;
            isum.add_chunk_dag(d2, static_cast<uint64_t>(n));
            REQUIRE(isum.accounted_bits == static_cast<uint64_t>(n));
            REQUIRE(evaluate_chunk_dag(d2, static_cast<uint64_t>(n)) == s);
            ++count;
        }
    }
    auto dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    REQUIRE(count == 131071ULL);
    std::cout << "  [PASS] Exhaustive n<=16 verification: " << count << " / 131,071 sequences in "
              << dt << " s\n";
}

void test_all_mechanisms_streaming_and_thread_determinism() {
    namespace fs = std::filesystem;
    fs::path tmp = fs::temp_directory_path() / "mapr_cpp_test";
    fs::create_directories(tmp);

    // Build heterogeneous multi-chunk stream under small StreamConfig to test:
    // CHUNK_REF (ID, NOT, REV, REV_NOT), LFSR, InterleaveNode, XorDiffNode, SliceNode, MorphNode, RepeatNode
    StreamConfig small_cfg{64, 16320, 16384, 16384, 16};
    std::mt19937_64 rng(99887766ULL);

    auto rand_bytes = [&](size_t nb) {
        std::vector<uint8_t> b(nb);
        for (size_t i = 0; i < nb; ++i) b[i] = static_cast<uint8_t>(rng() & 0xFFu);
        return b;
    };

    auto bA = rand_bytes(2048); // 16,384 bits (exact L_max chunk!)
    BitSeq cA = BitSeq::from_bytes_msb(bA.data(), bA.size());

    // Shifted + complemented intra-chunk repeat
    auto bM = rand_bytes(512); // 4,096 bits
    BitSeq motif = BitSeq::from_bytes_msb(bM.data(), bM.size());
    BitSeq shifted = BitSeq::concat({
        motif,
        BitSeq::from_bitstring("101"),
        motif.bitwise_not(),
        BitSeq::from_bitstring("11001"),
        motif
    }); // byte-aligned (4096*3 + 8 = 12,296 bits)

    // 32-bit counter table (16,384 bits)
    std::vector<uint8_t> tbl_bytes;
    for (uint32_t i = 0; i < 512; ++i) {
        tbl_bytes.push_back(0);
        tbl_bytes.push_back(0);
        tbl_bytes.push_back(static_cast<uint8_t>((i >> 8) & 0xFFu));
        tbl_bytes.push_back(static_cast<uint8_t>(i & 0xFFu));
    }
    BitSeq cTable = BitSeq::from_bytes_msb(tbl_bytes.data(), tbl_bytes.size());

    // LFSR degree 17 (16,384 bits)
    BitSeq cLfsr = evaluate_lfsr(17, (1ULL << 16) | (1ULL << 2), 0x12345ULL, 16384);

    // Perturbed XOR records (16 * 1024 = 16,384 bits)
    auto r0b = rand_bytes(128);
    BitSeq rec0 = BitSeq::from_bytes_msb(r0b.data(), r0b.size());
    std::vector<BitSeq> xrecs = {rec0};
    for (int k = 1; k < 16; ++k) {
        std::vector<uint64_t> dw(16, 0ULL);
        dw[static_cast<size_t>(k % 16)] = 1ULL << (k * 3);
        xrecs.push_back(rec0.bitwise_xor(BitSeq(dw, 1024)));
    }
    BitSeq cXor = BitSeq::concat(xrecs);

    BitSeq full_seq = BitSeq::concat({
        cA,
        cA.bitwise_not(),
        cA.reverse_bits(),
        cA.reverse_bits().bitwise_not(),
        shifted,
        cTable,
        cLfsr,
        cXor
    });
    REQUIRE((full_seq.bit_len() & 7ULL) == 0ULL);

    std::string p_t1 = (tmp / "out_t1.mapr").string();
    std::string p_t4 = (tmp / "out_t4.mapr").string();
    auto st1 = encode_bitseq_to_file(full_seq, p_t1, true, 1, small_cfg);
    auto st4 = encode_bitseq_to_file(full_seq, p_t4, true, 4, small_cfg);
    REQUIRE(st1.output_bytes == st4.output_bytes);
    REQUIRE(st1.chunk_ref_count >= 3);

    // Verify byte-for-byte identity between 1-thread and 4-thread encoding!
    auto read_all = [](const std::string& p) {
        std::ifstream f(p, std::ios::binary);
        return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    };
    REQUIRE(read_all(p_t1) == read_all(p_t4));

    // Inspect & verify 100% bit accountability
    auto irep = inspect_mapr_container(p_t1);
    REQUIRE(irep.summary.accounted_bits == full_seq.bit_len());

    // Test streaming file encoder vs in-memory encoder + fresh OS subprocess decode!
    std::string raw_in = (tmp / "raw.bin").string();
    std::string mapr_str = (tmp / "streamed.mapr").string();
    std::string raw_out = (tmp / "reconstructed.bin").string();
    {
        auto rb = full_seq.to_bytes_msb();
        std::ofstream f(raw_in, std::ios::binary);
        f.write(reinterpret_cast<const char*>(rb.data()), static_cast<std::streamsize>(rb.size()));
    }
    auto st_s = encode_raw_file_streaming(raw_in, mapr_str, 2);
    REQUIRE(st_s.input_bits == full_seq.bit_len());

    // Subprocess decode using standalone `./bin/mapr` if built
    if (fs::exists("./bin/mapr")) {
        std::string cmd = "./bin/mapr decode --input " + mapr_str + " --output " + raw_out + " --threads 2";
        int rc = std::system(cmd.c_str());
        REQUIRE(rc == 0);
        REQUIRE(read_all(raw_in) == read_all(raw_out));
    } else {
        auto dst = decode_mapr_to_raw_file(mapr_str, raw_out, 2);
        REQUIRE(dst.sha256_verified);
        REQUIRE(read_all(raw_in) == read_all(raw_out));
    }

    // Also test non-byte-aligned prime bit-length container roundtrip
    BitSeq prime_seq = full_seq.slice(5, 29173);
    std::string prime_mapr = (tmp / "prime.mapr").string();
    encode_bitseq_to_file(prime_seq, prime_mapr, false, 2, small_cfg);
    auto [dec_prime, dp_st] = decode_mapr_to_bitseq(prime_mapr, 2);
    REQUIRE(dp_st.sha256_verified);
    REQUIRE(dec_prime == prime_seq);

    fs::remove_all(tmp);
    std::cout << "  [PASS] Multi-chunk V4 CHUNK_REF, all 10 mechanisms, thread determinism (t1==t4), & streaming I/O\n";
}

void test_adversarial_and_fuzz_rejection() {
    namespace fs = std::filesystem;
    fs::path tmp = fs::temp_directory_path() / "mapr_fuzz_test";
    fs::create_directories(tmp);

    // 1. Direct static DAG validator negative cases
    {
        // Self-cycle in ConcatNode
        ExplicitChunkDAG bad{{AtomNode{DualBasisAtom{AtomBasis::POS, 8, 0, 0}}, ConcatNode{{0, 1}}}, 1};
        REQUIRE(!validate_chunk_dag(bad, 16).valid);
    }
    {
        // Invalid rho >= C(8, 2) = 28
        ExplicitChunkDAG bad{{AtomNode{DualBasisAtom{AtomBasis::POS, 8, 2, 28}}}, 0};
        REQUIRE(!validate_chunk_dag(bad, 8).valid);
    }
    {
        // Non-dyadic ZHEG
        ExplicitChunkDAG bad{{AtomNode{DualBasisAtom{AtomBasis::ZHEG, 7, 0, 0}}}, 0};
        REQUIRE(!validate_chunk_dag(bad, 7).valid);
    }
    {
        // Out-of-bounds SliceNode
        ExplicitChunkDAG bad{{AtomNode{DualBasisAtom{AtomBasis::POS, 8, 0, 0}}, SliceNode{0, 5, 4}}, 1};
        REQUIRE(!validate_chunk_dag(bad, 4).valid);
    }
    {
        // Mismatched XorDiffNode
        ExplicitChunkDAG bad{{
            AtomNode{DualBasisAtom{AtomBasis::POS, 8, 0, 0}},
            AtomNode{DualBasisAtom{AtomBasis::POS, 7, 0, 0}},
            XorDiffNode{0, 1}
        }, 2};
        REQUIRE(!validate_chunk_dag(bad, 8).valid);
    }

    // 2. Fuzz 500 random corruptions & truncations of a valid multi-chunk .mapr file
    StreamConfig scfg{64, 1024, 2048, 4096, 8};
    std::mt19937_64 rng(5551234ULL);
    std::vector<uint8_t> data(3000);
    for (auto& b : data) b = static_cast<uint8_t>(rng() & 0xFFu);
    BitSeq seq = BitSeq::from_bytes_msb(data.data(), data.size());

    std::string valid_path = (tmp / "valid.mapr").string();
    encode_bitseq_to_file(seq, valid_path, true, 2, scfg);

    std::vector<uint8_t> orig_bytes;
    {
        std::ifstream f(valid_path, std::ios::binary);
        orig_bytes.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    }

    std::string mut_path = (tmp / "mutated.mapr").string();
    int rejected = 0;
    for (int trial = 0; trial < 500; ++trial) {
        std::vector<uint8_t> mut = orig_bytes;
        if (trial < 50) {
            // Random truncation
            size_t new_len = static_cast<size_t>(rng() % orig_bytes.size());
            mut.resize(new_len);
        } else {
            // Flip 1 to 4 random bits anywhere in header, MCHK frames, INDX, or TRLR
            int flips = 1 + static_cast<int>(trial % 4);
            for (int f_i = 0; f_i < flips; ++f_i) {
                size_t pos = static_cast<size_t>(rng() % mut.size());
                uint8_t bit = static_cast<uint8_t>(1u << (rng() & 7ULL));
                mut[pos] ^= bit;
            }
        }
        if (mut == orig_bytes) continue;

        {
            std::ofstream f(mut_path, std::ios::binary | std::ios::trunc);
            f.write(reinterpret_cast<const char*>(mut.data()), static_cast<std::streamsize>(mut.size()));
        }
        bool threw = false;
        try {
            auto [dseq, dst] = decode_mapr_to_bitseq(mut_path, 1);
            (void)dseq; (void)dst;
        } catch (const std::exception&) {
            threw = true;
        }
        // Note: flipping an unused reserved flag bit 3..15 in the header STILL flips header_crc32,
        // so EVERY single non-identical byte/bit mutation MUST be caught by CRC-32 or SHA-256!
        REQUIRE(threw);
        ++rejected;
    }

    fs::remove_all(tmp);
    std::cout << "  [PASS] Adversarial DAG validator + " << rejected
              << "/500 corrupted/truncated .mapr fuzz cases cleanly rejected\n";
}

} // namespace

int main() {
    std::cout << "Running MAPR v1.0 C++20 Automated Test Suite...\n";
    test_crypto_vectors();
    test_tier1_algebra_and_combinatorics();
    test_exhaustive_131071_small_sequences();
    test_all_mechanisms_streaming_and_thread_determinism();
    test_adversarial_and_fuzz_rejection();
    std::cout << "ALL C++20 TESTS PASSED!\n";
    return 0;
}
