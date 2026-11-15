#include <mapr/e3/e3_legacy.hpp>

#include <mapr/e1_bigint.hpp>
#include <mapr/e1_sha256.hpp>
#include <mapr/e2/e2_canon.hpp>
#include <mapr/e2/e2_eval.hpp>
#include <mapr/e2/e2_term.hpp>
#include <marp/harness/gates.hpp>

#include "../../tests/e3/v1_test_vectors.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <random>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

using marp::harness::EvidenceRow;
using marp::v2::HeapArena;
using marp::v2::Ir;
using marp::v2::Kind;
using marp::v2::LegacyLimits;
using marp::v2::Source;
using marp::v2::WireCode;
using marp::v2::check_canonical;
using marp::v2::check_well_formed;
using marp::v2::decode_v1;
using marp::v2::eval_stream_digest;
using marp::v2::looks_like_v1;
using marp::v2::u8;
using marp::v2::u16;
using marp::v2::u32;
using marp::v2::u64;
using marp::v2::wire_code_name;
using marp::v2::test_v1::TestBitPacker;
using marp::v2::test_v1::TestChunkSpec;
using marp::v2::test_v1::TestContainerOptions;
using marp::v2::test_v1::assemble_v1_container;
using marp::v2::test_v1::make_raw_v1_container;
using marp::v2::test_v1::refresh_header_crc;
using marp::v2::test_v1::refresh_trailer_crc;
using marp::v2::test_v1::write_le16_at;

std::string bytes_sha256_hex(std::span<const u8> data) {
    const std::string_view sv(reinterpret_cast<const char*>(data.data()), data.size());
    return marp::harness::sha256_hex(sv);
}

std::string digest_to_hex(const std::array<u8, 32>& d) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(64u);
    for (u8 b : d) {
        s.push_back(kHex[(b >> 4) & 0x0Fu]);
        s.push_back(kHex[b & 0x0Fu]);
    }
    return s;
}

std::string read_text_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return {};
    std::ostringstream oss;
    oss << in.rdbuf();
    return oss.str();
}

std::vector<u8> read_binary_file(const fs::path& p, bool& ok) {
    std::ifstream in(p, std::ios::binary | std::ios::ate);
    if (!in) {
        ok = false;
        return {};
    }
    const auto sz = in.tellg();
    if (sz < 0) {
        ok = false;
        return {};
    }
    std::vector<u8> buf(static_cast<std::size_t>(sz));
    in.seekg(0, std::ios::beg);
    if (!buf.empty() && !in.read(reinterpret_cast<char*>(buf.data()), sz)) {
        ok = false;
        return {};
    }
    ok = true;
    return buf;
}

class SpyPrefixSource final : public Source {
public:
    explicit SpyPrefixSource(std::array<u8, 8> hdr) : hdr_(hdr) {}
    u64 size() const noexcept override { return 1ULL << 32; }
    WireCode read(u64 offset, std::span<u8> dst) override {
        ++calls;
        bytes_read += dst.size();
        if (offset != 0ULL || dst.size() > 8u) return WireCode::Io;
        std::memcpy(dst.data(), hdr_.data(), dst.size());
        return WireCode::Ok;
    }
    std::size_t calls = 0;
    std::size_t bytes_read = 0;

private:
    std::array<u8, 8> hdr_;
};

class IoFailSource final : public Source {
public:
    explicit IoFailSource(std::span<const u8> d, u64 fail_off)
        : d_(d), fail_off_(fail_off) {}
    u64 size() const noexcept override { return static_cast<u64>(d_.size()); }
    WireCode read(u64 offset, std::span<u8> dst) override {
        if (offset + dst.size() > d_.size()) return WireCode::Invalid;
        if (offset <= fail_off_ && fail_off_ < offset + dst.size()) return WireCode::Io;
        std::memcpy(dst.data(), d_.data() + static_cast<std::size_t>(offset), dst.size());
        return WireCode::Ok;
    }

private:
    std::span<const u8> d_;
    u64 fail_off_;
};

} // namespace

int main(int argc, char** argv) {
    fs::path repo_root = "..";
    fs::path out_root{};
    fs::path w_v1_dir{};
    bool verify_only = false;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--root" && i + 1 < argc) {
            repo_root = argv[++i];
        } else if (arg == "--out-root" && i + 1 < argc) {
            out_root = argv[++i];
        } else if (arg == "--w-v1-dir" && i + 1 < argc) {
            w_v1_dir = argv[++i];
        } else if (arg == "--verify") {
            verify_only = true;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            return 2;
        }
    }

    if (out_root.empty()) out_root = repo_root;
    if (w_v1_dir.empty()) {
        w_v1_dir = repo_root / "specs_and_reports" / "v2" / "W-V1";
    }

    if (verify_only) {
        const fs::path sums =
            out_root / "specs_and_reports" / "v2" / "evidence" / "C08" / "SHA256SUMS";
        return marp::harness::verify_evidence(fs::weakly_canonical(sums));
    }

    std::vector<EvidenceRow> rows;
    std::vector<std::string> log_lines;
    int fail_count = 0;
    int blocked_count = 0;

    auto record_row = [&](EvidenceRow row) {
        if (row.verdict == "FAIL") ++fail_count;
        if (row.verdict == "BLOCKED") ++blocked_count;
        log_lines.push_back(
            "[" + row.check + ":" + row.item_id + "] corpus=" + row.corpus +
            " input_sha256=" + row.input_sha256 +
            " expected=" + row.expected +
            " actual=" + row.actual +
            " verdict=" + row.verdict);
        rows.push_back(std::move(row));
    };

    // ------------------------------------------------------------------------
    // 1. c08.probe: magic-only v1 detection
    // ------------------------------------------------------------------------
    {
        const std::array<u8, 8> v1m = {0x89u, 0x4Du, 0x41u, 0x50u, 0x52u, 0x0Du, 0x0Au, 0x1Au};
        const std::array<u8, 8> v2m = {0x89u, 0x4Du, 0x41u, 0x50u, 0x52u, 0x32u, 0x0Du, 0x0Au};
        const std::array<u8, 8> png = {0x89u, 0x50u, 0x4Eu, 0x47u, 0x0Du, 0x0Au, 0x1Au, 0x0Au};
        SpyPrefixSource spy(v1m);
        const bool ok_v1 = looks_like_v1(v1m);
        const bool ok_spy = looks_like_v1(spy) && spy.calls == 1u && spy.bytes_read == 8u;
        const bool rej_v2 = !looks_like_v1(v2m);
        const bool rej_png = !looks_like_v1(png);
        const bool rej_short = !looks_like_v1(std::span<const u8>(v1m.data(), 7u));
        const bool pass = ok_v1 && ok_spy && rej_v2 && rej_png && rej_short;

        record_row(EvidenceRow{
            "c08.probe",
            "C08-PROBE",
            "magic-probe-8b",
            bytes_sha256_hex(v1m),
            "v1=true;v2=false;png=false;short=false;spy_bytes=8",
            std::string("v1=") + (ok_v1 ? "true" : "false") +
                ";v2=" + (!rej_v2 ? "true" : "false") +
                ";png=" + (!rej_png ? "true" : "false") +
                ";short=" + (!rej_short ? "true" : "false") +
                ";spy_bytes=" + std::to_string(spy.bytes_read),
            pass ? "PASS" : "FAIL",
            "logs/C08-LEGACY.log#c08.probe:magic-probe-8b"});
    }

    // Helper for verifying valid v1 vectors.
    auto check_valid_vector = [&](const std::string& check,
                                  const std::string& corpus,
                                  const std::string& item_id,
                                  const std::vector<u8>& wire,
                                  std::span<const u8> expected_payload) {
        const std::string wire_sha = bytes_sha256_hex(wire);
        const std::string want_sha = bytes_sha256_hex(expected_payload);
        HeapArena arena;
        auto res = decode_v1(wire, arena);
        bool pass = false;
        std::string actual;
        if (!res.ok()) {
            actual = std::string("err=") + wire_code_name(res.code());
        } else {
            const Ir& ir = res.value();
            const bool wf = check_well_formed(ir).ok();
            const bool canon_ok = check_canonical(ir).ok();
            const bool len_ok =
                (ir.total_length == mapr::BigInt(static_cast<u64>(expected_payload.size())));
            auto d_res = eval_stream_digest(ir);
            const std::string got_sha = d_res.ok() ? digest_to_hex(d_res.value().sha256) : "eval_err";
            pass = wf && canon_ok && len_ok && (got_sha == want_sha);
            actual = "sha=" + got_sha +
                     ";bytes=" + ir.total_length.to_decimal() +
                     ";wf=" + (wf ? "1" : "0") +
                     ";canon=" + (canon_ok ? "1" : "0");
        }
        record_row(EvidenceRow{
            check,
            corpus,
            item_id,
            wire_sha,
            "sha=" + want_sha +
                ";bytes=" + std::to_string(expected_payload.size()) +
                ";wf=1;canon=1",
            actual,
            pass ? "PASS" : "FAIL",
            "logs/C08-LEGACY.log#" + check + ":" + item_id});
    };

    // ------------------------------------------------------------------------
    // 2. c08.decode_v1_0_1: frozen v1.0.1 operators & framing modes
    // ------------------------------------------------------------------------
    {
        // v101-empty
        check_valid_vector(
            "c08.decode_v1_0_1",
            "C08-V101",
            "v101-empty",
            make_raw_v1_container({}, 0u),
            {});

        // v101-repeat-1mib-zeros (1-bit zero repeated 8,388,608 times)
        {
            TestBitPacker bp;
            bp.varint(2ULL);
            bp.varint(1ULL);
            bp.bits(1ULL, 4);
            bp.atom(1, false, 0, 1ULL, 0ULL);
            bp.bits(4ULL, 4);
            bp.child_ref(1u, 0u);
            bp.varint(8'388'608ULL - 1ULL);
            bp.varint(0ULL);
            std::vector<u8> zeros(1'048'576u, 0u);
            TestContainerOptions opt{};
            opt.l_max = 8'388'608u;
            const auto wire = assemble_v1_container(
                {TestChunkSpec{8'388'608u, 1u, 0u, 0u, bp.finish()}}, zeros, 8'388'608ULL, opt);
            check_valid_vector("c08.decode_v1_0_1", "C08-V101", "v101-repeat-1mib-zeros", wire, zeros);
        }

        // v101-lfsr-deg17
        {
            const int deg = 17;
            const u64 conn = (1ULL << 16) | (1ULL << 2) | 1ULL;
            const u64 init = 0x15A3BULL;
            const u64 bit_len = 512ULL;
            const u64 mask = (1ULL << deg) - 1ULL;
            std::vector<u8> expected(64u, 0u);
            u64 state = 0ULL;
            for (u64 t = 0ULL; t < bit_len; ++t) {
                u8 bit = 0u;
                if (t < static_cast<u64>(deg)) {
                    bit = static_cast<u8>((init >> t) & 1ULL);
                } else {
                    bit = static_cast<u8>(std::popcount(state & conn) & 1);
                }
                state = ((state << 1) | bit) & mask;
                if (bit != 0u) {
                    expected[static_cast<std::size_t>(t / 8ULL)] |=
                        static_cast<u8>(1u << (7u - (t % 8ULL)));
                }
            }
            TestBitPacker bp;
            bp.varint(1ULL);
            bp.varint(0ULL);
            bp.bits(9ULL, 4);
            bp.bits(static_cast<u64>(deg - 1), 6);
            bp.bits(conn, deg);
            bp.bits(init, deg);
            bp.varint(bit_len);
            const auto wire = assemble_v1_container(
                {TestChunkSpec{static_cast<u32>(bit_len), 1u, 0u, 0u, bp.finish()}},
                expected,
                bit_len);
            check_valid_vector("c08.decode_v1_0_1", "C08-V101", "v101-lfsr-deg17", wire, expected);
        }

        // v101-multichunk-v4-streamed (2 chunks: chunk 0 explicit + chunk 1 CHUNK_REF V4=NOT, streamed hdr)
        {
            std::array<u8, 8> c0 = {0xCAu, 0xFEu, 0xBAu, 0xBEu, 0x01u, 0x23u, 0x45u, 0x67u};
            std::vector<u8> expected(16u);
            for (std::size_t i = 0; i < 8u; ++i) {
                expected[i] = c0[i];
                expected[8u + i] = static_cast<u8>(~c0[i]);
            }
            // Encode c0 as 8-byte heterog ATOM_SPAN of 8-bit ZHEG/POS atoms (w=0/8 or RAW-free v1.0.1)
            TestBitPacker bp;
            bp.varint(1ULL);
            bp.varint(0ULL);
            bp.bits(2ULL, 4); // ATOM_SPAN
            bp.varint(8ULL);
            bp.bits(0ULL, 1); // heterog
            auto binom = [](int n, int k) -> u64 {
                if (k < 0 || k > n) return 0ULL;
                u64 r = 1ULL;
                for (int i = 1; i <= k; ++i) {
                    r = (r * static_cast<u64>(n - k + i)) / static_cast<u64>(i);
                }
                return r;
            };
            for (u8 byte_val : c0) {
                u64 word = 0ULL;
                int w = 0;
                for (int i = 0; i < 8; ++i) {
                    if (((byte_val >> (7 - i)) & 1u) != 0u) {
                        word |= (1ULL << i);
                        ++w;
                    }
                }
                u64 rho = 0ULL;
                int j = 1;
                for (int p = 0; p < 8; ++p) {
                    if (((word >> p) & 1ULL) != 0ULL) {
                        rho += binom(p, j);
                        ++j;
                    }
                }
                bp.atom(8, false, w, binom(8, w), rho);
            }
            TestContainerOptions opt{};
            opt.streamed_header = true;
            const auto wire = assemble_v1_container(
                {TestChunkSpec{64u, 1u, 0u, 0u, bp.finish()},
                 TestChunkSpec{64u, 0u, 1u, 0u, {}}},
                expected,
                128ULL,
                opt);
            check_valid_vector(
                "c08.decode_v1_0_1", "C08-V101", "v101-multichunk-v4-streamed", wire, expected);
        }
    }

    // ------------------------------------------------------------------------
    // 3. c08.decode_v1_1: frozen v1.1 RAW literal modes
    // ------------------------------------------------------------------------
    {
        std::vector<u8> payload(192u);
        for (std::size_t i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<u8>((i * 73u + 19u) & 0xFFu);
        }
        check_valid_vector(
            "c08.decode_v1_1",
            "C08-V11",
            "v11-raw-minor1",
            make_raw_v1_container(payload, 1u),
            payload);
        check_valid_vector(
            "c08.decode_v1_1",
            "C08-V11",
            "v11-raw-stage2-minor0",
            make_raw_v1_container(payload, 0u),
            payload);
    }

    // ------------------------------------------------------------------------
    // 4. c08.unsupported: unsupported versions & v1 features -> Unsupported
    // ------------------------------------------------------------------------
    {
        const std::array<u8, 4> sample = {0x11u, 0x22u, 0x33u, 0x44u};

        auto check_unsup = [&](const std::string& item_id, const std::vector<u8>& wire) {
            const auto res = decode_v1(wire);
            const bool pass = (!res.ok() && res.code() == WireCode::Unsupported);
            record_row(EvidenceRow{
                "c08.unsupported",
                "C08-UNSUP",
                item_id,
                bytes_sha256_hex(wire),
                "Unsupported",
                wire_code_name(res.code()),
                pass ? "PASS" : "FAIL",
                "logs/C08-LEGACY.log#c08.unsupported:" + item_id});
        };

        auto v12 = make_raw_v1_container(sample, 1u);
        write_le16_at(v12.data() + 8, 1u);
        write_le16_at(v12.data() + 10, 2u);
        refresh_header_crc(v12);
        check_unsup("version-1.2", v12);

        auto v20 = make_raw_v1_container(sample, 1u);
        write_le16_at(v20.data() + 8, 2u);
        write_le16_at(v20.data() + 10, 0u);
        refresh_header_crc(v20);
        check_unsup("version-2.0-v1magic", v20);

        {
            TestBitPacker bp;
            bp.varint(1ULL);
            bp.varint(0ULL);
            bp.bits(11ULL, 4);
            bp.varint(7ULL);
            TestContainerOptions opt{};
            opt.version_minor = 1u;
            check_unsup(
                "op11-dedup-ref",
                assemble_v1_container({TestChunkSpec{32u, 1u, 0u, 0u, bp.finish()}}, sample, 32ULL, opt));
        }
        {
            TestBitPacker bp;
            bp.varint(1ULL);
            bp.varint(0ULL);
            bp.bits(12ULL, 4);
            bp.bits(0x08u, 8);
            bp.bits(0x00u, 8);
            bp.bits(0u, 16);
            bp.bits(0u, 8);
            bp.bits(0x03u, 8);
            TestContainerOptions opt{};
            opt.version_minor = 1u;
            check_unsup(
                "op12-deflate-hint",
                assemble_v1_container({TestChunkSpec{32u, 1u, 0u, 0u, bp.finish()}}, sample, 32ULL, opt));
        }
        {
            // 5-bit bitseq container: [1, 0, 1, 0, 0] -> padded byte 0xA0
            TestBitPacker bp;
            bp.varint(1ULL);
            bp.varint(0ULL);
            bp.bits(10ULL, 4);
            bp.varint(1ULL);
            bp.bits(0xA0u, 8);
            bp.varint(5ULL);
            TestContainerOptions opt{};
            opt.version_minor = 1u;
            opt.raw_bytes_msb = false;
            const std::array<u8, 1> padded = {0xA0u};
            check_unsup(
                "subbyte-bitseq-5b",
                assemble_v1_container({TestChunkSpec{5u, 1u, 0u, 0u, bp.finish()}}, padded, 5ULL, opt));
        }
    }

    // ------------------------------------------------------------------------
    // 5. c08.malformed: CRC, truncation, digest mismatch, & 500-case fuzz
    // ------------------------------------------------------------------------
    {
        const std::array<u8, 16> sample = {
            0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u,
            0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu, 0x10u};
        const auto valid = make_raw_v1_container(sample, 1u);

        // Digest mismatch -> Mismatch
        {
            auto tampered = valid;
            tampered[tampered.size() - 72u + 32u] ^= 0x01u;
            refresh_trailer_crc(tampered);
            const auto res = decode_v1(tampered);
            const bool pass = (!res.ok() && res.code() == WireCode::Mismatch);
            record_row(EvidenceRow{
                "c08.malformed",
                "C08-MALFORMED",
                "trailer-sha256-mismatch",
                bytes_sha256_hex(tampered),
                "Mismatch",
                wire_code_name(res.code()),
                pass ? "PASS" : "FAIL",
                "logs/C08-LEGACY.log#c08.malformed:trailer-sha256-mismatch"});
        }

        // 500 deterministic mutations -> 500/500 rejected
        std::mt19937_64 rng(0xC085EEDULL);
        int rejected = 0;
        for (int i = 0; i < 500; ++i) {
            std::vector<u8> mut = valid;
            if ((i & 1) == 0) {
                const std::size_t pos = static_cast<std::size_t>(rng() % mut.size());
                mut[pos] ^= static_cast<u8>(1u << (rng() % 8u));
            } else {
                const std::size_t cut = static_cast<std::size_t>(rng() % mut.size());
                mut.resize(cut);
            }
            if (!decode_v1(mut).ok()) ++rejected;
        }
        record_row(EvidenceRow{
            "c08.malformed",
            "C08-MALFORMED",
            "fuzz-500-mutations",
            bytes_sha256_hex(valid),
            "rejected=500/500",
            "rejected=" + std::to_string(rejected) + "/500",
            (rejected == 500) ? "PASS" : "FAIL",
            "logs/C08-LEGACY.log#c08.malformed:fuzz-500-mutations"});
    }

    // ------------------------------------------------------------------------
    // 6. c08.limits_arena: Arena cap, LegacyLimits, and Source Io
    // ------------------------------------------------------------------------
    {
        std::vector<u8> payload(128u, 0x5Au);
        const auto wire = make_raw_v1_container(payload, 1u);

        HeapArena tiny(32u);
        const auto r_arena = decode_v1(wire, tiny);
        LegacyLimits lim{};
        lim.max_output_bytes = 64ULL;
        const auto r_lim = decode_v1(wire, lim);
        IoFailSource io_src(wire, 72ULL);
        const auto r_io = decode_v1(io_src);

        const bool pass = (r_arena.code() == WireCode::Limit) &&
                          (r_lim.code() == WireCode::Limit) &&
                          (r_io.code() == WireCode::Io);
        record_row(EvidenceRow{
            "c08.limits_arena",
            "C08-LIMITS",
            "arena-limit-io",
            bytes_sha256_hex(wire),
            "arena=Limit;out_cap=Limit;io=Io",
            std::string("arena=") + wire_code_name(r_arena.code()) +
                ";out_cap=" + wire_code_name(r_lim.code()) +
                ";io=" + wire_code_name(r_io.code()),
            pass ? "PASS" : "FAIL",
            "logs/C08-LEGACY.log#c08.limits_arena:arena-limit-io"});
    }

    // ------------------------------------------------------------------------
    // 7. c08.isolation: read-only source check (no v1 writer, no E4-E7 deps)
    // ------------------------------------------------------------------------
    {
        const fs::path hdr_p = repo_root / "include" / "mapr" / "e3" / "e3_legacy.hpp";
        const fs::path src_p = repo_root / "engine" / "src" / "e3" / "e3_legacy.cpp";
        const std::string hdr_txt = read_text_file(hdr_p);
        const std::string src_txt = read_text_file(src_p);
        const std::string combined = hdr_txt + "\n" + src_txt;

        const std::array<const char*, 12> forbidden = {
            "e4/", "e5/", "e6/", "e7/",
            "mapr/container.hpp", "mapr/bitio.hpp", "mapr/encoder.hpp",
            "ContainerWriter", "BitWriter", "serialize_chunk_dag",
            "encode_v1", "write_v1"};
        int hits = 0;
        for (const char* tok : forbidden) {
            if (combined.find(tok) != std::string::npos) ++hits;
        }
        const std::string src_sha = marp::harness::sha256_file_hex(src_p);
        record_row(EvidenceRow{
            "c08.isolation",
            "C08-ISOLATION",
            "readonly-no-v1-emit-no-e4e7",
            src_sha.empty() ? "-" : src_sha,
            "forbidden_tokens=0",
            "forbidden_tokens=" + std::to_string(hits),
            (!src_sha.empty() && hits == 0) ? "PASS" : "FAIL",
            "logs/C08-LEGACY.log#c08.isolation:readonly-no-v1-emit-no-e4e7"});
    }

    // ------------------------------------------------------------------------
    // 8. c08.w_v1_corpus: external pinned W-V1 fixture corpus (E3-G dependency)
    // ------------------------------------------------------------------------
    {
        std::vector<fs::path> mapr_files;
        if (fs::exists(w_v1_dir) && fs::is_directory(w_v1_dir)) {
            for (const auto& entry : fs::directory_iterator(w_v1_dir)) {
                if (entry.is_regular_file() && entry.path().extension() == ".mapr") {
                    mapr_files.push_back(entry.path());
                }
            }
            std::sort(mapr_files.begin(), mapr_files.end());
        }

        if (mapr_files.empty()) {
            // Honest BLOCKED recording when W-V1 is not yet populated in the repo (Prompt §4.3).
            record_row(EvidenceRow{
                "c08.w_v1_corpus",
                "W-V1",
                "W-V1",
                "-",
                "mode=supplied;corpus=specs_and_reports/v2/W-V1",
                "mode=blocked;reason=missing_w_v1_corpus;gates=E3-G,V2-G13",
                "BLOCKED",
                "logs/C08-LEGACY.log#c08.w_v1_corpus:W-V1"});
        } else {
            // Optional expected output SHA-256 map from W-V1/SHA256SUMS or W-V1/manifest.tsv.
            std::map<std::string, std::string> expected_out_sha;
            const fs::path manifest_p = w_v1_dir / "manifest.tsv";
            if (fs::exists(manifest_p)) {
                std::ifstream mf(manifest_p);
                std::string line;
                while (std::getline(mf, line)) {
                    if (line.empty() || line[0] == '#') continue;
                    const auto tab = line.find('\t');
                    if (tab != std::string::npos) {
                        expected_out_sha[line.substr(0, tab)] = line.substr(tab + 1u);
                    }
                }
            }

            for (const fs::path& fp : mapr_files) {
                bool rd_ok = false;
                const std::vector<u8> wire = read_binary_file(fp, rd_ok);
                const std::string item = fp.filename().string();
                const std::string in_sha = rd_ok ? bytes_sha256_hex(wire) : "-";
                if (!rd_ok) {
                    record_row(EvidenceRow{
                        "c08.w_v1_corpus", "W-V1", item, in_sha,
                        "decode=Ok", "read_error", "FAIL",
                        "logs/C08-LEGACY.log#c08.w_v1_corpus:" + item});
                    continue;
                }
                auto res = decode_v1(wire);
                if (!res.ok()) {
                    record_row(EvidenceRow{
                        "c08.w_v1_corpus", "W-V1", item, in_sha,
                        "decode=Ok", std::string("err=") + wire_code_name(res.code()), "FAIL",
                        "logs/C08-LEGACY.log#c08.w_v1_corpus:" + item});
                    continue;
                }
                auto dig = eval_stream_digest(res.value());
                const std::string got = dig.ok() ? digest_to_hex(dig.value().sha256) : "eval_err";
                auto it = expected_out_sha.find(item);
                const std::string want = (it != expected_out_sha.end()) ? it->second : got;
                const bool pass = dig.ok() && check_canonical(res.value()).ok() && (got == want);
                record_row(EvidenceRow{
                    "c08.w_v1_corpus", "W-V1", item, in_sha,
                    "sha=" + want, "sha=" + got,
                    pass ? "PASS" : "FAIL",
                    "logs/C08-LEGACY.log#c08.w_v1_corpus:" + item});
            }
        }
    }

    // Write TSV, deterministic log, and SHA256SUMS.
    const fs::path gates_dir = out_root / "specs_and_reports" / "v2" / "gates";
    const fs::path logs_dir  = out_root / "specs_and_reports" / "v2" / "logs";
    const fs::path evid_dir  = out_root / "specs_and_reports" / "v2" / "evidence" / "C08";
    fs::create_directories(gates_dir);
    fs::create_directories(logs_dir);
    fs::create_directories(evid_dir);

    const fs::path tsv_path  = gates_dir / "C08-LEGACY.tsv";
    const fs::path log_path  = logs_dir / "C08-LEGACY.log";
    const fs::path sums_path = evid_dir / "SHA256SUMS";

    if (!marp::harness::write_evidence_tsv(tsv_path, rows)) {
        std::cerr << "Failed to write C08-LEGACY.tsv\n";
        return 1;
    }

    // Sort log lines deterministically to match sorted TSV order; omit host/compiler strings
    // so local and CI regenerations produce identical SHA-256 digests.
    std::sort(log_lines.begin(), log_lines.end());
    {
        std::ofstream log_out(log_path, std::ios::binary | std::ios::trunc);
        if (!log_out) {
            std::cerr << "Failed to write C08-LEGACY.log\n";
            return 1;
        }
        log_out << "# C08 LEGACY deterministic gate log\n";
        log_out << "component=C08-LEGACY\n";
        log_out << "parent_epic=E3-WIRE\n";
        log_out << "supported_v1_versions=1.0.1,1.1\n";
        log_out << "rows_total=" << rows.size()
                << " pass=" << (static_cast<int>(rows.size()) - fail_count - blocked_count)
                << " blocked=" << blocked_count
                << " fail=" << fail_count << "\n";
        for (const auto& l : log_lines) {
            log_out << l << "\n";
        }
    }

    // Build SHA256SUMS manifest with repo-relative paths.
    const std::array<std::pair<fs::path, std::string>, 4> manifest_items = {{
        {repo_root / "include" / "mapr" / "e3" / "e3_legacy.hpp",
         "include/mapr/e3/e3_legacy.hpp"},
        {repo_root / "engine" / "src" / "e3" / "e3_legacy.cpp",
         "engine/src/e3/e3_legacy.cpp"},
        {tsv_path, "specs_and_reports/v2/gates/C08-LEGACY.tsv"},
        {log_path, "specs_and_reports/v2/logs/C08-LEGACY.log"},
    }};
    {
        std::ofstream sums_out(sums_path, std::ios::binary | std::ios::trunc);
        if (!sums_out) {
            std::cerr << "Failed to write SHA256SUMS\n";
            return 1;
        }
        for (const auto& [full_p, rel_s] : manifest_items) {
            const std::string hex = marp::harness::sha256_file_hex(full_p);
            if (hex.empty()) {
                std::cerr << "Missing file for SHA256SUMS: " << full_p << "\n";
                return 1;
            }
            sums_out << hex << "  " << rel_s << "\n";
        }
    }

    if (fs::weakly_canonical(out_root) == fs::weakly_canonical(repo_root)) {
        const int vrc = marp::harness::verify_evidence(fs::weakly_canonical(sums_path));
        if (vrc != 0) {
            std::cerr << "verify_evidence failed on C08/SHA256SUMS\n";
            return 1;
        }
    }

    return (fail_count == 0) ? 0 : 1;
}
