#include "marp/harness/e1_gate.hpp"
#include "marp/harness/gates.hpp"
#include "marp/harness/e1_terms.hpp"
#include <mapr/e1_bigint.hpp>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace marp::harness {

namespace {

namespace fs = std::filesystem;
using mapr::BigInt;

constexpr char kHex[] = "0123456789abcdef";

// The A-BITS set from SPECS §12.3.
constexpr std::array<int, 26> kBitLengths = {
    0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65,
    127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025
};

std::string hex_bytes(const std::vector<uint8_t>& bytes) {
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes) {
        out.push_back(kHex[byte >> 4]);
        out.push_back(kHex[byte & 0x0Fu]);
    }
    return out;
}

std::string hex_u64(uint64_t value) {
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i) {
        out[static_cast<size_t>(i)] = kHex[value & 0x0Fu];
        value >>= 4;
    }
    return out;
}

// Deterministic replacement for std::uniform_int_distribution. mt19937_64
// itself is standardised, so `rng() % span` is identical across libstdc++
// versions.
uint64_t pick(std::mt19937_64& rng, uint64_t lo, uint64_t hi) {
    if (hi <= lo) return lo;
    const uint64_t span = hi - lo + 1;
    return lo + rng() % span;
}

std::string padded_index(size_t index, int width) {
    std::ostringstream oss;
    oss << std::setw(width) << std::setfill('0') << index;
    return oss.str();
}

BigInt pow2(size_t bits) {
    auto result = BigInt(1).shl(bits);
    return result.ok() ? result.value() : BigInt(0);
}

BigInt all_ones(int bits) {
    if (bits <= 0) return BigInt(0);
    auto result = pow2(static_cast<size_t>(bits)).sub(BigInt(1));
    return result.ok() ? result.value() : BigInt(0);
}

BigInt random_exact_bits(int bits, std::mt19937_64& rng) {
    if (bits <= 0) return BigInt(0);
    const size_t nbytes = (static_cast<size_t>(bits) + 7u) / 8u;
    std::vector<uint8_t> bytes(nbytes, 0);
    for (size_t i = 0; i < nbytes; ++i) {
        bytes[i] = static_cast<uint8_t>(rng() & 0xFFu);
    }
    const int rem = bits % 8;
    if (rem != 0) {
        bytes.back() &= static_cast<uint8_t>((1u << rem) - 1u);
    }
    const size_t top_byte = static_cast<size_t>(bits - 1) / 8u;
    const int top_bit = (bits - 1) % 8;
    bytes[top_byte] |= static_cast<uint8_t>(1u << top_bit);

    const std::string_view view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    auto result = BigInt::from_le_bytes(view);
    return result.ok() ? result.value() : BigInt(0);
}

std::vector<uint8_t> trim_le(const std::vector<uint8_t>& bytes) {
    std::vector<uint8_t> out = bytes;
    while (!out.empty() && out.back() == 0) out.pop_back();
    return out;
}

int bit_length_from_le(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return 0;
    uint8_t top = bytes.back();
    int bits = static_cast<int>((bytes.size() - 1) * 8);
    while (top != 0) {
        top = static_cast<uint8_t>(top >> 1);
        ++bits;
    }
    return bits;
}

BigInt make_edge_value(size_t index) {
    const BigInt p32 = pow2(32);
    const BigInt p64 = pow2(64);
    const BigInt p128 = pow2(128);
    switch (index) {
        case 0: return BigInt(0);
        case 1: return BigInt(1);
        case 2: return BigInt(2);
        case 3: return p32.sub(BigInt(1)).value();
        case 4: return p32;
        case 5: return p32.add(BigInt(1)).value();
        case 6: return p64.sub(BigInt(1)).value();
        case 7: return p64;
        case 8: return p64.add(BigInt(1)).value();
        case 9: return p128.sub(BigInt(1)).value();
        case 10: return p128;
        default: return p128.add(BigInt(1)).value();
    }
}

const std::array<const char*, 12>& edge_names() {
    static const std::array<const char*, 12> names = {
        "0", "1", "2", "2^32-1", "2^32", "2^32+1",
        "2^64-1", "2^64", "2^64+1", "2^128-1", "2^128", "2^128+1"
    };
    return names;
}

} // namespace

std::vector<std::string> e1_kat_messages() {
    return {
        "",
        "abc",
        std::string(static_cast<size_t>(55), 'a'),
        std::string(static_cast<size_t>(56), 'a'),
        std::string(static_cast<size_t>(57), 'a'),
        std::string(static_cast<size_t>(63), 'a'),
        std::string(static_cast<size_t>(64), 'a'),
        std::string(static_cast<size_t>(65), 'a'),
        std::string(static_cast<size_t>(127), 'a'),
        std::string(static_cast<size_t>(128), 'a'),
        "The quick brown fox jumps over the lazy dog",
        std::string(static_cast<size_t>(1024) * 1024, 'x')
    };
}

E1Corpus build_e1_corpus() {
    E1Corpus corpus;

    auto add_item = [&corpus](const std::string& corpus_id,
                              const std::string& item_id,
                              const std::string& description,
                              int bit_length,
                              uint64_t seed) {
        CorpusItem item;
        item.corpus_id = corpus_id;
        item.item_id = item_id;
        item.description = description;
        item.description_sha256 = sha256_hex(description);
        item.seed = seed;
        item.bit_length = bit_length;
        corpus.items.push_back(std::move(item));
    };

    // A-EDGE: twelve boundary values.
    for (size_t i = 0; i < edge_names().size(); ++i) {
        const BigInt value = make_edge_value(i);
        corpus.a_edge.push_back(value);
        const std::string description =
            std::string("edge:") + edge_names()[i] + "=" + value.to_decimal();
        add_item("A-EDGE", padded_index(i, 3), description, value.bit_length(),
                 E1_CORPUS_SEED);
    }

    // A-BITS: one all-ones value at every required bit length.
    for (size_t i = 0; i < kBitLengths.size(); ++i) {
        const int bits = kBitLengths[i];
        const BigInt value = all_ones(bits);
        corpus.a_bits.push_back(value);
        const std::string description =
            "bits:" + std::to_string(bits) + "=" + value.to_decimal();
        add_item("A-BITS", padded_index(i, 3), description, bits, E1_CORPUS_SEED);
    }

    // A-RAND: eight values of exactly each required bit length.
    std::mt19937_64 rand_rng(E1_CORPUS_SEED ^ 0x52414E44ull); // "RAND"
    size_t rand_index = 0;
    for (const int bits : kBitLengths) {
        for (int r = 0; r < 8; ++r) {
            const BigInt value = random_exact_bits(bits, rand_rng);
            corpus.a_rand.push_back(value);
            const std::string description =
                "rand:" + std::to_string(bits) + ":" + std::to_string(r) +
                "=" + value.to_decimal();
            add_item("A-RAND", padded_index(rand_index, 3), description,
                     value.bit_length(), E1_CORPUS_SEED);
            ++rand_index;
        }
    }

    // A-ARITH: seeded ordered pairs drawn from A-EDGE ∪ A-BITS ∪ A-RAND.
    std::vector<BigInt> pool;
    pool.reserve(corpus.a_edge.size() + corpus.a_bits.size() + corpus.a_rand.size());
    for (const BigInt& value : corpus.a_edge) pool.push_back(value);
    for (const BigInt& value : corpus.a_bits) pool.push_back(value);
    for (const BigInt& value : corpus.a_rand) pool.push_back(value);

    std::mt19937_64 pair_rng(E1_CORPUS_SEED ^ 0x41524954ull); // "ARIT"
    corpus.a_arith.reserve(E1_ARITH_PAIRS);
    for (size_t i = 0; i < E1_ARITH_PAIRS; ++i) {
        const size_t ia = static_cast<size_t>(
            pick(pair_rng, 0, static_cast<uint64_t>(pool.size() - 1)));
        const size_t ib = static_cast<size_t>(
            pick(pair_rng, 0, static_cast<uint64_t>(pool.size() - 1)));
        const BigInt& a = pool[ia];
        const BigInt& b = pool[ib];
        corpus.a_arith.emplace_back(a, b);
        const std::string description = "arith:" + a.to_decimal() + "+" + b.to_decimal();
        add_item("A-ARITH", padded_index(i, 5), description,
                 std::max(a.bit_length(), b.bit_length()), E1_CORPUS_SEED);
    }

    // S-DEC: canonical decimal strings of A-EDGE ∪ A-BITS.
    for (size_t i = 0; i < corpus.a_edge.size(); ++i) {
        corpus.s_dec.push_back(corpus.a_edge[i].to_decimal());
    }
    for (size_t i = 0; i < corpus.a_bits.size(); ++i) {
        corpus.s_dec.push_back(corpus.a_bits[i].to_decimal());
    }
    for (size_t i = 0; i < corpus.s_dec.size(); ++i) {
        const std::string& text = corpus.s_dec[i];
        add_item("S-DEC", padded_index(i, 3), "dec:" + text,
                 static_cast<int>(text.size()) * 4, E1_CORPUS_SEED);
    }

    // S-BYTES: 256 magnitudes, each in a canonical and a zero-extended form.
    std::mt19937_64 bytes_rng(E1_CORPUS_SEED ^ 0x42595445ull); // "BYTE"
    size_t bytes_index = 0;
    auto add_bytes = [&](const std::vector<uint8_t>& raw) {
        E1Corpus::BytesItem item;
        item.raw = raw;
        item.trimmed = trim_le(raw);
        item.item_id = padded_index(bytes_index, 4);
        item.description = "le:" + hex_bytes(raw);
        item.description_sha256 = sha256_hex(item.description);
        item.bit_length = bit_length_from_le(item.trimmed);
        add_item("S-BYTES", item.item_id, item.description, item.bit_length,
                 E1_CORPUS_SEED);
        corpus.s_bytes.push_back(std::move(item));
        ++bytes_index;
    };

    add_bytes(std::vector<uint8_t>{0x00});
    add_bytes(std::vector<uint8_t>{0x00, 0x00, 0x00});
    for (int j = 0; j < 255; ++j) {
        const size_t len = static_cast<size_t>(pick(bytes_rng, 1, 40));
        std::vector<uint8_t> base(len, 0);
        for (size_t k = 0; k < len; ++k) {
            base[k] = static_cast<uint8_t>(bytes_rng() & 0xFFu);
        }
        base.back() |= 0x01u;
        add_bytes(base);

        std::vector<uint8_t> extended = base;
        const size_t extra = static_cast<size_t>(pick(bytes_rng, 1, 4));
        extended.insert(extended.end(), extra, 0);
        add_bytes(extended);
    }

    // T-LEN: 2,000 well-formed terms covering every NodeKind, depth 1–4.
    const uint64_t term_seed = E1_CORPUS_SEED ^ 0x544C454Eull; // "TLEN"
    corpus.t_len = build_terms(term_seed, E1_TERM_COUNT);
    for (size_t i = 0; i < corpus.t_len.size(); ++i) {
        const std::string fingerprint = term_fingerprint(corpus.t_len[i]);
        const uint64_t root_length =
            corpus.t_len[i].nodes.empty() ? 0 : corpus.t_len[i].nodes.back().generation_length;
        const int reported = static_cast<int>(
            std::min<uint64_t>(root_length, static_cast<uint64_t>(0x7FFFFFFFull)));
        add_item("T-LEN", padded_index(i, 4), "term:" + fingerprint, reported, term_seed);
    }

    // D-KAT: 12 messages × 2 digest families = 24 items.
    corpus.kat_messages = e1_kat_messages();
    for (size_t m = 0; m < corpus.kat_messages.size(); ++m) {
        const size_t bytes = corpus.kat_messages[m].size();
        const int bits = static_cast<int>(std::min<size_t>(bytes, 0x0FFFFFFFull)) * 8;
        add_item("D-KAT", "crc-" + padded_index(m, 3),
                 "crc32:msg" + std::to_string(m), bits, E1_CORPUS_SEED);
        add_item("D-KAT", "sha-" + padded_index(m, 3),
                 "sha256:msg" + std::to_string(m), bits, E1_CORPUS_SEED);
    }

    return corpus;
}

bool write_corpus(const E1Corpus& corpus, const fs::path& path) {
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    if (ec) return false;

    fs::path temp = path;
    temp += ".tmp";

    {
        std::ofstream ofs(temp, std::ios::trunc);
        if (!ofs) return false;
        ofs << "corpus_id\titem_id\tdescription\tbit_length\t"
               "description_sha256\tseed\n";
        for (const CorpusItem& item : corpus.items) {
            ofs << item.corpus_id << '\t'
                << item.item_id << '\t'
                << item.description << '\t'
                << item.bit_length << '\t'
                << item.description_sha256 << '\t'
                << item.seed << '\n';
            if (!ofs) return false;
        }
        ofs.flush();
        if (!ofs) return false;
    }

    fs::rename(temp, path, ec);
    if (ec) {
        fs::remove(temp, ec);
        return false;
    }
    return true;
}

std::vector<CorpusItem> read_corpus(const fs::path& path) {
    std::vector<CorpusItem> items;
    std::ifstream ifs(path);
    if (!ifs) return items;

    std::string line;
    std::getline(ifs, line); // header
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        std::istringstream iss(line);
        CorpusItem item;
        std::string bit_text;
        std::string seed_text;
        std::getline(iss, item.corpus_id, '\t');
        std::getline(iss, item.item_id, '\t');
        std::getline(iss, item.description, '\t');
        std::getline(iss, bit_text, '\t');
        std::getline(iss, item.description_sha256, '\t');
        std::getline(iss, seed_text);
        item.bit_length = static_cast<int>(std::strtol(bit_text.c_str(), nullptr, 10));
        item.seed = std::strtoull(seed_text.c_str(), nullptr, 10);
        item.parse_ok = !item.corpus_id.empty() && !item.item_id.empty();
        if (item.parse_ok) items.push_back(std::move(item));
    }
    return items;
}

} // namespace marp::harness
