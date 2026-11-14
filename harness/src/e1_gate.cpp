// E1-G gate measurement and evidence writer.
//
// Every row is produced by running the E1 surface against the independent
// base-10^9 oracle (or against pinned KAT vectors). Nothing is copied from a
// fixture file and no value is typed in by hand except the published digest
// constants below.

#include "marp/harness/e1_gate.hpp"
#include "marp/harness/gates.hpp"
#include "marp/harness/e1_oracle.hpp"
#include "marp/harness/e1_terms.hpp"
#include <mapr/e1_bigint.hpp>
#include <mapr/e1_crc32.hpp>
#include <mapr/e1_gear.hpp>
#include <mapr/e1_length.hpp>
#include <mapr/e1_sha256.hpp>
#include <mapr/e1_types.hpp>
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace marp::harness {

namespace {

namespace fs = std::filesystem;
using mapr::BigInt;
using OracleBigInt = oracle::BigInt;

constexpr char kHex[] = "0123456789abcdef";

// Published SHA-256 / CRC-32 values for e1_kat_messages(), in order:
// empty, "abc", 55/56/57/63/64/65/127/128 'a', quick-brown-fox, 1 MiB 'x'.
constexpr std::array<const char*, 12> kSha256Kat = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
    "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
    "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6",
    "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
    "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
    "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
    "c57e9278af78fa3cab38667bef4ce29d783787a2f731d4e12200270f0c32320a",
    "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e",
    "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
    "8f990ba0b577b51cf009ea049368c16bbda1b21e1b93be07a824758bb253c39b",
};

constexpr std::array<const char*, 12> kCrc32Kat = {
    "00000000", "352441c2", "aadfe34e", "79790d37", "50736241", "6824c5de",
    "89b46555", "f33faf5d", "f0bebe96", "f12b368c", "414fa339", "153b9c32",
};

struct ItemResult {
    bool pass = true;
    bool counted = true;
    std::string detail;
};

template <typename T, typename Fn>
std::vector<T> parallel_map(size_t count, int threads, Fn fn) {
    std::vector<T> out(count);
    if (count == 0) return out;

    std::atomic<size_t> next{0};
    auto worker = [&]() {
        for (;;) {
            const size_t i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= count) return;
            out[i] = fn(i);
        }
    };

    const int workers = std::max(1, threads);
    std::vector<std::thread> pool;
    pool.reserve(static_cast<size_t>(workers - 1));
    for (int w = 1; w < workers; ++w) pool.emplace_back(worker);
    worker();
    for (auto& th : pool) th.join();
    return out;
}

std::string hex_bytes(const std::vector<uint8_t>& bytes) {
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes) {
        out.push_back(kHex[byte >> 4]);
        out.push_back(kHex[byte & 0x0Fu]);
    }
    return out;
}


std::string_view bytes_view(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return {};
    return std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::string sha256_hex_bytes(const std::vector<uint8_t>& data) {
    return sha256_hex(bytes_view(data));
}

std::string crc32_hex(uint32_t value) {
    std::string out(8, '0');
    for (int i = 7; i >= 0; --i) {
        out[static_cast<size_t>(i)] = kHex[value & 0x0Fu];
        value >>= 4;
    }
    return out;
}

bool to_oracle(const BigInt& value, OracleBigInt& out) {
    auto parsed = oracle::from_decimal(value.to_decimal());
    if (!parsed) return false;
    out = std::move(*parsed);
    return true;
}

bool matches_oracle(const BigInt& value, const OracleBigInt& expected) {
    return value.to_decimal() == oracle::to_decimal(expected);
}

std::string join_limbs(const std::vector<BigInt>& values) {
    std::string out;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i != 0) out.push_back(',');
        out += values[i].to_decimal();
    }
    return out;
}

std::string join_oracle(const std::vector<OracleBigInt>& values) {
    std::string out;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i != 0) out.push_back(',');
        out += oracle::to_decimal(values[i]);
    }
    return out;
}

EvidenceRow make_row(const std::string& check, const std::string& corpus,
                     const std::string& item, const std::string& input_sha,
                     const std::string& expected, const std::string& actual,
                     bool pass) {
    EvidenceRow row;
    row.check = check;
    row.corpus = corpus;
    row.item_id = item;
    row.input_sha256 = input_sha;
    row.expected = expected;
    row.actual = actual;
    row.verdict = pass ? "PASS" : "FAIL";
    row.log = "logs/E1-G.log#" + check + "/" + item;
    return row;
}

EvidenceRow make_blocked_row(const std::string& check, const std::string& corpus,
                             const std::string& item, const std::string& expected,
                             const std::string& actual) {
    EvidenceRow row;
    row.check = check;
    row.corpus = corpus;
    row.item_id = item;
    row.input_sha256 = sha256_hex(check + "\n" + corpus + "\n" + item);
    row.expected = expected;
    row.actual = actual;
    row.verdict = "BLOCKED";
    row.log = "logs/E1-G.log#" + check;
    return row;
}

std::string serialize_rows(const std::vector<EvidenceRow>& rows) {
    std::string out;
    for (const auto& row : rows) {
        out += row.check;
        out += '\t';
        out += row.corpus;
        out += '\t';
        out += row.item_id;
        out += '\t';
        out += row.input_sha256;
        out += '\t';
        out += row.expected;
        out += '\t';
        out += row.actual;
        out += '\t';
        out += row.verdict;
        out += '\t';
        out += row.log;
        out += '\n';
    }
    return out;
}

std::string serialize_corpus(const E1Corpus& corpus) {
    std::string out;
    for (const auto& item : corpus.items) {
        out += item.corpus_id;
        out += '\t';
        out += item.item_id;
        out += '\t';
        out += item.description;
        out += '\t';
        out += std::to_string(item.bit_length);
        out += '\t';
        out += item.description_sha256;
        out += '\t';
        out += std::to_string(item.seed);
        out += '\n';
    }
    return out;
}

std::string padded(size_t value, int width) {
    std::ostringstream oss;
    oss << std::setw(width) << std::setfill('0') << value;
    return oss.str();
}

// Split points for incremental digest checks. Messages up to 4 KiB are tested
// at every split point. The 1 MiB message uses the bounded policy permitted by
// SPECS §12.4: all 0..128, all n-128..n, every 4096th byte, plus 1024 seeded
// splits. The two sets are deduplicated by sorting.
std::vector<size_t> policy_splits(size_t n, uint64_t seed) {
    std::vector<size_t> splits;
    if (n <= 4096) {
        splits.reserve(n + 1);
        for (size_t i = 0; i <= n; ++i) splits.push_back(i);
        return splits;
    }

    const size_t edge = 128;
    for (size_t i = 0; i <= edge && i <= n; ++i) splits.push_back(i);
    const size_t first_tail = n > edge ? n - edge : 0;
    for (size_t i = first_tail; i <= n; ++i) splits.push_back(i);
    for (size_t i = 0; i <= n; i += 4096) splits.push_back(i);

    std::mt19937_64 rng(seed);
    for (int i = 0; i < 1024; ++i) {
        const uint64_t span = static_cast<uint64_t>(n);
        splits.push_back(static_cast<size_t>(rng() % (span + 1)));
    }
    std::sort(splits.begin(), splits.end());
    splits.erase(std::unique(splits.begin(), splits.end()), splits.end());
    return splits;
}

void append_failure(std::vector<std::string>& failures, const std::string& detail) {
    if (failures.size() < 32) failures.push_back(detail);
}

void add_aggregate(std::vector<EvidenceRow>& rows, std::vector<std::string>& log,
                   const std::string& check, const std::string& corpus,
                   size_t total, size_t passed,
                   const std::vector<std::string>& failures) {
    const bool ok = total > 0 && passed == total;
    rows.push_back(make_row(check, corpus, "all", sha256_hex(check + "\n" + corpus),
                            std::to_string(total), std::to_string(passed), ok));
    for (const auto& failure : failures) log.push_back(check + ": " + failure);
    log.push_back(check + ": total=" + std::to_string(total) +
                  " passed=" + std::to_string(passed) + (ok ? " PASS" : " FAIL"));
}

void check_arith_add(const E1Corpus& corpus, int threads,
                     std::vector<EvidenceRow>& rows, std::vector<std::string>& log) {
    const auto results = parallel_map<ItemResult>(
        corpus.a_arith.size(), threads, [&](size_t i) {
            ItemResult result;
            const BigInt& a = corpus.a_arith[i].first;
            const BigInt& b = corpus.a_arith[i].second;
            OracleBigInt oa;
            OracleBigInt ob;
            if (!to_oracle(a, oa) || !to_oracle(b, ob)) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " oracle conversion failed";
                return result;
            }
            auto sum = a.add(b);
            if (!sum.ok()) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " add returned error";
                return result;
            }
            const std::string expected = oracle::to_decimal(oracle::add(oa, ob));
            if (sum.value().to_decimal() != expected) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " add " +
                                a.to_decimal() + "+" + b.to_decimal() + " expected " +
                                expected + " actual " + sum.value().to_decimal();
            }
            return result;
        });

    size_t total = 0;
    size_t passed = 0;
    std::vector<std::string> failures;
    for (const auto& result : results) {
        ++total;
        if (result.pass) ++passed;
        else append_failure(failures, result.detail);
    }
    add_aggregate(rows, log, "arith.add", "A-ARITH", total, passed, failures);
}

void check_arith_mul(const E1Corpus& corpus, int threads,
                     std::vector<EvidenceRow>& rows, std::vector<std::string>& log) {
    const auto results = parallel_map<ItemResult>(
        corpus.a_arith.size(), threads, [&](size_t i) {
            ItemResult result;
            const BigInt& a = corpus.a_arith[i].first;
            const BigInt& b = corpus.a_arith[i].second;
            OracleBigInt oa;
            OracleBigInt ob;
            if (!to_oracle(a, oa) || !to_oracle(b, ob)) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " oracle conversion failed";
                return result;
            }
            auto product = a.mul(b);
            if (!product.ok()) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " mul returned error";
                return result;
            }
            const std::string expected = oracle::to_decimal(oracle::mul(oa, ob));
            if (product.value().to_decimal() != expected) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " mul " +
                                a.to_decimal() + "*" + b.to_decimal() + " expected " +
                                expected + " actual " + product.value().to_decimal();
            }
            return result;
        });

    size_t total = 0;
    size_t passed = 0;
    std::vector<std::string> failures;
    for (const auto& result : results) {
        ++total;
        if (result.pass) ++passed;
        else append_failure(failures, result.detail);
    }
    add_aggregate(rows, log, "arith.mul", "A-ARITH", total, passed, failures);
}

void check_arith_sub(const E1Corpus& corpus, int threads,
                     std::vector<EvidenceRow>& rows, std::vector<std::string>& log) {
    const auto results = parallel_map<ItemResult>(
        corpus.a_arith.size(), threads, [&](size_t i) {
            ItemResult result;
            const BigInt& a = corpus.a_arith[i].first;
            const BigInt& b = corpus.a_arith[i].second;
            if (a < b) {
                result.counted = false;
                return result;
            }
            OracleBigInt oa;
            OracleBigInt ob;
            if (!to_oracle(a, oa) || !to_oracle(b, ob)) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " oracle conversion failed";
                return result;
            }
            auto difference = a.sub(b);
            if (!difference.ok()) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " sub returned error";
                return result;
            }
            auto minus = oracle::sub(oa, ob);
            if (!minus) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " oracle sub rejected a >= b";
                return result;
            }
            const std::string expected = oracle::to_decimal(*minus);
            if (difference.value().to_decimal() != expected) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " sub " +
                                a.to_decimal() + "-" + b.to_decimal() + " expected " +
                                expected + " actual " + difference.value().to_decimal();
            }
            return result;
        });

    size_t total = 0;
    size_t passed = 0;
    std::vector<std::string> failures;
    for (const auto& result : results) {
        if (!result.counted) continue;
        ++total;
        if (result.pass) ++passed;
        else append_failure(failures, result.detail);
    }
    add_aggregate(rows, log, "arith.sub", "A-ARITH", total, passed, failures);
}

void check_arith_ring(const E1Corpus& corpus, int threads,
                      std::vector<EvidenceRow>& rows, std::vector<std::string>& log) {
    std::vector<BigInt> pool;
    pool.reserve(corpus.a_edge.size() + corpus.a_bits.size() + corpus.a_rand.size());
    for (const auto& value : corpus.a_edge) pool.push_back(value);
    for (const auto& value : corpus.a_bits) pool.push_back(value);
    for (const auto& value : corpus.a_rand) pool.push_back(value);
    if (pool.empty()) {
        add_aggregate(rows, log, "arith.ring", "A-ARITH", 0, 0, {"empty operand pool"});
        return;
    }

    constexpr size_t kTriples = 1000;
    std::mt19937_64 rng(E1_CORPUS_SEED ^ 0x52494E47ull); // "RING"
    std::vector<std::array<BigInt, 3>> triples;
    triples.reserve(kTriples);
    for (size_t i = 0; i < kTriples; ++i) {
        const auto pick_index = [&]() {
            return static_cast<size_t>(rng() % pool.size());
        };
        triples.push_back({pool[pick_index()], pool[pick_index()], pool[pick_index()]});
    }

    const auto results = parallel_map<ItemResult>(
        triples.size(), threads, [&](size_t i) {
            ItemResult result;
            const BigInt& a = triples[i][0];
            const BigInt& b = triples[i][1];
            const BigInt& c = triples[i][2];
            OracleBigInt oa;
            OracleBigInt ob;
            OracleBigInt oc;
            if (!to_oracle(a, oa) || !to_oracle(b, ob) || !to_oracle(c, oc)) {
                result.pass = false;
                result.detail = "triple " + padded(i, 4) + " oracle conversion failed";
                return result;
            }

            auto ab = a.add(b);
            auto bc = b.add(c);
            if (!ab.ok() || !bc.ok()) {
                result.pass = false;
                result.detail = "triple " + padded(i, 4) + " add returned error";
                return result;
            }
            auto lhs = ab.value().add(c);
            auto rhs = a.add(bc.value());
            if (!lhs.ok() || !rhs.ok()) {
                result.pass = false;
                result.detail = "triple " + padded(i, 4) + " associativity returned error";
                return result;
            }
            if (lhs.value() != rhs.value() ||
                !matches_oracle(lhs.value(), oracle::add(oracle::add(oa, ob), oc))) {
                result.pass = false;
                result.detail = "triple " + padded(i, 4) + " associativity failed";
                return result;
            }

            auto bpc = b.add(c);
            if (!bpc.ok()) {
                result.pass = false;
                result.detail = "triple " + padded(i, 4) + " b+c returned error";
                return result;
            }
            auto distributed = a.mul(bpc.value());
            auto prod_b = a.mul(b);
            auto prod_c = a.mul(c);
            if (!distributed.ok() || !prod_b.ok() || !prod_c.ok()) {
                result.pass = false;
                result.detail = "triple " + padded(i, 4) + " distributivity returned error";
                return result;
            }
            auto sum_products = prod_b.value().add(prod_c.value());
            if (!sum_products.ok()) {
                result.pass = false;
                result.detail = "triple " + padded(i, 4) + " product sum returned error";
                return result;
            }
            if (distributed.value() != sum_products.value() ||
                !matches_oracle(distributed.value(),
                                oracle::add(oracle::mul(oa, ob), oracle::mul(oa, oc)))) {
                result.pass = false;
                result.detail = "triple " + padded(i, 4) + " distributivity failed";
                return result;
            }

            auto ba = b.mul(a);
            if (!ba.ok() || ba.value() != prod_b.value() ||
                !matches_oracle(ba.value(), oracle::mul(ob, oa))) {
                result.pass = false;
                result.detail = "triple " + padded(i, 4) + " commutativity failed";
            }
            return result;
        });

    size_t total = 0;
    size_t passed = 0;
    std::vector<std::string> failures;
    for (const auto& result : results) {
        ++total;
        if (result.pass) ++passed;
        else append_failure(failures, result.detail);
    }
    add_aggregate(rows, log, "arith.ring", "A-ARITH", total, passed, failures);
}

void check_div_divmod(const E1Corpus& corpus, int threads,
                      std::vector<EvidenceRow>& rows, std::vector<std::string>& log) {
    const auto results = parallel_map<ItemResult>(
        corpus.a_arith.size(), threads, [&](size_t i) {
            ItemResult result;
            const BigInt& a = corpus.a_arith[i].first;
            const BigInt& b = corpus.a_arith[i].second;
            if (b.is_zero()) {
                result.counted = false;
                return result;
            }
            OracleBigInt oa;
            OracleBigInt ob;
            if (!to_oracle(a, oa) || !to_oracle(b, ob)) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " oracle conversion failed";
                return result;
            }

            auto dm = a.divmod(b);
            if (!dm.ok()) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " divmod returned error";
                return result;
            }
            const BigInt& q = dm.value().first;
            const BigInt& r = dm.value().second;
            auto recon_q = q.mul(b);
            if (!recon_q.ok()) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " q*b returned error";
                return result;
            }
            auto recon = recon_q.value().add(r);
            if (!recon.ok() || recon.value() != a) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " a != q*b+r";
                return result;
            }
            if (!(r < b)) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " remainder not < divisor";
                return result;
            }

            auto od = oracle::divmod(oa, ob);
            if (!matches_oracle(q, od.first) || !matches_oracle(r, od.second)) {
                result.pass = false;
                result.detail = "A-ARITH " + padded(i, 5) + " quotient/remainder differ from oracle";
            }
            return result;
        });

    size_t total = 0;
    size_t passed = 0;
    std::vector<std::string> failures;
    for (const auto& result : results) {
        if (!result.counted) continue;
        ++total;
        if (result.pass) ++passed;
        else append_failure(failures, result.detail);
    }
    add_aggregate(rows, log, "div.divmod", "A-ARITH", total, passed, failures);
}

void check_conv_dec(const E1Corpus& corpus, int threads,
                    std::vector<EvidenceRow>& rows, std::vector<std::string>& log) {
    const auto outcomes = parallel_map<std::pair<EvidenceRow, std::string>>(
        corpus.s_dec.size(), threads, [&](size_t i) {
            const std::string& text = corpus.s_dec[i];
            std::string actual = "<from_decimal error>";
            std::string detail;
            bool pass = true;

            auto value = BigInt::from_decimal(text);
            if (!value.ok()) {
                pass = false;
                detail = "S-DEC " + padded(i, 3) + " from_decimal rejected canonical text";
            } else {
                actual = value.value().to_decimal();
                auto oracle_value = oracle::from_decimal(text);
                if (!oracle_value) {
                    pass = false;
                    detail = "S-DEC " + padded(i, 3) + " oracle rejected canonical text";
                } else {
                    const std::string oracle_text = oracle::to_decimal(*oracle_value);
                    if (actual != text) {
                        pass = false;
                        detail = "S-DEC " + padded(i, 3) + " round-trip expected " +
                                 text + " actual " + actual;
                    } else if (oracle_text != text) {
                        pass = false;
                        detail = "S-DEC " + padded(i, 3) + " oracle round-trip " + oracle_text;
                    } else if (actual != oracle_text) {
                        pass = false;
                        detail = "S-DEC " + padded(i, 3) + " engine/oracle disagree";
                    }
                }
            }

            EvidenceRow row = make_row("conv.dec", "S-DEC", padded(i, 3),
                                       sha256_hex(text), text, actual, pass);
            return std::make_pair(std::move(row), std::move(detail));
        });

    for (const auto& outcome : outcomes) {
        rows.push_back(outcome.first);
        if (!outcome.second.empty()) log.push_back("conv.dec: " + outcome.second);
    }
}

void check_conv_le(const E1Corpus& corpus, int threads,
                   std::vector<EvidenceRow>& rows, std::vector<std::string>& log) {
    const auto outcomes = parallel_map<std::pair<EvidenceRow, std::string>>(
        corpus.s_bytes.size(), threads, [&](size_t i) {
            const E1Corpus::BytesItem& item = corpus.s_bytes[i];
            const std::string expected = hex_bytes(item.trimmed);
            std::string actual = "<from_le_bytes error>";
            std::string detail;
            bool pass = true;

            const std::string_view raw_view = bytes_view(item.raw);
            auto value = BigInt::from_le_bytes(raw_view);
            if (!value.ok()) {
                pass = false;
                detail = "S-BYTES " + item.item_id + " from_le_bytes rejected input";
            } else {
                actual = hex_bytes(value.value().to_le_bytes());
                const OracleBigInt oracle_value = oracle::from_le_bytes(raw_view);
                const std::string oracle_text = oracle::to_decimal(oracle_value);
                const std::string oracle_bytes = hex_bytes(oracle::to_le_bytes(oracle_value));
                if (actual != expected) {
                    pass = false;
                    detail = "S-BYTES " + item.item_id + " round-trip expected " +
                             expected + " actual " + actual;
                } else if (oracle_bytes != expected) {
                    pass = false;
                    detail = "S-BYTES " + item.item_id + " oracle round-trip " + oracle_bytes;
                } else if (value.value().to_decimal() != oracle_text) {
                    pass = false;
                    detail = "S-BYTES " + item.item_id + " engine/oracle disagree";
                }
            }

            EvidenceRow row = make_row("conv.le", "S-BYTES", item.item_id,
                                       sha256_hex_bytes(item.raw), expected, actual, pass);
            return std::make_pair(std::move(row), std::move(detail));
        });

    for (const auto& outcome : outcomes) {
        rows.push_back(outcome.first);
        if (!outcome.second.empty()) log.push_back("conv.le: " + outcome.second);
    }
}

void check_len_node(const E1Corpus& corpus, int threads,
                    std::vector<EvidenceRow>& rows, std::vector<std::string>& log) {
    const auto outcomes = parallel_map<std::pair<EvidenceRow, std::string>>(
        corpus.t_len.size(), threads, [&](size_t i) {
            const TermSet& term = corpus.t_len[i];
            const std::vector<OracleBigInt> oracle_memo = oracle_lengths(term);
            const std::string expected = sha256_hex(join_oracle(oracle_memo));
            std::string actual = "<length_of error>";
            std::string detail;
            bool pass = true;

            auto measured = mapr::length_of(term);
            if (!measured.ok()) {
                pass = false;
                detail = "T-LEN " + padded(i, 4) + " length_of returned error";
            } else {
                const std::vector<BigInt>& memo = measured.value().memo;
                actual = sha256_hex(join_limbs(memo));
                if (memo.size() != oracle_memo.size()) {
                    pass = false;
                    detail = "T-LEN " + padded(i, 4) + " memo size " +
                             std::to_string(memo.size()) + " expected " +
                             std::to_string(oracle_memo.size());
                } else {
                    for (size_t node = 0; node < memo.size(); ++node) {
                        if (!matches_oracle(memo[node], oracle_memo[node])) {
                            pass = false;
                            detail = "T-LEN " + padded(i, 4) + " node " +
                                     std::to_string(node) + " expected " +
                                     oracle::to_decimal(oracle_memo[node]) + " actual " +
                                     memo[node].to_decimal();
                            break;
                        }
                    }
                }
            }

            EvidenceRow row = make_row("len.node", "T-LEN", padded(i, 4),
                                       term_fingerprint(term), expected, actual, pass);
            return std::make_pair(std::move(row), std::move(detail));
        });

    for (const auto& outcome : outcomes) {
        rows.push_back(outcome.first);
        if (!outcome.second.empty()) log.push_back("len.node: " + outcome.second);
    }
}

void check_len_identity(const E1Corpus& corpus, int threads,
                        std::vector<EvidenceRow>& rows, std::vector<std::string>& log) {
    const auto outcomes = parallel_map<std::pair<EvidenceRow, std::string>>(
        corpus.t_len.size(), threads, [&](size_t i) {
            const TermSet& term = corpus.t_len[i];
            std::string detail;
            size_t checked = 0;
            size_t passed = 0;
            bool have_memo = false;

            auto measured = mapr::length_of(term);
            if (!measured.ok()) {
                detail = "T-LEN " + padded(i, 4) + " length_of returned error";
            } else {
                have_memo = true;
                const std::vector<BigInt>& memo = measured.value().memo;
                for (size_t node = 0; node < term.nodes.size(); ++node) {
                    const TermNode& n = term.nodes[node];
                    BigInt identity = BigInt::zero();
                    bool applicable = true;
                    switch (n.kind) {
                        case mapr::NodeKind::Concat: {
                            std::vector<BigInt> children;
                            for (uint32_t child : n.children) {
                                children.push_back(memo[static_cast<size_t>(child)]);
                            }
                            identity = mapr::length_identity::concat(children);
                            break;
                        }
                        case mapr::NodeKind::Repeat:
                            identity = mapr::length_identity::repeat(
                                memo[static_cast<size_t>(n.child)], n.repeat_q, n.repeat_r);
                            break;
                        case mapr::NodeKind::Slice:
                            identity = mapr::length_identity::slice(
                                memo[static_cast<size_t>(n.child)], n.slice_start, n.slice_len);
                            break;
                        case mapr::NodeKind::Interleave: {
                            std::vector<BigInt> children;
                            for (uint32_t child : n.children) {
                                children.push_back(memo[static_cast<size_t>(child)]);
                            }
                            identity = mapr::length_identity::interleave(children, n.stride);
                            break;
                        }
                        default:
                            applicable = false;
                            break;
                    }
                    if (!applicable) continue;
                    ++checked;
                    if (identity == memo[node]) {
                        ++passed;
                    } else if (detail.empty()) {
                        detail = "T-LEN " + padded(i, 4) + " node " +
                                 std::to_string(node) + " identity " +
                                 identity.to_decimal() + " expected " +
                                 memo[node].to_decimal();
                    }
                }
            }

            const std::string expected = std::to_string(checked);
            const std::string actual =
                have_memo ? std::to_string(passed) : std::string("<length_of error>");
            const bool pass = have_memo && checked == passed;
            EvidenceRow row = make_row("len.identity", "T-LEN", padded(i, 4),
                                       term_fingerprint(term), expected, actual, pass);
            return std::make_pair(std::move(row), std::move(detail));
        });

    for (const auto& outcome : outcomes) {
        rows.push_back(outcome.first);
        if (!outcome.second.empty()) log.push_back("len.identity: " + outcome.second);
    }
}

void check_len_no_trust(const E1Corpus& corpus, int threads,
                        std::vector<EvidenceRow>& rows, std::vector<std::string>& log) {
    const auto outcomes = parallel_map<std::pair<EvidenceRow, std::string>>(
        corpus.t_len.size(), threads, [&](size_t i) {
            const TermSet& term = corpus.t_len[i];
            const std::vector<OracleBigInt> oracle_memo = oracle_lengths(term);
            std::string detail;
            bool pass = true;

            auto baseline = mapr::length_of(term);
            if (!baseline.ok()) {
                pass = false;
                detail = "T-LEN " + padded(i, 4) + " baseline length_of returned error";
            }

            TermSet corrupted = term;
            for (TermNode& node : corrupted.nodes) {
                auto incremented = node.stored_length.add(BigInt(1));
                node.stored_length = incremented.ok() ? incremented.value() : BigInt(0);
            }
            auto after = mapr::length_of(corrupted);
            if (!after.ok()) {
                pass = false;
                if (detail.empty()) {
                    detail = "T-LEN " + padded(i, 4) + " corrupted length_of returned error";
                }
            }

            std::string expected = "<baseline error>";
            std::string actual = "<corrupted error>";
            if (baseline.ok()) expected = sha256_hex(join_limbs(baseline.value().memo));
            if (after.ok()) actual = sha256_hex(join_limbs(after.value().memo));

            if (baseline.ok() && after.ok()) {
                if (baseline.value().memo.size() != oracle_memo.size()) {
                    pass = false;
                    if (detail.empty()) detail = "T-LEN " + padded(i, 4) + " memo size mismatch";
                } else {
                    for (size_t node = 0; node < oracle_memo.size(); ++node) {
                        if (!matches_oracle(after.value().memo[node], oracle_memo[node])) {
                            pass = false;
                            if (detail.empty()) {
                                detail = "T-LEN " + padded(i, 4) + " node " +
                                         std::to_string(node) + " trusted stored length";
                            }
                            break;
                        }
                    }
                }
                if (baseline.value().memo != after.value().memo) {
                    pass = false;
                    if (detail.empty()) {
                        detail = "T-LEN " + padded(i, 4) + " stored-length corruption changed memo";
                    }
                }
            }

            EvidenceRow row = make_row("len.no_trust", "T-LEN", padded(i, 4),
                                       term_fingerprint(term), expected, actual, pass);
            return std::make_pair(std::move(row), std::move(detail));
        });

    for (const auto& outcome : outcomes) {
        rows.push_back(outcome.first);
        if (!outcome.second.empty()) log.push_back("len.no_trust: " + outcome.second);
    }
}

void check_digest_sha256(const E1Corpus& corpus, int threads,
                         std::vector<EvidenceRow>& rows, std::vector<std::string>& log) {
    const auto outcomes = parallel_map<std::pair<EvidenceRow, std::string>>(
        corpus.kat_messages.size(), threads, [&](size_t i) {
            const std::string& message = corpus.kat_messages[i];
            std::string actual = "<error>";
            std::string detail;
            bool pass = true;

            auto digest = mapr::Sha256::hash(message);
            if (!digest.ok()) {
                pass = false;
                detail = "D-KAT sha-" + padded(i, 3) + " hash returned error";
            } else {
                actual = hex_bytes(std::vector<uint8_t>(digest.value().begin(),
                                                        digest.value().end()));
                const std::array<uint8_t, 32> oracle_digest = oracle::sha256(message);
                const std::string oracle_hex =
                    hex_bytes(std::vector<uint8_t>(oracle_digest.begin(), oracle_digest.end()));
                if (actual != kSha256Kat[i]) {
                    pass = false;
                    detail = "D-KAT sha-" + padded(i, 3) + " pinned expected " +
                             kSha256Kat[i] + " actual " + actual;
                } else if (oracle_hex != kSha256Kat[i]) {
                    pass = false;
                    detail = "D-KAT sha-" + padded(i, 3) + " oracle " + oracle_hex +
                             " does not match pinned";
                } else if (actual != oracle_hex) {
                    pass = false;
                    detail = "D-KAT sha-" + padded(i, 3) + " engine/oracle disagree";
                }
            }

            EvidenceRow row = make_row("digest.sha256", "D-KAT", "sha-" + padded(i, 3),
                                       sha256_hex(message), kSha256Kat[i], actual, pass);
            return std::make_pair(std::move(row), std::move(detail));
        });

    for (const auto& outcome : outcomes) {
        rows.push_back(outcome.first);
        if (!outcome.second.empty()) log.push_back("digest.sha256: " + outcome.second);
    }
}

void check_digest_crc32(const E1Corpus& corpus, int threads,
                        std::vector<EvidenceRow>& rows, std::vector<std::string>& log) {
    const auto outcomes = parallel_map<std::pair<EvidenceRow, std::string>>(
        corpus.kat_messages.size(), threads, [&](size_t i) {
            const std::string& message = corpus.kat_messages[i];
            const std::string actual = crc32_hex(mapr::crc32(message));
            const std::string oracle_hex = crc32_hex(oracle::crc32(message));
            std::string detail;
            bool pass = true;
            if (actual != kCrc32Kat[i]) {
                pass = false;
                detail = "D-KAT crc-" + padded(i, 3) + " pinned expected " +
                         kCrc32Kat[i] + " actual " + actual;
            } else if (oracle_hex != kCrc32Kat[i]) {
                pass = false;
                detail = "D-KAT crc-" + padded(i, 3) + " oracle " + oracle_hex +
                         " does not match pinned";
            } else if (actual != oracle_hex) {
                pass = false;
                detail = "D-KAT crc-" + padded(i, 3) + " engine/oracle disagree";
            }

            EvidenceRow row = make_row("digest.crc32", "D-KAT", "crc-" + padded(i, 3),
                                       sha256_hex(message), kCrc32Kat[i], actual, pass);
            return std::make_pair(std::move(row), std::move(detail));
        });

    for (const auto& outcome : outcomes) {
        rows.push_back(outcome.first);
        if (!outcome.second.empty()) log.push_back("digest.crc32: " + outcome.second);
    }
}

void check_digest_sha_incremental(const E1Corpus& corpus, int threads,
                                  std::vector<EvidenceRow>& rows,
                                  std::vector<std::string>& log) {
    (void)threads;
    size_t total_possible = 0;
    size_t policy_total = 0;
    size_t tested = 0;
    size_t passed = 0;
    bool one_shot_ok = true;
    std::vector<std::string> failures;

    for (size_t m = 0; m < corpus.kat_messages.size(); ++m) {
        const std::string& message = corpus.kat_messages[m];
        const std::string_view view(message);
        total_possible += message.size() + 1;
        const std::vector<size_t> splits =
            policy_splits(message.size(), E1_CORPUS_SEED ^ (0x53484100ull + m));
        policy_total += splits.size();

        auto one_shot = mapr::Sha256::hash(message);
        if (!one_shot.ok()) {
            one_shot_ok = false;
            append_failure(failures, "message " + std::to_string(m) + " one-shot error");
            continue;
        }

        size_t message_passed = 0;
        for (size_t split : splits) {
            ++tested;
            mapr::Sha256 ctx;
            bool ok = ctx.update(view.substr(0, split)) == mapr::ErrCode::Ok &&
                      ctx.update(view.substr(split)) == mapr::ErrCode::Ok;
            if (ok) {
                auto digest = ctx.finish();
                ok = digest.ok() && digest.value() == one_shot.value();
            }
            if (ok) {
                ++passed;
                ++message_passed;
            } else {
                append_failure(failures, "message " + std::to_string(m) +
                                             " split " + std::to_string(split));
            }
        }
        log.push_back("digest.sha_incremental: message=" + std::to_string(m) +
                      " tested=" + std::to_string(splits.size()) +
                      " total=" + std::to_string(message.size() + 1) +
                      " passed=" + std::to_string(message_passed));
    }

    const bool ok = one_shot_ok && tested == policy_total && passed == tested;
    EvidenceRow row;
    row.check = "digest.sha_incremental";
    row.corpus = "D-KAT";
    row.item_id = "all";
    row.input_sha256 = sha256_hex("digest.sha_incremental\nD-KAT");
    row.expected = "split_points_total=" + std::to_string(total_possible) +
                   " split_points_policy=" + std::to_string(policy_total);
    row.actual = "split_points_tested=" + std::to_string(tested) +
                 " split_points_passed=" + std::to_string(passed);
    row.verdict = ok ? "PASS" : "FAIL";
    row.log = "logs/E1-G.log#digest.sha_incremental";
    rows.push_back(std::move(row));
    for (const auto& failure : failures) log.push_back("digest.sha_incremental: " + failure);
    log.push_back("digest.sha_incremental: tested=" + std::to_string(tested) +
                  " passed=" + std::to_string(passed) + (ok ? " PASS" : " FAIL"));
}

void check_digest_crc_incremental(const E1Corpus& corpus, int threads,
                                  std::vector<EvidenceRow>& rows,
                                  std::vector<std::string>& log) {
    (void)threads;
    size_t total_possible = 0;
    size_t combine_tested = 0;
    size_t combine_passed = 0;
    size_t incremental_tested = 0;
    size_t incremental_passed = 0;
    std::vector<std::string> failures;

    for (size_t m = 0; m < corpus.kat_messages.size(); ++m) {
        const std::string& message = corpus.kat_messages[m];
        const std::string_view view(message);
        const size_t n = message.size();
        total_possible += n + 1;
        const uint32_t one_shot = mapr::crc32(message);

        if (n <= 4096) {
            // Every split point, directly through the incremental surface.
            std::vector<uint32_t> prefix(n + 1, 0);
            for (size_t i = 0; i < n; ++i) {
                prefix[i + 1] = mapr::crc32_incremental(view.substr(i, 1), prefix[i]);
            }
            size_t message_passed = 0;
            for (size_t split = 0; split <= n; ++split) {
                ++incremental_tested;
                if (mapr::crc32_incremental(view.substr(split), prefix[split]) == one_shot) {
                    ++incremental_passed;
                    ++message_passed;
                } else {
                    append_failure(failures, "message " + std::to_string(m) +
                                                 " split " + std::to_string(split));
                }
            }
            log.push_back("digest.crc_incremental: message=" + std::to_string(m) +
                          " direct_splits=" + std::to_string(message_passed) + "/" +
                          std::to_string(n + 1));
            continue;
        }

        // Large message: all split points via prefix states + combine, plus a
        // bounded direct-incremental sample (the SHA policy).
        std::vector<uint32_t> prefix(n + 1, 0);
        for (size_t i = 0; i < n; ++i) {
            prefix[i + 1] = mapr::crc32_incremental(view.substr(i, 1), prefix[i]);
        }
        std::vector<uint32_t> suffix(n + 1, 0);
        for (size_t i = n; i-- > 0;) {
            suffix[i] = mapr::crc32_combine(mapr::crc32(view.substr(i, 1)), suffix[i + 1],
                                            n - i - 1);
        }

        size_t combine_passed_message = 0;
        for (size_t split = 0; split <= n; ++split) {
            ++combine_tested;
            if (mapr::crc32_combine(prefix[split], suffix[split], n - split) == one_shot) {
                ++combine_passed;
                ++combine_passed_message;
            } else {
                append_failure(failures, "message " + std::to_string(m) +
                                             " combine split " + std::to_string(split));
            }
        }

        std::vector<size_t> sample = policy_splits(n, E1_CORPUS_SEED ^ (0x43524300ull + m));
        size_t incremental_passed_message = 0;
        for (size_t split : sample) {
            ++incremental_tested;
            if (mapr::crc32_incremental(view.substr(split), prefix[split]) == one_shot) {
                ++incremental_passed;
                ++incremental_passed_message;
            } else {
                append_failure(failures, "message " + std::to_string(m) +
                                             " incremental split " + std::to_string(split));
            }
        }
        log.push_back("digest.crc_incremental: message=" + std::to_string(m) +
                      " combine_splits=" + std::to_string(combine_passed_message) + "/" +
                      std::to_string(n + 1) + " incremental_sample=" +
                      std::to_string(incremental_passed_message) + "/" +
                      std::to_string(sample.size()));
    }

    const bool ok = combine_passed == combine_tested &&
                    incremental_passed == incremental_tested &&
                    combine_tested + incremental_tested > 0;
    EvidenceRow row;
    row.check = "digest.crc_incremental";
    row.corpus = "D-KAT";
    row.item_id = "all";
    row.input_sha256 = sha256_hex("digest.crc_incremental\nD-KAT");
    row.expected = "split_points_total=" + std::to_string(total_possible) +
                   " all_splits_via_combine=yes";
    row.actual = "combine_tested=" + std::to_string(combine_tested) +
                 " combine_passed=" + std::to_string(combine_passed) +
                 " incremental_tested=" + std::to_string(incremental_tested) +
                 " incremental_passed=" + std::to_string(incremental_passed);
    row.verdict = ok ? "PASS" : "FAIL";
    row.log = "logs/E1-G.log#digest.crc_incremental";
    rows.push_back(std::move(row));
    for (const auto& failure : failures) log.push_back("digest.crc_incremental: " + failure);
    log.push_back("digest.crc_incremental: combine=" + std::to_string(combine_passed) + "/" +
                  std::to_string(combine_tested) + " incremental=" +
                  std::to_string(incremental_passed) + "/" +
                  std::to_string(incremental_tested) + (ok ? " PASS" : " FAIL"));
}

void check_digest_zeroed(const E1Corpus& corpus, int threads,
                         std::vector<EvidenceRow>& rows, std::vector<std::string>& log) {
    (void)corpus;
    constexpr size_t kRegions = 1000;
    const auto results = parallel_map<ItemResult>(
        kRegions, threads, [&](size_t i) {
            ItemResult result;
            std::mt19937_64 rng(E1_CORPUS_SEED ^ (0x5A45524Full + i)); // "ZERO"
            const size_t length = 4 + static_cast<size_t>(rng() % 1021);
            std::string data(length, '\0');
            for (size_t j = 0; j < length; ++j) {
                data[j] = static_cast<char>(rng() & 0xFFu);
            }
            const size_t offset = static_cast<size_t>(rng() % (length - 3));

            const uint32_t zeroed = mapr::crc32_zeroed(data, offset);
            std::string materialized = data;
            for (size_t j = 0; j < 4; ++j) materialized[offset + j] = '\0';
            const uint32_t definition = mapr::crc32(materialized);
            const uint32_t oracle_zeroed = oracle::crc32_zeroed(data, offset);
            const uint32_t oracle_definition = oracle::crc32(materialized);

            if (zeroed != definition) {
                result.pass = false;
                result.detail = "region " + std::to_string(i) +
                                " crc32_zeroed != materialized definition";
            } else if (zeroed != oracle_zeroed) {
                result.pass = false;
                result.detail = "region " + std::to_string(i) + " engine/oracle disagree";
            } else if (definition != oracle_definition) {
                result.pass = false;
                result.detail = "region " + std::to_string(i) + " oracle definition disagrees";
            }
            return result;
        });

    size_t passed = 0;
    std::vector<std::string> failures;
    for (const auto& result : results) {
        if (result.pass) ++passed;
        else append_failure(failures, result.detail);
    }
    add_aggregate(rows, log, "digest.zeroed", "S-BYTES", results.size(), passed, failures);
}

void check_gear_stable(const E1Corpus& corpus, int threads,
                       std::vector<EvidenceRow>& rows, std::vector<std::string>& log) {
    (void)corpus;
    constexpr size_t kInputs = 100;
    const auto results = parallel_map<ItemResult>(
        kInputs, threads, [&](size_t i) {
            ItemResult result;
            std::mt19937_64 rng(E1_CORPUS_SEED ^ (0x47454152ull + i)); // "GEAR"
            const size_t length = static_cast<size_t>(rng() % 1025);
            std::string data(length, '\0');
            for (size_t j = 0; j < length; ++j) {
                data[j] = static_cast<char>(rng() & 0xFFu);
            }
            const uint64_t seed = rng();

            const uint64_t one_shot = mapr::gear_hash(data, seed);
            const uint64_t repeated = mapr::gear_hash(data, seed);
            mapr::GearHash stream(seed);
            stream.update(data);
            const uint64_t streamed = stream.finish();
            const uint64_t oracle_value = oracle::gear_hash(data, seed);

            if (one_shot != oracle_value) {
                result.pass = false;
                result.detail = "input " + std::to_string(i) + " engine/oracle disagree";
            } else if (repeated != one_shot) {
                result.pass = false;
                result.detail = "input " + std::to_string(i) + " repeated run differs";
            } else if (streamed != one_shot) {
                result.pass = false;
                result.detail = "input " + std::to_string(i) + " streaming differs";
            }
            return result;
        });

    size_t passed = 0;
    std::vector<std::string> failures;
    for (const auto& result : results) {
        if (result.pass) ++passed;
        else append_failure(failures, result.detail);
    }
    add_aggregate(rows, log, "gear.stable", "GEAR", results.size(), passed, failures);
}

void check_corpus_determinism(const E1Corpus& corpus,
                              std::vector<EvidenceRow>& rows,
                              std::vector<std::string>& log) {
    std::string expected = sha256_hex(serialize_corpus(corpus));
    std::string actual;
    bool pass = false;
    size_t second_rows = 0;
    try {
        const E1Corpus second = build_e1_corpus();
        second_rows = second.items.size();
        actual = sha256_hex(serialize_corpus(second));
        pass = expected == actual && corpus.items.size() == second.items.size();
    } catch (const std::exception& ex) {
        actual = std::string("exception:") + ex.what();
    }
    rows.push_back(make_row("corpus.determinism", "ALL", "all",
                            sha256_hex("corpus.determinism"), expected, actual, pass));
    log.push_back("corpus.determinism: rows=" + std::to_string(corpus.items.size()) +
                  " second_rows=" + std::to_string(second_rows) +
                  (pass ? " PASS" : " FAIL"));
}

} // namespace

Measurement measure_e1(const E1Corpus& corpus, int threads) {
    Measurement measurement;
    check_arith_add(corpus, threads, measurement.rows, measurement.log);
    check_arith_mul(corpus, threads, measurement.rows, measurement.log);
    check_arith_sub(corpus, threads, measurement.rows, measurement.log);
    check_arith_ring(corpus, threads, measurement.rows, measurement.log);
    check_div_divmod(corpus, threads, measurement.rows, measurement.log);
    check_conv_dec(corpus, threads, measurement.rows, measurement.log);
    check_conv_le(corpus, threads, measurement.rows, measurement.log);
    check_len_node(corpus, threads, measurement.rows, measurement.log);
    check_len_identity(corpus, threads, measurement.rows, measurement.log);
    check_len_no_trust(corpus, threads, measurement.rows, measurement.log);
    check_digest_sha256(corpus, threads, measurement.rows, measurement.log);
    check_digest_crc32(corpus, threads, measurement.rows, measurement.log);
    check_digest_sha_incremental(corpus, threads, measurement.rows, measurement.log);
    check_digest_crc_incremental(corpus, threads, measurement.rows, measurement.log);
    check_digest_zeroed(corpus, threads, measurement.rows, measurement.log);
    check_gear_stable(corpus, threads, measurement.rows, measurement.log);
    return measurement;
}

namespace {

bool write_manifest(const fs::path& root, const fs::path& manifest_path,
                    const std::vector<std::string>& relative_paths,
                    std::string& error) {
    std::error_code ec;
    fs::create_directories(manifest_path.parent_path(), ec);
    const fs::path temp = manifest_path.string() + ".tmp";
    std::ofstream ofs(temp, std::ios::trunc);
    if (!ofs) {
        error = "cannot open manifest temp file";
        return false;
    }
    for (const std::string& relative : relative_paths) {
        const std::string digest = sha256_file_hex(root / relative);
        if (digest.empty()) {
            error = "cannot hash " + relative;
            return false;
        }
        ofs << digest << "  " << relative << '\n';
    }
    ofs.flush();
    if (!ofs) {
        error = "manifest write failed";
        return false;
    }
    ofs.close();
    fs::rename(temp, manifest_path, ec);
    if (ec) {
        fs::remove(temp, ec);
        error = "manifest rename failed";
        return false;
    }
    return true;
}

size_t manifest_entries(const fs::path& manifest_path) {
    std::ifstream ifs(manifest_path);
    size_t count = 0;
    std::string line;
    while (std::getline(ifs, line)) {
        if (!line.empty()) ++count;
    }
    return count;
}

std::string env_record_text(const EnvRecord& env) {
    std::ostringstream oss;
    oss << "date_utc: " << env.date_utc << '\n';
    oss << "host: " << env.host << '\n';
    oss << "kernel: " << env.kernel << '\n';
    oss << "nproc: " << env.nproc << '\n';
    oss << "mem_total_kib: " << env.mem_total_kib << '\n';
    oss << "disk: " << env.disk << '\n';
    oss << "compiler: " << env.compiler << '\n';
    oss << "make: " << env.make << '\n';
    oss << "engine_sha256: " << env.engine_sha256 << '\n';
    oss << "test_sha256: " << env.test_sha256 << '\n';
    oss << "fixture_manifest_sha256: " << env.fixture_manifest_sha256 << '\n';
    return oss.str();
}

} // namespace

int run_e1_gate(const fs::path& root, int threads, std::string_view command_line) {
    const fs::path v2 = root / "specs_and_reports" / "v2";
    const fs::path gates_dir = v2 / "gates";
    const fs::path logs_dir = v2 / "logs";
    const fs::path corpus_path = v2 / "corpus" / "E1" / "corpus.tsv";
    const fs::path evidence_dir = v2 / "evidence" / "E1";
    const fs::path tsv_path = gates_dir / "E1-G.tsv";
    const fs::path log_path = logs_dir / "E1-G.log";
    const fs::path manifest_path = evidence_dir / "SHA256SUMS";
    const fs::path e0_tsv = gates_dir / "E0-G.tsv";
    const fs::path e0_log = logs_dir / "E0-G.log";

    std::error_code ec;
    fs::create_directories(gates_dir, ec);
    fs::create_directories(logs_dir, ec);
    fs::create_directories(corpus_path.parent_path(), ec);
    fs::create_directories(evidence_dir, ec);

    std::ofstream log_file(log_path, std::ios::trunc);
    if (!log_file) return 1;
    log_file << env_record_text(capture_env_record(root));
    log_file << "command_line: " << command_line << '\n';
    log_file.flush();

    std::vector<EvidenceRow> rows;
    std::vector<std::string> log_lines;

    // Precondition: E0-G must already pass with committed evidence.
    std::string e0_problem;
    const auto e0_rows = read_evidence_tsv(e0_tsv);
    if (e0_rows.empty()) {
        e0_problem = "missing or empty E0-G.tsv";
    } else {
        size_t failed = 0;
        for (const auto& row : e0_rows) {
            if (row.verdict != "PASS") ++failed;
        }
        if (failed != 0) e0_problem = std::to_string(failed) + " non-PASS E0-G rows";
    }
    if (!fs::exists(e0_log)) {
        e0_problem = e0_problem.empty() ? "missing E0-G.log" : e0_problem + "; missing E0-G.log";
    }
    if (!e0_problem.empty()) {
        rows.push_back(make_blocked_row("precondition.e0g", "E0-G", "all",
                                        "E0-G PASS with evidence", e0_problem));
        log_file << "precondition.e0g: BLOCKED " << e0_problem << '\n';
        log_file << "RESULT: BLOCKED\nexit_code: 2\n";
        log_file.close();
        write_evidence_tsv(tsv_path, std::move(rows));
        return 2;
    }

    E1Corpus corpus;
    std::string corpus_error;
    try {
        corpus = build_e1_corpus();
    } catch (const std::exception& ex) {
        corpus_error = std::string("build_e1_corpus threw: ") + ex.what();
    }
    if (corpus_error.empty() && !write_corpus(corpus, corpus_path)) {
        corpus_error = "write_corpus failed";
    } else if (corpus_error.empty()) {
        const auto read_back = read_corpus(corpus_path);
        if (read_back.size() != corpus.items.size()) {
            corpus_error = "corpus.tsv rows " + std::to_string(read_back.size()) +
                           " expected " + std::to_string(corpus.items.size());
        }
    }
    if (!corpus_error.empty()) {
        rows.push_back(make_blocked_row("precondition.corpus", "ALL", "all",
                                        "corpus.tsv written and read back",
                                        corpus_error));
        log_file << "precondition.corpus: BLOCKED " << corpus_error << '\n';
        log_file << "RESULT: BLOCKED\nexit_code: 2\n";
        log_file.close();
        write_evidence_tsv(tsv_path, std::move(rows));
        return 2;
    }

    const int cli_threads = std::max(1, threads);
    const Measurement cli = measure_e1(corpus, cli_threads);
    const Measurement one = (cli_threads == 1) ? cli : measure_e1(corpus, 1);
    const Measurement four = (cli_threads == 4) ? cli : measure_e1(corpus, 4);

    rows = cli.rows;
    for (const auto& line : cli.log) log_file << line << '\n';
    check_corpus_determinism(corpus, rows, log_lines);
    for (const auto& line : log_lines) log_file << line << '\n';
    log_lines.clear();

    // threads.identical: the full measurement under 1 and 4 workers must
    // produce the same row sequence.
    {
        const std::string one_serial = serialize_rows(one.rows);
        const std::string four_serial = serialize_rows(four.rows);
        const std::string expected = sha256_hex(one_serial);
        const std::string actual = sha256_hex(four_serial);
        const bool pass = expected == actual && one.rows.size() == four.rows.size();
        rows.push_back(make_row("threads.identical", "ALL", "all",
                                sha256_hex("threads.identical"), expected, actual, pass));
        log_file << "threads.identical: rows_1=" << one.rows.size()
                 << " rows_4=" << four.rows.size()
                 << (pass ? " PASS" : " FAIL") << '\n';
    }

    // Phase 1: evidence without evidence.present. The manifest is computed over
    // this exact state, then verified, then evidence.present is appended.
    log_file.flush();
    if (!write_evidence_tsv(tsv_path, rows)) {
        log_file << "RESULT: FAIL\nexit_code: 1\n";
        log_file.close();
        return 1;
    }

    const std::vector<std::string> evidence_files = {
        "specs_and_reports/v2/gates/E0-G.tsv",
        "specs_and_reports/v2/logs/E0-G.log",
        "specs_and_reports/v2/gates/E1-G.tsv",
        "specs_and_reports/v2/logs/E1-G.log",
        "specs_and_reports/v2/corpus/E1/corpus.tsv",
    };

    std::string manifest_error;
    const bool phase1_manifest =
        write_manifest(root, manifest_path, evidence_files, manifest_error);
    const int phase1_verify = phase1_manifest ? verify_evidence(manifest_path) : 1;
    const size_t entries = phase1_manifest ? manifest_entries(manifest_path) : 0;

    EvidenceRow evidence_row;
    evidence_row.check = "evidence.present";
    evidence_row.corpus = "ALL";
    evidence_row.item_id = "all";
    evidence_row.input_sha256 = sha256_hex("evidence.present");
    evidence_row.expected = "manifest_entries=" + std::to_string(entries);
    evidence_row.actual = phase1_verify == 0
                              ? "manifest_entries=" + std::to_string(entries)
                              : ("verification_failed:" + manifest_error);
    evidence_row.verdict = (phase1_manifest && phase1_verify == 0 && entries > 0) ? "PASS" : "FAIL";
    evidence_row.log = "logs/E1-G.log#evidence.present";
    rows.push_back(std::move(evidence_row));
    log_file << "evidence.present: entries=" << entries
             << " verify=" << (phase1_verify == 0 ? "PASS" : "FAIL")
             << (manifest_error.empty() ? "" : (" error=" + manifest_error)) << '\n';

    if (!write_evidence_tsv(tsv_path, rows)) {
        log_file << "RESULT: FAIL\nexit_code: 1\n";
        log_file.close();
        return 1;
    }

    bool all_pass = !rows.empty();
    for (const auto& row : rows) {
        if (row.verdict != "PASS") all_pass = false;
    }

    const int exit_code = all_pass ? 0 : 1;
    log_file << "RESULT: " << (all_pass ? "PASS" : "FAIL") << '\n';
    log_file << "exit_code: " << exit_code << '\n';
    log_file.flush();
    log_file.close();

    // Phase 2: final manifest over the final TSV and final log. The committed
    // artifact is verified by CI with `--verify-evidence`.
    std::string final_error;
    const bool final_manifest =
        write_manifest(root, manifest_path, evidence_files, final_error);
    if (!final_manifest || verify_evidence(manifest_path) != 0) return 1;
    return exit_code;
}

} // namespace marp::harness

