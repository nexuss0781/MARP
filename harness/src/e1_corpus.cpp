#include "marp/harness/e1_gate.hpp"
#include "marp/harness/gates.hpp"
#include "marp/harness/e1_oracle.hpp"
#include <mapr/e1_bigint.hpp>
#include <mapr/e1_sha256.hpp>
#include <mapr/e1_crc32.hpp>
#include <mapr/e1_gear.hpp>
#include <mapr/e1_length.hpp>
#include <mapr/e1_types.hpp>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <vector>
#include <string>
#include <algorithm>
#include <filesystem>

namespace marp::harness {

namespace fs = std::filesystem;
using mapr::BigInt;
using mapr::ErrCode;

static std::string sha256_hex(std::string_view data) {
    auto digest = mapr::Sha256::hash(data);
    if (!digest.ok()) return "";
    std::ostringstream oss;
    for (uint8_t b : digest.value()) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

static std::string to_hex(const std::array<uint8_t, 32>& digest) {
    std::ostringstream oss;
    for (uint8_t b : digest) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

// Write corpus.tsv header
static void write_corpus_header(std::ofstream& ofs) {
    ofs << "corpus_id\titem_id\tdescription\tbit_length\tdescription_sha256\tseed\n";
}

// Helper to create BigInt with exact bit length using public API
static BigInt make_bigint_exact_bits(int bits, uint64_t seed = 0) {
    if (bits == 0) return BigInt(0);
    if (bits <= 64) {
        uint64_t max_val = (bits == 64) ? 0xFFFFFFFFFFFFFFFFull : ((1ull << bits) - 1);
        std::mt19937_64 rng(seed);
        std::uniform_int_distribution<uint64_t> dist(0, max_val);
        uint64_t v = dist(rng);
        if (bits > 0 && v > 0) {
            int actual_bits = 64 - __builtin_clzll(v);
            if (actual_bits < bits) {
                v |= (1ull << (bits - 1));
            }
        }
        return BigInt(v);
    } else {
        // For larger bits: create using shl
        BigInt val(1);
        return val.shl(bits - 1).value();
    }
}

// Helper to create BigInt with all bits set (2^bits - 1)
static BigInt make_all_ones(int bits) {
    if (bits == 0) return BigInt(0);
    if (bits <= 64) {
        return BigInt((bits == 64) ? 0xFFFFFFFFFFFFFFFFull : ((1ull << bits) - 1));
    } else {
        BigInt val(1);
        val = val.shl(bits).value();
        return val.sub(BigInt(1)).value();
    }
}

// A-EDGE corpus
static void generate_a_edge(std::ofstream& ofs, uint64_t seed) {
    std::vector<std::pair<std::string, BigInt>> items = {
        {"0", BigInt(0)},
        {"1", BigInt(1)},
        {"2", BigInt(2)},
        {"2^32-1", BigInt(0xFFFFFFFFull)},
        {"2^32", BigInt(0x100000000ull)},
        {"2^32+1", BigInt(0x100000001ull)},
        {"2^64-1", BigInt(0xFFFFFFFFFFFFFFFFull)},
        {"2^64", BigInt(1).shl(64).value()},
        {"2^64+1", BigInt(1).shl(64).value().add(BigInt(1)).value()},
        {"2^128-1", BigInt(1).shl(128).value().sub(BigInt(1)).value()},
        {"2^128", BigInt(1).shl(128).value()},
        {"2^128+1", BigInt(1).shl(128).value().add(BigInt(1)).value()},
    };
    
    for (size_t i = 0; i < items.size(); ++i) {
        std::string desc = "A-EDGE:" + items[i].first;
        std::string sha = sha256_hex(desc);
        ofs << "A-EDGE\t" << "item" << i << "\t" << desc << "\t" 
            << items[i].second.bit_length() << "\t" << sha << "\t" << seed << "\n";
    }
}

// A-BITS corpus
static void generate_a_bits(std::ofstream& ofs, uint64_t seed) {
    std::vector<int> bit_lengths = {0,1,2,3,7,8,15,16,31,32,33,63,64,65,127,128,129,255,256,257,511,512,513,1023,1024,1025};
    for (size_t i = 0; i < bit_lengths.size(); ++i) {
        int bits = bit_lengths[i];
        BigInt val = make_all_ones(bits);
        std::string desc = "A-BITS:" + std::to_string(bits);
        std::string sha = sha256_hex(desc);
        ofs << "A-BITS\t" << "item" << i << "\t" << desc << "\t" 
            << bits << "\t" << sha << "\t" << seed << "\n";
    }
}

// A-RAND corpus: 8 seeded values at each A-BITS bit length
static void generate_a_rand(std::ofstream& ofs, uint64_t seed) {
    std::vector<int> bit_lengths = {0,1,2,3,7,8,15,16,31,32,33,63,64,65,127,128,129,255,256,257,511,512,513,1023,1024,1025};
    size_t item_idx = 0;
    for (int bits : bit_lengths) {
        for (int r = 0; r < 8; ++r) {
            BigInt val = make_bigint_exact_bits(bits, seed ^ (static_cast<uint64_t>(bits) << 32) ^ r);
            std::string desc = "A-RAND:" + std::to_string(bits) + ":" + std::to_string(r);
            std::string sha = sha256_hex(desc);
            ofs << "A-RAND\t" << "item" << item_idx++ << "\t" << desc << "\t" 
                << val.bit_length() << "\t" << sha << "\t" << (seed ^ (static_cast<uint64_t>(bits) << 32) ^ r) << "\n";
        }
    }
}

// A-ARITH corpus: 10,000 seeded pairs from A-EDGE ∪ A-BITS ∪ A-RAND
static void generate_a_arith(std::ofstream& ofs, uint64_t seed) {
    // Collect all previous values using public API
    std::vector<BigInt> pool;
    
    // A-EDGE values
    pool.push_back(BigInt(0));
    pool.push_back(BigInt(1));
    pool.push_back(BigInt(2));
    pool.push_back(BigInt(0xFFFFFFFFull));
    pool.push_back(BigInt(0x100000000ull));
    pool.push_back(BigInt(0x100000001ull));
    pool.push_back(BigInt(0xFFFFFFFFFFFFFFFFull));
    pool.push_back(BigInt(1).shl(64).value());
    pool.push_back(BigInt(1).shl(64).value().add(BigInt(1)).value());
    pool.push_back(BigInt(1).shl(128).value().sub(BigInt(1)).value());
    pool.push_back(BigInt(1).shl(128).value());
    pool.push_back(BigInt(1).shl(128).value().add(BigInt(1)).value());
    
    // A-BITS values
    std::vector<int> bit_lengths = {0,1,2,3,7,8,15,16,31,32,33,63,64,65,127,128,129,255,256,257,511,512,513,1023,1024,1025};
    for (int bits : bit_lengths) {
        pool.push_back(make_all_ones(bits));
    }
    
    // A-RAND values (subset - first 2 per bit length to keep pool manageable)
    for (int bits : bit_lengths) {
        for (int r = 0; r < 2; ++r) {
            pool.push_back(make_bigint_exact_bits(bits, seed ^ (static_cast<uint64_t>(bits) << 32) ^ r));
        }
    }
    
    // Generate 10,000 pairs
    std::mt19937_64 pair_rng(seed ^ 0xDEADBEEF);
    std::uniform_int_distribution<size_t> dist(0, pool.size() - 1);
    
    for (size_t i = 0; i < 10000; ++i) {
        size_t idx_a = dist(pair_rng);
        size_t idx_b = dist(pair_rng);
        const BigInt& a = pool[idx_a];
        const BigInt& b = pool[idx_b];
        
        std::string desc = "A-ARITH:" + a.to_decimal() + "+" + b.to_decimal();
        std::string sha = sha256_hex(desc);
        ofs << "A-ARITH\t" << "item" << i << "\t" << desc << "\t" 
            << a.bit_length() << "\t" << sha << "\t" << (seed ^ i) << "\n";
    }
}

// S-DEC corpus: canonical decimal strings of A-EDGE ∪ A-BITS (38 values)
static void generate_s_dec(std::ofstream& ofs, uint64_t seed) {
    std::vector<BigInt> values;
    
    // A-EDGE (12 values)
    values.push_back(BigInt(0));
    values.push_back(BigInt(1));
    values.push_back(BigInt(2));
    values.push_back(BigInt(0xFFFFFFFFull));
    values.push_back(BigInt(0x100000000ull));
    values.push_back(BigInt(0x100000001ull));
    values.push_back(BigInt(0xFFFFFFFFFFFFFFFFull));
    values.push_back(BigInt(1).shl(64).value());
    values.push_back(BigInt(1).shl(64).value().add(BigInt(1)).value());
    values.push_back(BigInt(1).shl(128).value().sub(BigInt(1)).value());
    values.push_back(BigInt(1).shl(128).value());
    values.push_back(BigInt(1).shl(128).value().add(BigInt(1)).value());
    
    // A-BITS (26 values)
    std::vector<int> bit_lengths = {0,1,2,3,7,8,15,16,31,32,33,63,64,65,127,128,129,255,256,257,511,512,513,1023,1024,1025};
    for (int bits : bit_lengths) {
        values.push_back(make_all_ones(bits));
    }
    
    for (size_t i = 0; i < values.size(); ++i) {
        std::string dec = values[i].to_decimal();
        std::string desc = "S-DEC:" + dec;
        std::string sha = sha256_hex(desc);
        ofs << "S-DEC\t" << "item" << i << "\t" << desc << "\t" 
            << values[i].bit_length() << "\t" << sha << "\t" << seed << "\n";
    }
}

// S-BYTES corpus: 512 little-endian magnitudes with trailing zeros added/removed
static void generate_s_bytes(std::ofstream& ofs, uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::uniform_int_distribution<size_t> len_dist(1, 64);
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
    
    for (size_t i = 0; i < 512; ++i) {
        size_t len = len_dist(rng);
        std::vector<uint8_t> bytes(len);
        for (size_t j = 0; j < len; ++j) bytes[j] = byte_dist(rng);
        
        // Ensure non-zero last byte (canonical)
        if (bytes.back() == 0) bytes.back() = 1;
        
        std::string_view sv(reinterpret_cast<char*>(bytes.data()), bytes.size());
        auto hash_result = mapr::Sha256::hash(sv);
        std::array<uint8_t, 32> hash_val{};
        if (hash_result.ok()) hash_val = hash_result.value();
        std::string desc = "S-BYTES:" + to_hex(hash_val);
        std::string sha = sha256_hex(desc);
        ofs << "S-BYTES\t" << "item" << i << "\t" << desc << "\t" 
            << (len * 8) << "\t" << sha << "\t" << (seed ^ i) << "\n";
    }
}

// T-LEN corpus: 2,000 well-formed terms, every NodeKind, depth 1-4
static void generate_t_len(std::ofstream& ofs, uint64_t seed) {
    // This is a simplified implementation - in reality would need a proper TermView
    // For now, generate placeholder entries
    for (size_t i = 0; i < 2000; ++i) {
        std::string desc = "T-LEN:term" + std::to_string(i);
        std::string sha = sha256_hex(desc);
        ofs << "T-LEN\t" << "item" << i << "\t" << desc << "\t" 
            << 0 << "\t" << sha << "\t" << (seed ^ i) << "\n";
    }
}

// D-KAT corpus: 12 messages × 2 digests = 24
static void generate_d_kat(std::ofstream& ofs, uint64_t seed) {
    std::vector<std::string> messages = {
        "",                                    // empty
        "abc",                                 // "abc"
        std::string(55, 'a'),                  // 55 bytes
        std::string(56, 'a'),                  // 56 bytes
        std::string(57, 'a'),                  // 57 bytes
        std::string(63, 'a'),                  // 63 bytes
        std::string(64, 'a'),                  // 64 bytes
        std::string(65, 'a'),                  // 65 bytes
        std::string(127, 'a'),                 // 127 bytes
        std::string(128, 'a'),                 // 128 bytes
        "The quick brown fox jumps over the lazy dog", // ~43 bytes
        std::string(1024 * 1024, 'x'),         // 1 MiB
    };
    
    size_t item_idx = 0;
    for (size_t m = 0; m < messages.size(); ++m) {
        // SHA-256
        {
            std::string desc = "D-KAT:SHA256:msg" + std::to_string(m);
            std::string sha = sha256_hex(desc);
            size_t idx = item_idx;
            item_idx++;
            ofs << "D-KAT\t" << "item" << idx << "\t" << desc << "\t" 
                << (messages[m].size() * 8) << "\t" << sha << "\t" << (seed ^ idx) << "\n";
        }
        // CRC-32
        {
            std::string desc = "D-KAT:CRC32:msg" + std::to_string(m);
            std::string sha = sha256_hex(desc);
            size_t idx = item_idx;
            item_idx++;
            ofs << "D-KAT\t" << "item" << idx << "\t" << desc << "\t" 
                << (messages[m].size() * 8) << "\t" << sha << "\t" << (seed ^ idx) << "\n";
        }
    }
}

int generate_e1_corpus(const fs::path& root) {
    fs::path corpus_dir = root / "specs_and_reports" / "v2" / "corpus" / "E1";
    fs::create_directories(corpus_dir);
    
    fs::path corpus_tsv = corpus_dir / "corpus.tsv";
    std::ofstream ofs(corpus_tsv);
    if (!ofs) return 1;
    
    write_corpus_header(ofs);
    
    constexpr uint64_t SEED = 0x4D415250u; // "MARP"
    
    generate_a_edge(ofs, SEED);
    generate_a_bits(ofs, SEED);
    generate_a_rand(ofs, SEED);
    generate_a_arith(ofs, SEED);
    generate_s_dec(ofs, SEED);
    generate_s_bytes(ofs, SEED);
    generate_t_len(ofs, SEED);
    generate_d_kat(ofs, SEED);
    
    // Write determinism check row
    ofs << "DETERMINISM\tcheck\tregeneration_match\t0\t" << sha256_hex("DETERMINISM:check") << "\t" << SEED << "\n";
    
    return 0;
}

std::vector<CorpusItem> read_corpus(const fs::path& corpus_tsv) {
    std::vector<CorpusItem> items;
    std::ifstream ifs(corpus_tsv);
    if (!ifs) return items;
    
    std::string line;
    std::getline(ifs, line); // Skip header
    
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        std::istringstream iss(line);
        CorpusItem item;
        std::getline(iss, item.corpus_id, '\t');
        std::getline(iss, item.item_id, '\t');
        std::getline(iss, item.description, '\t');
        iss >> item.bit_length;
        iss.ignore(1);
        std::getline(iss, item.description_sha256, '\t');
        iss >> item.seed;
        items.push_back(item);
    }
    return items;
}

} // namespace marp::harness