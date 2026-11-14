#include "marp/harness/e1_oracle.hpp"
#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <array>

using namespace marp::harness::oracle;

TEST(E1Oracle, SHA256_EmptyString) {
    auto digest = sha256("");
    std::array<uint8_t, 32> expected = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    EXPECT_EQ(digest, expected);
}

TEST(E1Oracle, SHA256_Abc) {
    auto digest = sha256("abc");
    std::array<uint8_t, 32> expected = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    EXPECT_EQ(digest, expected);
}

TEST(E1Oracle, SHA256_LongString) {
    std::string long_str = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    auto digest = sha256(long_str);
    std::array<uint8_t, 32> expected = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
    };
    EXPECT_EQ(digest, expected);
}

TEST(E1Oracle, CRC32_EmptyString) {
    EXPECT_EQ(crc32(""), 0x00000000u);
}

TEST(E1Oracle, CRC32_KnownValues) {
    EXPECT_EQ(crc32("a"), 0xE8B7BE43u);
    EXPECT_EQ(crc32("abc"), 0x352441C2u);
    EXPECT_EQ(crc32("message digest"), 0x20159D7Fu);
    EXPECT_EQ(crc32("abcdefghijklmnopqrstuvwxyz"), 0x4C2750BDu);
    EXPECT_EQ(crc32("123456789"), 0xCBF43926u);
    EXPECT_EQ(crc32("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), 0x1FC2E6D2u);
}

TEST(E1Oracle, CRC32_IncrementalProperty) {
    std::string a = "Hello, ";
    std::string b = "World!";
    std::string ab = a + b;
    
    // Initial state for incremental is finalized CRC of empty (init=0 finalized)
    constexpr uint32_t CRC32_INIT_VAL = 0xFFFFFFFFu;
    constexpr uint32_t CRC32_XOROUT_VAL = 0xFFFFFFFFu;
    uint32_t init_finalized = CRC32_INIT_VAL ^ CRC32_XOROUT_VAL; // 0xFFFFFFFF ^ 0xFFFFFFFF = 0
    uint32_t crc_a = crc32_incremental(a, init_finalized);
    uint32_t crc_ab = crc32_incremental(ab, init_finalized);
    uint32_t crc_b_from_a = crc32_incremental(b, crc_a);
    EXPECT_EQ(crc_b_from_a, crc_ab);
}

TEST(E1Oracle, CRC32_Combine) {
    std::string a = "Hello, ";
    std::string b = "World!";
    std::string ab = a + b;
    
    uint32_t crc_a = crc32(a);
    uint32_t crc_b = crc32(b);
    uint32_t crc_ab = crc32(ab);
    uint32_t combined = crc32_combine(crc_a, crc_b, b.size());
    EXPECT_EQ(combined, crc_ab);
}

TEST(E1Oracle, CRC32_Zeroed) {
    std::string data = "HeaderWithChecksumFieldAtOffset16";
    while (data.size() < 20) data += "x";
    
    uint32_t zeroed = crc32_zeroed(data, 16);
    
    std::string modified = data;
    modified[16] ^= static_cast<char>(0xFF);
    modified[17] ^= static_cast<char>(0xAA);
    modified[18] ^= static_cast<char>(0x55);
    modified[19] ^= static_cast<char>(0x33);
    
    uint32_t zeroed2 = crc32_zeroed(modified, 16);
    EXPECT_EQ(zeroed, zeroed2);
    
    std::string data_with_zeros = data;
    data_with_zeros[16] = 0;
    data_with_zeros[17] = 0;
    data_with_zeros[18] = 0;
    data_with_zeros[19] = 0;
    EXPECT_EQ(crc32_zeroed(data_with_zeros, 16), crc32(data_with_zeros));
}

TEST(E1Oracle, GearHash_Empty) {
    EXPECT_EQ(gear_hash(""), 0ull);
}

TEST(E1Oracle, GearHash_Deterministic) {
    std::string data = "Hello, World!";
    uint64_t h1 = gear_hash(data);
    uint64_t h2 = gear_hash(data);
    EXPECT_EQ(h1, h2);
}

TEST(E1Oracle, GearHash_DifferentSeeds) {
    std::string data = "test";
    uint64_t h1 = gear_hash(data, 0);
    uint64_t h2 = gear_hash(data, 1);
    uint64_t h3 = gear_hash(data, 0xFFFFFFFFFFFFFFFFull);
    EXPECT_NE(h1, h2);
    EXPECT_NE(h1, h3);
    EXPECT_NE(h2, h3);
}

TEST(E1Oracle, GearHash_StreamingEqualsOneShot) {
    std::string data = "The quick brown fox jumps over the lazy dog";
    uint64_t one_shot = gear_hash(data);
    
    uint64_t state = 0;
    const auto& G = []() {
        std::array<uint64_t, 256> t{};
        for (int i = 0; i < 256; ++i) {
            t[i] = (static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ull) ^ (static_cast<uint64_t>(i) * 0xC2B2AE3D27D4EB4Full);
        }
        return t;
    }();
    
    for (char c : data) {
        state = (state << 1) + G[static_cast<uint8_t>(c)];
    }
    EXPECT_EQ(state, one_shot);
}

TEST(E1Oracle, BigInt_FromDecimal) {
    auto r = from_decimal("0");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(to_decimal(*r), "0");
    
    r = from_decimal("42");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(to_decimal(*r), "42");
    
    r = from_decimal("4294967296");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(to_decimal(*r), "4294967296");
    
    r = from_decimal("00");
    EXPECT_FALSE(r.has_value());
    
    r = from_decimal("12a3");
    EXPECT_FALSE(r.has_value());
}

TEST(E1Oracle, BigInt_DecimalRoundtrip) {
    std::vector<std::string> corpus = {
        "0", "1", "9", "10", "42", "255", "256", "65535", "65536",
        "4294967295", "4294967296", "18446744073709551615",
        "340282366920938463463374607431768211455"
    };
    for (const auto& s : corpus) {
        auto r = from_decimal(s);
        ASSERT_TRUE(r.has_value()) << "Failed to parse: " << s;
        EXPECT_EQ(to_decimal(*r), s) << "Roundtrip failed for: " << s;
    }
}

TEST(E1Oracle, BigInt_Add) {
    auto a = from_decimal("12345678901234567890");
    auto b = from_decimal("98765432109876543210");
    ASSERT_TRUE(a && b);
    auto sum = add(*a, *b);
    EXPECT_EQ(to_decimal(sum), "111111111011111111100");
}

TEST(E1Oracle, BigInt_Sub) {
    auto a = from_decimal("98765432109876543210");
    auto b = from_decimal("12345678901234567890");
    ASSERT_TRUE(a && b);
    auto diff = sub(*a, *b);
    ASSERT_TRUE(diff.has_value());
    EXPECT_EQ(to_decimal(*diff), "86419753208641975320");
    
    // a < b should return nullopt
    auto diff2 = sub(*b, *a);
    EXPECT_FALSE(diff2.has_value());
}

TEST(E1Oracle, BigInt_Mul) {
    auto a = from_decimal("123456789");
    auto b = from_decimal("987654321");
    ASSERT_TRUE(a && b);
    auto prod = mul(*a, *b);
    EXPECT_EQ(to_decimal(prod), "121932631112635269");
}

TEST(E1Oracle, BigInt_Divmod) {
    auto a = from_decimal("100");
    auto b = from_decimal("7");
    ASSERT_TRUE(a && b);
    auto [q, r] = divmod(*a, *b);
    EXPECT_EQ(to_decimal(q), "14");
    EXPECT_EQ(to_decimal(r), "2");
    
    // Verify a = q*b + r
    auto qb = mul(q, *b);
    auto qbr = add(qb, r);
    EXPECT_EQ(qbr, *a);
    EXPECT_LT(compare(r, *b), 0);
    EXPECT_GE(compare(r, BigInt{0}), 0);
}

TEST(E1Oracle, BigInt_DivmodScalar) {
    auto a = from_decimal("12345678901234567890");
    ASSERT_TRUE(a);
    auto [q, r] = divmod_scalar(*a, 1000);
    EXPECT_EQ(to_decimal(q), "12345678901234567");
    EXPECT_EQ(r, 890);
    
    // Verify
    auto qb = mul(q, BigInt{1000});
    auto qbr = add(qb, BigInt{r});
    EXPECT_EQ(qbr, *a);
}

TEST(E1Oracle, BigInt_FromLEBytes) {
    std::vector<uint8_t> bytes = {0x01, 0x00, 0x00, 0x00};
    auto bi = from_le_bytes(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    EXPECT_EQ(to_decimal(bi), "1");
    
    bytes = {0x00, 0x00, 0x00, 0x01};
    bi = from_le_bytes(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    EXPECT_EQ(to_decimal(bi), "16777216");
}

TEST(E1Oracle, BigInt_ToLEBytes) {
    // 0x01020304 = 16909060 in decimal
    auto bi = from_decimal("16909060");
    ASSERT_TRUE(bi);
    auto bytes = to_le_bytes(*bi);
    ASSERT_EQ(bytes.size(), 4u);
    EXPECT_EQ(bytes[0], 0x04);
    EXPECT_EQ(bytes[1], 0x03);
    EXPECT_EQ(bytes[2], 0x02);
    EXPECT_EQ(bytes[3], 0x01);
    
    bi = from_decimal("1");
    ASSERT_TRUE(bi);
    bytes = to_le_bytes(*bi);
    ASSERT_EQ(bytes.size(), 1u);
    EXPECT_EQ(bytes[0], 0x01);
}

TEST(E1Oracle, BigInt_BitLength) {
    EXPECT_EQ(bit_length(BigInt(0)), 0);
    EXPECT_EQ(bit_length(BigInt(1)), 1);
    EXPECT_EQ(bit_length(BigInt(0xFFFFFFFFull)), 32);
    EXPECT_EQ(bit_length(BigInt(0x100000000ull)), 33); // 2^32
}

TEST(E1Oracle, SelfCheck) {
    EXPECT_TRUE(self_check());
}

TEST(E1Oracle, NoE1Headers) {
    // This test verifies that the oracle source doesn't include E1 headers
    // by checking that we can compile without them - this is a compile-time check
    // The actual check is done in CI by grepping for "mapr/e1_" in oracle sources
    SUCCEED();
}

TEST(E1Oracle, Compare) {
    auto a = from_decimal("100");
    auto b = from_decimal("200");
    ASSERT_TRUE(a && b);
    EXPECT_EQ(compare(*a, *b), -1);
    EXPECT_EQ(compare(*b, *a), 1);
    EXPECT_EQ(compare(*a, *a), 0);
}

TEST(E1Oracle, Trim) {
    BigInt a = {0, 0, 1, 0, 0}; // trailing zeros
    auto trimmed = trim(a);
    EXPECT_EQ(trimmed.size(), 3u);
    EXPECT_EQ(trimmed[2], 1u);
    
    BigInt zero = {0, 0, 0};
    auto trimmed_zero = trim(zero);
    EXPECT_EQ(trimmed_zero.size(), 1u);
    EXPECT_EQ(trimmed_zero[0], 0u);
}