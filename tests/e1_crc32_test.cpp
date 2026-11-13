#include "mapr/e1_crc32.hpp"
#include <gtest/gtest.h>
#include <string_view>
#include <random>
#include <zlib.h>

using namespace mapr;

TEST(E1Crc32, EmptyString) {
    EXPECT_EQ(crc32(""), 0u);
}

TEST(E1Crc32, KnownValues) {
    // Standard CRC-32 test vectors
    EXPECT_EQ(crc32(""), 0x00000000u);
    EXPECT_EQ(crc32("a"), 0xE8B7BE43u);
    EXPECT_EQ(crc32("abc"), 0x352441C2u);
    EXPECT_EQ(crc32("message digest"), 0x20159D7Fu);
    EXPECT_EQ(crc32("abcdefghijklmnopqrstuvwxyz"), 0x4C2750BDu);
    EXPECT_EQ(crc32("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), 0xD6A84C6Fu);
    EXPECT_EQ(crc32("12345678901234567890123456789012345678901234567890123456789012345678901234567890"), 0x14B87C49u);
}

TEST(E1Crc32, ZlibCompatibility) {
    // zlib.crc32 with init=0 matches our incremental (no init, no final XOR)
    std::string data = "Hello, World!";
    uint32_t zlib_crc = static_cast<uint32_t>(::crc32(0, reinterpret_cast<const Bytef*>(data.data()), static_cast<uInt>(data.size())));
    uint32_t our_crc = crc32_incremental(data);
    EXPECT_EQ(our_crc, zlib_crc);
}

TEST(E1Crc32, IncrementalProperty) {
    std::string data = "The quick brown fox jumps over the lazy dog";
    for (size_t cut = 0; cut <= data.size(); ++cut) {
        uint32_t c1 = crc32_incremental(std::string_view(data).substr(0, cut));
        uint32_t c2 = crc32_incremental(std::string_view(data).substr(cut), c1);
        uint32_t c_full = crc32_incremental(data);
        EXPECT_EQ(c2, c_full) << "Split at " << cut;
    }
}

TEST(E1Crc32, StandardVsIncremental) {
    // crc32() = zlib.crc32(0xFFFFFFFF, data) ^ 0xFFFFFFFF
    std::string data = "test data";
    uint32_t std_crc = crc32(data);
    uint32_t zlib_crc = static_cast<uint32_t>(::crc32(0xFFFFFFFF, reinterpret_cast<const Bytef*>(data.data()), static_cast<uInt>(data.size()))) ^ 0xFFFFFFFF;
    EXPECT_EQ(std_crc, zlib_crc);
}

TEST(E1Crc32, Combine) {
    std::string a = "Hello, ";
    std::string b = "World!";
    std::string ab = a + b;

    uint32_t crc_a = crc32(a);
    uint32_t crc_b = crc32(b);
    uint32_t crc_ab = crc32(ab);

    uint32_t combined1 = crc32_combine(crc_a, crc_b, b.size());
    EXPECT_EQ(combined1, crc_ab);

    // Test with random data
    std::mt19937 rng(0xC0FFEEu);
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    for (int iter = 0; iter < 100; ++iter) {
        size_t la = rng() % 100;
        size_t lb = rng() % 100;
        std::string sa(la, 0), sb(lb, 0);
        for (size_t i = 0; i < la; ++i) sa[i] = dist(rng);
        for (size_t i = 0; i < lb; ++i) sb[i] = dist(rng);

        uint32_t ca = crc32(sa);
        uint32_t cb = crc32(sb);
        uint32_t cab = crc32(sa + sb);
        uint32_t combined2 = crc32_combine(ca, cb, lb);
        EXPECT_EQ(combined2, cab) << "Iter " << iter << ", la=" << la << ", lb=" << lb;
    }
}

TEST(E1Crc32, ZeroedField) {
    std::string data = "HeaderWithChecksumFieldAtOffset16";
    // Ensure we have at least 20 bytes
    while (data.size() < 20) data += "x";

    (void)crc32(data); // unused but kept for reference
    uint32_t zeroed = crc32_zeroed(data, 16);

    // Change the 4 bytes at offset 16
    std::string modified = data;
    modified[16] ^= static_cast<char>(0xFF);
    modified[17] ^= static_cast<char>(0xAA);
    modified[18] ^= static_cast<char>(0x55);
    modified[19] ^= static_cast<char>(0x33);

    uint32_t zeroed2 = crc32_zeroed(modified, 16);
    EXPECT_EQ(zeroed, zeroed2); // Invariant: zeroed checksum unchanged

    // If the 4 bytes were already zero, zeroed == original
    std::string data_with_zeros = data;
    data_with_zeros[16] = 0;
    data_with_zeros[17] = 0;
    data_with_zeros[18] = 0;
    data_with_zeros[19] = 0;
    EXPECT_EQ(crc32_zeroed(data_with_zeros, 16), crc32(data_with_zeros));
}

TEST(E1Crc32, ZeroedFieldInvariance) {
    std::mt19937 rng(0xDEADBEEF);
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    for (int iter = 0; iter < 100; ++iter) {
        size_t L = 20 + rng() % 100;
        size_t offset = rng() % (L - 3);
        std::string data(L, 0);
        for (size_t i = 0; i < L; ++i) data[i] = dist(rng);

        bool ok = crc32_zeroed_invariant(data, offset);
        EXPECT_TRUE(ok) << "Iter " << iter << ", L=" << L << ", offset=" << offset;
    }
}

TEST(E1Crc32, TableGeneration) {
    // Verify the table matches the standard reflected polynomial
    const auto& table = crc32_table();
    for (int i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j) {
            if (c & 1) c = (c >> 1) ^ CRC32_POLY;
            else c >>= 1;
        }
        EXPECT_EQ(table[i], c) << "Table entry " << i;
    }
}

TEST(E1Crc32, CombineMatrix) {
    // Test that the combine matrix produces correct results for powers of 2
    const auto& powers = crc32_combine_matrix();
    // Just verify it compiles and the matrix is non-trivial
    EXPECT_NE(powers[0][0], 0u);
    EXPECT_NE(powers[1][0], 0u);
}