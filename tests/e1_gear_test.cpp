#include "mapr/e1_gear.hpp"
#include <gtest/gtest.h>
#include <string_view>
#include <random>

using namespace mapr;

TEST(E1Gear, EmptyString) {
    EXPECT_EQ(gear_hash(""), 0ull);
}

TEST(E1Gear, Deterministic) {
    std::string data = "Hello, World!";
    uint64_t h1 = gear_hash(data);
    uint64_t h2 = gear_hash(data);
    EXPECT_EQ(h1, h2);
}

TEST(E1Gear, DifferentSeeds) {
    std::string data = "test";
    uint64_t h1 = gear_hash(data, 0);
    uint64_t h2 = gear_hash(data, 1);
    uint64_t h3 = gear_hash(data, 0xFFFFFFFFFFFFFFFFull);
    EXPECT_NE(h1, h2);
    EXPECT_NE(h1, h3);
    EXPECT_NE(h2, h3);
}

TEST(E1Gear, StreamingEqualsOneShot) {
    std::string data = "The quick brown fox jumps over the lazy dog";
    uint64_t one_shot = gear_hash(data);

    GearHash gh;
    gh.update("The quick ");
    gh.update("brown fox ");
    gh.update("jumps over ");
    gh.update("the lazy dog");
    EXPECT_EQ(gh.finish(), one_shot);
}

TEST(E1Gear, AllSplitPoints) {
    std::string data = "test data for split points";
    for (size_t cut = 0; cut <= data.size(); ++cut) {
        GearHash gh;
        gh.update(std::string_view(data).substr(0, cut));
        gh.update(std::string_view(data).substr(cut));
        EXPECT_EQ(gh.finish(), gear_hash(data)) << "Split at " << cut;
    }
}

TEST(E1Gear, Window64Bytes) {
    // Gear hash has a 64-byte window: bytes older than 64 don't affect the hash
    // (Math-SPECS Theorem C12, Corollary C13)
    std::string tail(64, 'x');
    std::string prefix1(100, 'a');
    std::string prefix2(100, 'b');

    uint64_t h1 = gear_hash(prefix1 + tail);
    uint64_t h2 = gear_hash(prefix2 + tail);

    // Since prefixes are longer than 64 bytes and differ, but tail is same last 64 bytes
    // AND total length is same (164), the hash should be the same
    // because seed * 2^n is same for same n, and only last 64 bytes matter
    EXPECT_EQ(h1, h2);
}

TEST(E1Gear, WindowDifferentLengths) {
    // If lengths differ, seed*2^n differs even mod 2^64
    std::string tail(64, 'x');
    std::string prefix1(100, 'a');
    std::string prefix2(99, 'b');

    uint64_t h1 = gear_hash(prefix1 + tail);
    uint64_t h2 = gear_hash(prefix2 + tail);
    // Lengths differ (164 vs 163), so seed*2^n differs
    EXPECT_NE(h1, h2);
}

TEST(E1Gear, TableGeneration) {
    const auto& G = gear_table();
    for (int i = 0; i < 256; ++i) {
        uint64_t expected = (static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ull) ^
                           (static_cast<uint64_t>(i) * 0xC2B2AE3D27D4EB4Full);
        EXPECT_EQ(G[i], expected) << "Table entry " << i;
    }
}

TEST(E1Gear, ClosedFormMatchesIterative) {
    std::mt19937 rng(0xFEEDFACE);
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    std::uniform_int_distribution<uint64_t> seed_dist(0, UINT64_MAX);

    for (int iter = 0; iter < 100; ++iter) {
        size_t L = rng() % 200;
        std::string data(L, 0);
        for (size_t i = 0; i < L; ++i) data[i] = dist(rng);
        uint64_t seed = seed_dist(rng);

        uint64_t iterative = 0;
        {
            GearHash gh(seed);
            gh.update(data);
            iterative = gh.finish();
        }

        uint64_t one_shot = gear_hash(data, seed);
        EXPECT_EQ(iterative, one_shot);
    }
}

TEST(E1Gear, Forgetfulness) {
    // Bytes older than 64 cannot matter (Corollary C13)
    std::mt19937 rng(0xBADF00D);
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    for (int iter = 0; iter < 50; ++iter) {
        size_t L = 65 + rng() % 200;
        std::string data(L, 0);
        for (size_t i = 0; i < L; ++i) data[i] = dist(rng);
        uint64_t seed = rng();

        uint64_t h1 = gear_hash(data, seed);

        // Mutate a byte in the prefix (older than last 64)
        size_t old = rng() % (L - 64);
        data[old] ^= static_cast<char>(0xFF);

        uint64_t h2 = gear_hash(data, seed);
        EXPECT_EQ(h1, h2) << "Iter " << iter << ", L=" << L << ", old=" << old;
    }
}

TEST(E1Gear, SameTailSameLength) {
    // Two messages with same length and same last 64 bytes have same hash
    std::mt19937 rng(0xCAFEBABE);
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    for (int iter = 0; iter < 50; ++iter) {
        std::string tail(64, 0);
        for (size_t i = 0; i < 64; ++i) tail[i] = dist(rng);

        size_t prefix_len1 = rng() % 100;
        size_t prefix_len2 = rng() % 100;
        std::string prefix1(prefix_len1, 0), prefix2(prefix_len2, 0);
        for (size_t i = 0; i < prefix_len1; ++i) prefix1[i] = dist(rng);
        for (size_t i = 0; i < prefix_len2; ++i) prefix2[i] = dist(rng);

        // Only compare if total lengths are equal
        if (prefix_len1 == prefix_len2) {
            uint64_t h1 = gear_hash(prefix1 + tail);
            uint64_t h2 = gear_hash(prefix2 + tail);
            EXPECT_EQ(h1, h2) << "Iter " << iter;
        }
    }
}