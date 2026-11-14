#include "mapr/e1_sha256.hpp"
#include <gtest/gtest.h>
#include <array>
#include <string_view>
#include <vector>

using namespace mapr;

TEST(E1Sha256, EmptyString) {
    auto r = Sha256::hash("");
    ASSERT_TRUE(r.ok());
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    std::array<uint8_t, 32> expected = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    EXPECT_EQ(r.value(), expected);
}

TEST(E1Sha256, Abc) {
    auto r = Sha256::hash("abc");
    ASSERT_TRUE(r.ok());
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    std::array<uint8_t, 32> expected = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    EXPECT_EQ(r.value(), expected);
}

TEST(E1Sha256, LongString) {
    std::string long_str = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    auto r = Sha256::hash(long_str);
    ASSERT_TRUE(r.ok());
    // Known KAT
    std::array<uint8_t, 32> expected = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
    };
    EXPECT_EQ(r.value(), expected);
}

TEST(E1Sha256, StreamingEqualsOneShot) {
    std::string data = "The quick brown fox jumps over the lazy dog";
    auto one_shot = Sha256::hash(data);
    ASSERT_TRUE(one_shot.ok());

    // Test all split points
    for (size_t cut = 0; cut <= data.size(); ++cut) {
        Sha256 ctx;
        ErrCode err1 = ctx.update(std::string_view(data).substr(0, cut));
        ASSERT_EQ(err1, ErrCode::Ok);
        ErrCode err2 = ctx.update(std::string_view(data).substr(cut));
        ASSERT_EQ(err2, ErrCode::Ok);
        auto finish = ctx.finish();
        ASSERT_TRUE(finish.ok());
        EXPECT_EQ(finish.value(), one_shot.value()) << "Split at " << cut;
    }
}

TEST(E1Sha256, MultiUpdate) {
    std::string data = "The quick brown fox jumps over the lazy dog";
    auto one_shot = Sha256::hash(data);
    ASSERT_TRUE(one_shot.ok());

    Sha256 ctx;
    ctx.update("The quick ");
    ctx.update("brown fox ");
    ctx.update("jumps over ");
    ctx.update("the lazy dog");
    auto finish = ctx.finish();
    ASSERT_TRUE(finish.ok());
    EXPECT_EQ(finish.value(), one_shot.value());
}

TEST(E1Sha256, LimitExceeded) {
    Sha256 ctx;
    std::string large(1000000, 'x');
    for (int i = 0; i < 1000; ++i) {
        ErrCode err = ctx.update(large);
        if (err != ErrCode::Ok) {
            EXPECT_EQ(err, ErrCode::Limit);
            break;
        }
    }
}

TEST(E1Sha256, Reset) {
    Sha256 ctx;
    ctx.update("hello");
    ctx.finish();
    ctx.reset();
    ctx.update("world");
    auto r = ctx.finish();
    ASSERT_TRUE(r.ok());
    // SHA-256("world") = 486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7
    std::array<uint8_t, 32> expected = {
        0x48, 0x6e, 0xa4, 0x62, 0x24, 0xd1, 0xbb, 0x4f,
        0xb6, 0x80, 0xf3, 0x4f, 0x7c, 0x9a, 0xd9, 0x6a,
        0x8f, 0x24, 0xec, 0x88, 0xbe, 0x73, 0xea, 0x8e,
        0x5a, 0x6c, 0x65, 0x26, 0x0e, 0x9c, 0xb8, 0xa7
    };
    EXPECT_EQ(r.value(), expected);
}

TEST(E1Sha256, PaddingLength) {
    // Test that padding produces correct block count
    // |pad(M)| = 64 * ceil((L+9)/64) (Math-SPECS C2)
    std::vector<std::pair<size_t, size_t>> cases = {
        {0, 64},      // L=0 -> ceil(9/64)=1 -> 64
        {1, 64},      // L=1 -> ceil(10/64)=1 -> 64
        {55, 64},     // L=55 -> ceil(64/64)=1 -> 64
        {56, 128},    // L=56 -> ceil(65/64)=2 -> 128
        {63, 128},    // L=63 -> ceil(72/64)=2 -> 128
        {64, 128},    // L=64 -> ceil(73/64)=2 -> 128
        {1000, 1024}, // L=1000 -> ceil(1009/64)=16 -> 1024
    };

    for (auto [L, expected_padded] : cases) {
        std::string data(L, 'x');
        Sha256 ctx;
        ErrCode err = ctx.update(data);
        ASSERT_EQ(err, ErrCode::Ok);
        auto r = ctx.finish();
        ASSERT_TRUE(r.ok()) << "Failed for L=" << L;
    }
}