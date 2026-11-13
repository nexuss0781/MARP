#include "mapr/e1_bigint.hpp"
#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <cstdint>

using namespace mapr;

namespace {

// Test corpus - basic values
const std::vector<uint64_t> SMALL_VALUES = {
    0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 65,
    255, 256, 257, 65535, 65536, 65537,
    4294967295ull, 4294967296ull, 4294967297ull,
    18446744073709551615ull
};

// Generate all pairs for testing
std::vector<std::pair<BigInt, BigInt>> make_pairs() {
    std::vector<std::pair<BigInt, BigInt>> pairs;
    for (uint64_t a : SMALL_VALUES) {
        for (uint64_t b : SMALL_VALUES) {
            pairs.emplace_back(BigInt(a), BigInt(b));
        }
    }
    return pairs;
}

const auto ARITH_PAIRS = make_pairs();

// Remove the early namespace close - all tests go inside

TEST(E1BigInt, Construction) {
    EXPECT_TRUE(BigInt().is_zero());
    EXPECT_EQ(BigInt(0).limb_count(), static_cast<size_t>(0));
    EXPECT_EQ(BigInt(1).limb_count(), static_cast<size_t>(1));
    EXPECT_EQ(BigInt(0xFFFFFFFF).limb_count(), static_cast<size_t>(1));
    EXPECT_EQ(BigInt(0x100000000ull).limb_count(), static_cast<size_t>(2));
    EXPECT_EQ(BigInt(0x100000000ull).limb(0), static_cast<Limb>(0));
    EXPECT_EQ(BigInt(0x100000000ull).limb(1), static_cast<Limb>(1));
}

TEST(E1BigInt, FromLimbs) {
    Limb limbs[] = {1, 2, 3};
    auto r = BigInt::from_limbs(limbs, 3);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().limb_count(), static_cast<size_t>(3));
    EXPECT_EQ(r.value().limb(0), static_cast<Limb>(1));
    EXPECT_EQ(r.value().limb(1), static_cast<Limb>(2));
    EXPECT_EQ(r.value().limb(2), static_cast<Limb>(3));

    // Non-canonical should fail
    Limb bad[] = {1, 0};
    auto r2 = BigInt::from_limbs(bad, 2);
    EXPECT_FALSE(r2.ok());
    EXPECT_EQ(r2.error(), ErrCode::Invalid);
}

TEST(E1BigInt, FromLEBytes) {
    auto r = BigInt::from_le_bytes("\x01\x00\x00\x00");
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value(), BigInt(1));

    r = BigInt::from_le_bytes("\x00\x00\x00\x01");
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value(), BigInt(0x1000000));

    r = BigInt::from_le_bytes("");
    ASSERT_TRUE(r.ok());
    EXPECT_TRUE(r.value().is_zero());

    // Trailing zeros trimmed
    r = BigInt::from_le_bytes("\x01\x00\x00\x00\x00\x00\x00\x00");
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value(), BigInt(1));
}

TEST(E1BigInt, FromDecimal) {
    auto r = BigInt::from_decimal("0");
    ASSERT_TRUE(r.ok());
    EXPECT_TRUE(r.value().is_zero());

    r = BigInt::from_decimal("42");
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value(), BigInt(42));

    r = BigInt::from_decimal("4294967296"); // 2^32
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().limb_count(), static_cast<size_t>(2));
    EXPECT_EQ(r.value().limb(0), static_cast<Limb>(0));
    EXPECT_EQ(r.value().limb(1), static_cast<Limb>(1));

    // Leading zeros invalid
    r = BigInt::from_decimal("00");
    EXPECT_FALSE(r.ok());

    // Non-digits invalid
    r = BigInt::from_decimal("12a3");
    EXPECT_FALSE(r.ok());
}

TEST(E1BigInt, ToU64Checked) {
    EXPECT_EQ(BigInt(0).to_u64_checked().value(), 0ull);
    EXPECT_EQ(BigInt(42).to_u64_checked().value(), 42ull);
    EXPECT_EQ(BigInt(0xFFFFFFFF).to_u64_checked().value(), 0xFFFFFFFFull);
    EXPECT_EQ(BigInt(0xFFFFFFFFFFFFFFFFull).to_u64_checked().value(), 0xFFFFFFFFFFFFFFFFull);

    // Over 64 bits -> Limit
    EXPECT_EQ(BigInt(0x10000000000ull).to_u64_checked().error(), ErrCode::Limit);
}

TEST(E1BigInt, ToDecimal) {
    EXPECT_EQ(BigInt(0).to_decimal(), "0");
    EXPECT_EQ(BigInt(42).to_decimal(), "42");
    EXPECT_EQ(BigInt(0xFFFFFFFF).to_decimal(), "4294967295");
    EXPECT_EQ(BigInt(0x100000000ull).to_decimal(), "4294967296");
}

TEST(E1BigInt, ToLEBytes) {
    auto bytes = BigInt(0x01020304).to_le_bytes();
    ASSERT_EQ(bytes.size(), static_cast<size_t>(4));
    EXPECT_EQ(bytes[0], 0x04);
    EXPECT_EQ(bytes[1], 0x03);
    EXPECT_EQ(bytes[2], 0x02);
    EXPECT_EQ(bytes[3], 0x01);

    bytes = BigInt(0).to_le_bytes();
    EXPECT_TRUE(bytes.empty());

    // Trailing zeros trimmed
    bytes = BigInt(0x100000000ull).to_le_bytes(); // 0x01 0x00 0x00 0x00 0x00
    ASSERT_EQ(bytes.size(), static_cast<size_t>(5));
    EXPECT_EQ(bytes[4], 0x01);
}

TEST(E1BigInt, Compare) {
    EXPECT_EQ(BigInt(0).compare(BigInt(0)), 0);
    EXPECT_EQ(BigInt(1).compare(BigInt(0)), 1);
    EXPECT_EQ(BigInt(0).compare(BigInt(1)), -1);
    EXPECT_EQ(BigInt(0xFFFFFFFF).compare(BigInt(0x100000000ull)), -1);
    EXPECT_EQ(BigInt(0x100000000ull).compare(BigInt(0xFFFFFFFF)), 1);
}

TEST(E1BigInt, RingLaws_O1_1) {
    for (const auto& [a, b] : ARITH_PAIRS) {
        // Commutativity of add
        auto ab = a.add(b);
        auto ba = b.add(a);
        ASSERT_TRUE(ab.ok() && ba.ok());
        EXPECT_EQ(ab.value(), ba.value());

        // Commutativity of mul
        ab = a.mul(b);
        ba = b.mul(a);
        ASSERT_TRUE(ab.ok() && ba.ok());
        EXPECT_EQ(ab.value(), ba.value());
    }

    // Associativity and distributivity on smaller subset
    const std::vector<uint64_t> SUBSET = {0, 1, 2, 3, 7, 15, 31, 255, 65535, 4294967295};
    for (uint64_t av : SUBSET) {
        for (uint64_t bv : SUBSET) {
            for (uint64_t cv : SUBSET) {
                BigInt a(av), b(bv), c(cv);
                // (a + b) + c = a + (b + c)
                auto ab = a.add(b);
                auto bc = b.add(c);
                ASSERT_TRUE(ab.ok() && bc.ok());
                auto lhs = ab.value().add(c);
                auto rhs = a.add(bc.value());
                ASSERT_TRUE(lhs.ok() && rhs.ok());
                EXPECT_EQ(lhs.value(), rhs.value());

                // a * (b + c) = a*b + a*c
                bc = b.add(c);
                auto ambc = a.mul(bc.value());
                auto am = a.mul(b);
                auto ac = a.mul(c);
                ASSERT_TRUE(ambc.ok() && am.ok() && ac.ok());
                auto dist_rhs = am.value().add(ac.value());
                ASSERT_TRUE(dist_rhs.ok());
                EXPECT_EQ(ambc.value(), dist_rhs.value());
            }
        }
    }
}

TEST(E1BigInt, DivisionLaw_O1_2) {
    for (const auto& [a, b] : ARITH_PAIRS) {
        if (b.is_zero()) continue;
        auto dm = a.divmod(b);
        ASSERT_TRUE(dm.ok());
        const auto& [q, r] = dm.value();
        // a = q*b + r
        auto qb = q.mul(b);
        ASSERT_TRUE(qb.ok());
        auto qbr = qb.value().add(r);
        ASSERT_TRUE(qbr.ok());
        EXPECT_EQ(qbr.value(), a);
        // 0 <= r < b
        EXPECT_LT(r.compare(b), 0);
        EXPECT_GE(r.compare(BigInt::zero()), 0);
    }
}

TEST(E1BigInt, DecimalRoundtrip_O1_3) {
    const std::vector<std::string> DECIMAL_CORPUS = {
        "0", "1", "9", "10", "42", "255", "256", "65535", "65536",
        "4294967295", "4294967296", "18446744073709551615",
        "340282366920938463463374607431768211455" // 2^128-1
    };
    for (const auto& s : DECIMAL_CORPUS) {
        auto r = BigInt::from_decimal(s);
        ASSERT_TRUE(r.ok()) << "Failed to parse: " << s;
        EXPECT_EQ(r.value().to_decimal(), s) << "Roundtrip failed for: " << s;
    }
}

TEST(E1BigInt, ByteRoundtrip_O1_4) {
    const std::vector<std::string> BYTE_CORPUS = {
        "", "\x00", "\x01", "\xFF", "\x01\x02\x03\x04",
        "\x00\x00\x00\x01", "\xFF\xFF\xFF\xFF",
        "\x01\x00\x00\x00\x00", // 2^32
    };
    for (const auto& b : BYTE_CORPUS) {
        auto r = BigInt::from_le_bytes(b);
        ASSERT_TRUE(r.ok()) << "Failed to parse bytes";
        auto rt = r.value().to_le_bytes();
        // Trim trailing zeros from original
        std::vector<uint8_t> trimmed(b.begin(), b.end());
        while (!trimmed.empty() && trimmed.back() == 0) trimmed.pop_back();
        EXPECT_EQ(rt, trimmed) << "Roundtrip failed for bytes";
    }
}

TEST(E1BigInt, Shifts) {
    // shl
    EXPECT_EQ(BigInt(1).shl(0).value(), BigInt(1));
    EXPECT_EQ(BigInt(1).shl(1).value(), BigInt(2));
    EXPECT_EQ(BigInt(1).shl(31).value(), BigInt(1ull << 31));
    EXPECT_EQ(BigInt(1).shl(32).value(), BigInt(0x100000000ull));
    EXPECT_EQ(BigInt(1).shl(64).value().limb_count(), 3); // 2^64 = 3 limbs in base 2^32

    // shr
    EXPECT_EQ(BigInt(16).shr(0).value(), BigInt(16));
    EXPECT_EQ(BigInt(16).shr(1).value(), BigInt(8));
    EXPECT_EQ(BigInt(16).shr(4).value(), BigInt(1));
    EXPECT_EQ(BigInt(16).shr(5).value(), BigInt(0));
    EXPECT_EQ(BigInt(0x100000000ull).shr(32).value(), BigInt(1));
}

TEST(E1BigInt, DivmodScalar) {
    BigInt a(0x100000000ull); // 2^32
    auto r = a.divmod_scalar(2);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().first, BigInt(0x80000000ull));
    EXPECT_EQ(r.value().second, static_cast<Limb>(0));

    BigInt b(123456789012345ull);
    r = b.divmod_scalar(1000);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().first.mul(BigInt(1000)).value().add(BigInt(r.value().second)).value(), b);
    EXPECT_LT(static_cast<int>(r.value().second), 1000);
}

TEST(E1BigInt, KnuthDivmod) {
    // Multi-limb division
    BigInt a(0x100000000ull); // 2^32
    BigInt b(2);
    auto r = a.divmod(b);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().first, BigInt(0x80000000ull));
    EXPECT_TRUE(r.value().second.is_zero());

    // Large division
    auto rx = BigInt::from_decimal("340282366920938463463374607431768211455");
    ASSERT_TRUE(rx.ok());
    BigInt y(1000000);
    r = rx.value().divmod(y);
    ASSERT_TRUE(r.ok());
    auto check = r.value().first.mul(y).value().add(r.value().second).value();
    EXPECT_EQ(check, rx.value());
}

} // namespace

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}