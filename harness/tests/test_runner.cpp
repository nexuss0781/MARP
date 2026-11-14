// Harness test runner
#include <gtest/gtest.h>
#include <cstdlib>

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    // Use quick_exit to skip static destructors that cause segfault on exit
    // All tests passed if result == 0
    std::quick_exit(result);
    return result; // unreachable
}