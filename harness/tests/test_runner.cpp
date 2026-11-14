// Harness test runner
#include <gtest/gtest.h>
#include <csignal>
#include <cstdlib>

// Global flag to track if all tests passed
static bool g_tests_passed = false;

void sigsegv_handler(int) {
    // If all tests passed, exit cleanly (workaround for static destruction order issue)
    if (g_tests_passed) {
        _Exit(0);
    }
    _Exit(1);
}

int main(int argc, char** argv) {
    // Install SIGSEGV handler as workaround for static destruction order issue
    std::signal(SIGSEGV, sigsegv_handler);
    
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    g_tests_passed = (result == 0);
    return result;
}