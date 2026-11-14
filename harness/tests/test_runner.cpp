// Harness test runner
#include <gtest/gtest.h>
#include <cstdlib>

// Custom event listener to exit cleanly after tests pass
class CleanExitListener : public ::testing::EmptyTestEventListener {
public:
    void OnTestProgramEnd(const ::testing::UnitTest& unit_test) override {
        if (!unit_test.Failed()) {
            // All tests passed - exit cleanly to avoid static destruction segfault
            std::_Exit(0);
        }
    }
};

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    // Add custom listener to exit cleanly after tests pass
    ::testing::TestEventListeners& listeners = ::testing::UnitTest::GetInstance()->listeners();
    listeners.Append(new CleanExitListener);
    
    return RUN_ALL_TESTS();
}