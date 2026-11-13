CXX      := g++
CXXFLAGS := -std=c++20 -pedantic -Wall -Wextra -Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2 -O3 -pthread -I../include
SANFLAGS := -std=c++20 -pedantic -Wall -Wextra -Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -pthread -I../include

# Use pkg-config for gtest flags if available
GTEST_CFLAGS := $(shell pkg-config --cflags gtest 2>/dev/null || echo "-I/usr/local/include")
GTEST_LIBS := $(shell pkg-config --libs gtest gtest_main 2>/dev/null || echo "-L/usr/local/lib -lgtest -lgtest_main")

# E1 Foundation sources
E1_SRCS := \
    src/e1_bigint.cpp \
    src/e1_length.cpp \
    src/e1_sha256.cpp \
    src/e1_crc32.cpp \
    src/e1_gear.cpp

E1_OBJS := $(patsubst src/%.cpp,obj/%.o,$(E1_SRCS))

# Test sources (relative to engine/ directory)
TEST_SRCS := \
    ../tests/test_runner.cpp \
    ../tests/e1_bigint_test.cpp \
    ../tests/e1_length_test.cpp \
    ../tests/e1_sha256_test.cpp \
    ../tests/e1_crc32_test.cpp \
    ../tests/e1_gear_test.cpp

TEST_OBJS := $(patsubst ../tests/%.cpp,obj/tests/%.o,$(TEST_SRCS))

LIB_OBJS := $(E1_OBJS)

.PHONY: all clean test test-san e1-test

all: bin/mapr_tests

obj/%.o: src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(GTEST_CFLAGS) -c $< -o $@

obj/tests/%.o: ../tests/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(GTEST_CFLAGS) -c $< -o $@

# Only build the test binary for E1
bin/mapr_tests: $(LIB_OBJS) $(TEST_OBJS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o bin/mapr_tests $(LIB_OBJS) $(TEST_OBJS) $(GTEST_LIBS) -lz -lpthread

bin/mapr_tests_san: $(E1_SRCS) $(TEST_SRCS)
	@mkdir -p bin
	$(CXX) $(SANFLAGS) -o bin/mapr_tests_san $(E1_SRCS) $(TEST_SRCS) $(GTEST_LIBS) -lz -lpthread

test: bin/mapr_tests
	./bin/mapr_tests

test-san: bin/mapr_tests_san
	./bin/mapr_tests_san

e1-test: bin/mapr_tests
	./bin/mapr_tests

clean:
	rm -rf obj bin