CXX      := g++
CXXFLAGS := -std=c++20 -pedantic -Wall -Wextra -Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2 -O3 -pthread -I../include -I../harness/include -I/home/nexuss0781/.local/include
SANFLAGS := -std=c++20 -pedantic -Wall -Wextra -Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -pthread -I../include -I../harness/include

# Use pkg-config for gtest flags if available
GTEST_LIBS := $(shell pkg-config --libs gtest gtest_main 2>/dev/null || echo "-L/tmp/googletest/build/lib -lgtest -lgtest_main")
GTEST_CFLAGS := $(shell pkg-config --cflags gtest 2>/dev/null || echo "-I/usr/local/include -I/tmp/googletest/googletest/include")

# E1 Foundation sources
E1_SRCS := \
    src/e1_bigint.cpp \
    src/e1_length.cpp \
    src/e1_sha256.cpp \
    src/e1_crc32.cpp \
    src/e1_gear.cpp

E1_OBJS := $(patsubst src/%.cpp,obj/%.o,$(E1_SRCS))

# Harness sources
HARNESS_SRCS := \
    ../harness/src/gates.cpp \
    ../harness/src/e0_selftest.cpp \
    ../harness/src/e1_gate.cpp \
    ../harness/src/e1_corpus.cpp \
    ../harness/src/e1_oracle.cpp \
    ../harness/src/main.cpp

HARNESS_OBJS := $(patsubst ../harness/src/%.cpp,obj/harness/%.o,$(HARNESS_SRCS))

# Test sources (relative to engine/ directory)
TEST_SRCS := \
    ../tests/test_runner.cpp \
    ../tests/e1_bigint_test.cpp \
    ../tests/e1_length_test.cpp \
    ../tests/e1_sha256_test.cpp \
    ../tests/e1_crc32_test.cpp \
    ../tests/e1_gear_test.cpp

TEST_OBJS := $(patsubst ../tests/%.cpp,obj/tests/%.o,$(TEST_SRCS))

# Harness test sources
HARNESS_TEST_SRCS := \
    ../harness/tests/harness_gates_test.cpp \
    ../harness/tests/e1_oracle_test.cpp

HARNESS_TEST_OBJS := $(patsubst ../harness/tests/%.cpp,obj/harness_tests/%.o,$(HARNESS_TEST_SRCS))

LIB_OBJS := $(E1_OBJS)

.PHONY: all clean test test-san e1-test harness-test

all: bin/mapr_tests bin/mapr_gate bin/harness_tests

obj/%.o: src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(GTEST_CFLAGS) -c $< -o $@

obj/harness/%.o: ../harness/src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(GTEST_CFLAGS) -c $< -o $@

obj/tests/%.o: ../tests/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(GTEST_CFLAGS) -c $< -o $@

obj/harness_tests/%.o: ../harness/tests/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(GTEST_CFLAGS) -c $< -o $@

# Only build the test binary for E1
bin/mapr_tests: $(LIB_OBJS) $(TEST_OBJS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o bin/mapr_tests $(LIB_OBJS) $(TEST_OBJS) $(GTEST_LIBS) -lz -lpthread

bin/mapr_tests_san: $(E1_SRCS) $(TEST_SRCS)
	@mkdir -p bin
	$(CXX) $(SANFLAGS) -o bin/mapr_tests_san $(E1_SRCS) $(TEST_SRCS) $(GTEST_LIBS) -lz -lpthread

# Gate runner binary
bin/mapr_gate: $(LIB_OBJS) $(HARNESS_OBJS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o bin/mapr_gate $(LIB_OBJS) $(HARNESS_OBJS) -lz -lpthread

# Harness test binary
bin/harness_tests: $(LIB_OBJS) $(HARNESS_OBJS) $(HARNESS_TEST_OBJS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o bin/harness_tests $(LIB_OBJS) $(HARNESS_OBJS) $(HARNESS_TEST_OBJS) $(GTEST_LIBS) -lz -lpthread

# Harness test with sanitizer
bin/harness_tests_san: $(E1_SRCS) $(HARNESS_SRCS) $(HARNESS_TEST_SRCS)
	@mkdir -p bin
	$(CXX) $(SANFLAGS) -o bin/harness_tests_san $(E1_SRCS) $(HARNESS_SRCS) $(HARNESS_TEST_SRCS) $(GTEST_LIBS) -lz -lpthread

test: bin/mapr_tests
	./bin/mapr_tests

test-san: bin/mapr_tests_san
	./bin/mapr_tests_san

harness-test: bin/harness_tests
	./bin/harness_tests

harness-test-san: bin/harness_tests_san
	./bin/harness_tests_san

e1-test: bin/mapr_tests
	./bin/mapr_tests

clean:
	rm -rf obj bin