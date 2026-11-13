cmake_minimum_required(VERSION 3.20)
project(mapr VERSION 1.0.1 LANGUAGES C CXX)

# ──────────────────────────────────────────────────────────────
# Policies
# ──────────────────────────────────────────────────────────────
cmake_policy(SET CMP0077 NEW)  # option() honors normal variables
cmake_policy(SET CMP0091 NEW)  # FILE_SET for headers

# ──────────────────────────────────────────────────────────────
# Options
# ──────────────────────────────────────────────────────────────
option(MAPR_BUILD_SHARED      "Build shared library"        ON)
option(MAPR_BUILD_STATIC      "Build static library"        ON)
option(MAPR_BUILD_TOOLS       "Build CLI tools (mapr)"      ON)
option(MAPR_BUILD_TESTS       "Build tests"                 ON)
option(MAPR_BUILD_SIMD        "Build SIMD kernels"          ON)
option(MAPR_FUZZING           "Enable fuzzing builds"       OFF)
option(MAPR_SANITIZERS        "Enable sanitizers (ASan/UBSan/MSan/TSan)" OFF)

# ──────────────────────────────────────────────────────────────
# C++ Standard
# ──────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ──────────────────────────────────────────────────────────────
# Compile Options
# ──────────────────────────────────────────────────────────────

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(BASE_WARNINGS
        -Wall -Wextra -Wpedantic
        -Wcast-align -Wcast-qual -Wconversion
        -Wdouble-promotion -Wfloat-equal -Wformat=2
        -Wnull-dereference -Wshadow -Wsign-conversion
        -Wundef -Wunused -Wwrite-strings
    )
    add_compile_options(${BASE_WARNINGS})
else()
    add_compile_options(/W4 /permissive-)
endif()

# Release optimizations
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG")

# Sanitizers
if(MAPR_SANITIZERS AND NOT MSVC)
    set(SANITIZER_FLAGS "-fsanitize=address,undefined -fno-omit-frame-pointer")
    if(NOT MAPR_FUZZING)
        set(SANITIZER_FLAGS "${SANITIZER_FLAGS} -fsanitize=memory")
    endif()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SANITIZER_FLAGS}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SANITIZER_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${SANITIZER_FLAGS}")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${SANITIZER_FLAGS}")
endif()

# Fuzzing
if(MAPR_FUZZING)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=fuzzer-no-link")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=fuzzer-no-link")
endif()

# ──────────────────────────────────────────────────────────────
# SIMD Kernel Compilation
# ──────────────────────────────────────────────────────────────
set(MAPR_SIMD_SOURCES "")  # Default empty, populated if MAPR_BUILD_SIMD=ON
if(MAPR_BUILD_SIMD)
    # Baseline: x86-64-v2 (SSE4.2, POPCNT)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse4.2 -mpopcnt")
    endif()

    # SIMD sources compiled with appropriate flags per ISA
    set(MAPR_SIMD_SOURCES
        src/simd/dispatch.cpp
        src/simd/kernels_avx2.cpp
        src/simd/kernels_avx512.cpp
        src/simd/kernels_sha256_avx2.cpp
        src/simd/kernels_sha256_avx512.cpp
    )

    # Compile AVX2 kernels with AVX2 flags
    set_source_files_properties(src/simd/kernels_avx2.cpp PROPERTIES
        COMPILE_FLAGS "-mavx2 -mfma -mbmi2 -mbmi -mpopcnt -DLIBMAPR_AVX2"
    )
    set_source_files_properties(src/simd/kernels_sha256_avx2.cpp PROPERTIES
        COMPILE_FLAGS "-mavx2 -mfma -mbmi2 -mbmi -mpopcnt -msha -DLIBMAPR_AVX2"
    )

    # Compile AVX-512 kernels with AVX-512 flags
    set_source_files_properties(src/simd/kernels_avx512.cpp PROPERTIES
        COMPILE_FLAGS "-mavx512f -mavx512vl -mavx512bw -mavx512dq -mavx512vbmi -mavx512cd -mavx512vpopcntdq -DLIBMAPR_AVX512"
    )
    set_source_files_properties(src/simd/kernels_sha256_avx512.cpp PROPERTIES
        COMPILE_FLAGS "-mavx512f -mavx512vl -mavx512bw -mavx512dq -mavx512vbmi -mavx512cd -mavx512vpopcntdq -msha -DLIBMAPR_AVX512"
    )

    # Compile NEON kernels with ARM NEON flags (only on ARM)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|arm")
        list(APPEND MAPR_SIMD_SOURCES src/simd/kernels_neon.cpp)
        list(APPEND MAPR_SIMD_SOURCES src/simd/kernels_sha256_neon.cpp)
        set_source_files_properties(src/simd/kernels_neon.cpp PROPERTIES
            COMPILE_FLAGS "-march=armv8-a+simd -DLIBMAPR_NEON"
        )
        set_source_files_properties(src/simd/kernels_sha256_neon.cpp PROPERTIES
            COMPILE_FLAGS "-march=armv8-a+simd+crypto -DLIBMAPR_NEON"
        )
    endif()
endif()

# ──────────────────────────────────────────────────────────────
# Include Directories
# ──────────────────────────────────────────────────────────────
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# ──────────────────────────────────────────────────────────────
# Source Files
# ──────────────────────────────────────────────────────────────

# Core library sources
set(MAPR_CORE_SOURCES
    src/crypto.cpp
    src/bitseq.cpp
    src/math_core.cpp
    src/dag.cpp
    src/container.cpp
    src/encoder.cpp
    src/decoder.cpp
    src/pipeline.cpp
)

# New API/runtime sources
set(MAPR_API_SOURCES
    src/api/mapr_api.cpp
    src/hwprobe/hwprobe.cpp
    src/runtime/thread_pool.cpp
    src/runtime/profile.cpp
    src/runtime/chunk_analyzer.cpp
)

# All library sources (SIMD sources appended in SIMD block above)
set(MAPR_LIB_SOURCES ${MAPR_CORE_SOURCES} ${MAPR_API_SOURCES} ${MAPR_SIMD_SOURCES})

# ──────────────────────────────────────────────────────────────
# Library Targets
# ──────────────────────────────────────────────────────────────

if(MAPR_BUILD_SHARED)
    add_library(mapr_lib SHARED ${MAPR_LIB_SOURCES})
    target_include_directories(mapr_lib PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    target_compile_definitions(mapr_lib PRIVATE MAPR_BUILD_DLL)
    set_target_properties(mapr_lib PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        POSITION_INDEPENDENT_CODE ON
        OUTPUT_NAME mapr
        C_VISIBILITY_PRESET default
        CXX_VISIBILITY_PRESET default
    )
endif()

if(MAPR_BUILD_STATIC)
    add_library(mapr_static STATIC ${MAPR_LIB_SOURCES})
    target_include_directories(mapr_static PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    set_target_properties(mapr_static PROPERTIES
        POSITION_INDEPENDENT_CODE ON
    )
endif()

# Common link libraries
if(UNIX AND NOT APPLE)
    target_link_libraries(mapr_lib PUBLIC pthread dl m)
    target_link_libraries(mapr_static PUBLIC pthread dl m)
elseif(APPLE)
    target_link_libraries(mapr_lib PUBLIC pthread m)
    target_link_libraries(mapr_static PUBLIC pthread m)
elseif(WIN32)
    target_link_libraries(mapr_lib PUBLIC ws2_32)
    target_link_libraries(mapr_static PUBLIC ws2_32)
endif()

# ──────────────────────────────────────────────────────────────
# CLI Tool
# ──────────────────────────────────────────────────────────────
if(MAPR_BUILD_TOOLS)
    add_executable(mapr_cli src/main.cpp)
    if(MAPR_BUILD_SHARED)
        target_link_libraries(mapr_cli PRIVATE mapr_lib)
    else()
        target_link_libraries(mapr_cli PRIVATE mapr_static)
    endif()
    set_target_properties(mapr_cli PROPERTIES OUTPUT_NAME mapr)
endif()

# ──────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────
if(MAPR_BUILD_TESTS)
    enable_testing()

    add_executable(mapr_tests tests/test_suite.cpp)
    if(MAPR_BUILD_SHARED)
        target_link_libraries(mapr_tests PRIVATE mapr_lib)
    else()
        target_link_libraries(mapr_tests PRIVATE mapr_static)
    endif()

    add_test(NAME mapr_unit_tests COMMAND mapr_tests)

    # Sanitizer test build
    if(MAPR_SANITIZERS)
        add_executable(mapr_tests_san tests/test_suite.cpp ${MAPR_LIB_SOURCES})
        target_compile_options(mapr_tests_san PRIVATE ${SANITIZER_FLAGS})
        target_link_libraries(mapr_tests_san PRIVATE ${SANITIZER_FLAGS})
        add_test(NAME mapr_tests_asan COMMAND mapr_tests_san)
    endif()
endif()

# ──────────────────────────────────────────────────────────────
# Fuzzing (libFuzzer)
# ──────────────────────────────────────────────────────────────
if(MAPR_FUZZING)
    message(STATUS "Building libFuzzer targets...")
    
    # Find libFuzzer library
    find_library(LIBFUZZER_LIB fuzzer)
    if(NOT LIBFUZZER_LIB)
        # Try compiler-rt
        find_library(LIBFUZZER_LIB clang_rt.fuzzer)
    endif()
    if(NOT LIBFUZZER_LIB)
        # On some systems it's linked automatically with -fsanitize=fuzzer
        set(LIBFUZZER_LIB "")
    endif()

    # Fuzzer common sources
    set(FUZZ_COMMON_SOURCES
        fuzz/fuzz_container.cpp
        fuzz/fuzz_decoder.cpp
        fuzz/fuzz_encoder.cpp
        fuzz/fuzz_math.cpp
    )

    # Container fuzzer
    add_executable(fuzz_container fuzz/fuzz_container.cpp)
    target_link_libraries(fuzz_container PRIVATE mapr_static ${LIBFUZZER_LIB})
    if(LIBFUZZER_LIB)
        set_target_properties(fuzz_container PROPERTIES COMPILE_FLAGS "-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer")
        set_target_properties(fuzz_container PROPERTIES LINK_FLAGS "-fsanitize=fuzzer,address,undefined")
    else()
        target_compile_options(fuzz_container PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(fuzz_container PRIVATE -fsanitize=fuzzer,address,undefined)
    endif()

    # Decoder fuzzer
    add_executable(fuzz_decoder fuzz/fuzz_decoder.cpp)
    target_link_libraries(fuzz_decoder PRIVATE mapr_static ${LIBFUZZER_LIB})
    if(LIBFUZZER_LIB)
        set_target_properties(fuzz_decoder PROPERTIES COMPILE_FLAGS "-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer")
        set_target_properties(fuzz_decoder PROPERTIES LINK_FLAGS "-fsanitize=fuzzer,address,undefined")
    else()
        target_compile_options(fuzz_decoder PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(fuzz_decoder PRIVATE -fsanitize=fuzzer,address,undefined)
    endif()

    # Encoder fuzzer
    add_executable(fuzz_encoder fuzz/fuzz_encoder.cpp)
    target_link_libraries(fuzz_encoder PRIVATE mapr_static ${LIBFUZZER_LIB})
    if(LIBFUZZER_LIB)
        set_target_properties(fuzz_encoder PROPERTIES COMPILE_FLAGS "-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer")
        set_target_properties(fuzz_encoder PROPERTIES LINK_FLAGS "-fsanitize=fuzzer,address,undefined")
    else()
        target_compile_options(fuzz_encoder PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(fuzz_encoder PRIVATE -fsanitize=fuzzer,address,undefined)
    endif()

    # Math core fuzzer
    add_executable(fuzz_math fuzz/fuzz_math.cpp)
    target_link_libraries(fuzz_math PRIVATE mapr_static ${LIBFUZZER_LIB})
    if(LIBFUZZER_LIB)
        set_target_properties(fuzz_math PROPERTIES COMPILE_FLAGS "-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer")
        set_target_properties(fuzz_math PROPERTIES LINK_FLAGS "-fsanitize=fuzzer,address,undefined")
    else()
        target_compile_options(fuzz_math PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(fuzz_math PRIVATE -fsanitize=fuzzer,address,undefined)
    endif()

    # Combined fuzzer (all-in-one for OSS-Fuzz)
    add_executable(fuzz_all
        fuzz/fuzz_container.cpp
        fuzz/fuzz_decoder.cpp
        fuzz/fuzz_encoder.cpp
        fuzz/fuzz_math.cpp
    )
    target_link_libraries(fuzz_all PRIVATE mapr_static ${LIBFUZZER_LIB})
    if(LIBFUZZER_LIB)
        set_target_properties(fuzz_all PROPERTIES COMPILE_FLAGS "-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer")
        set_target_properties(fuzz_all PROPERTIES LINK_FLAGS "-fsanitize=fuzzer,address,undefined")
    else()
        target_compile_options(fuzz_all PRIVATE -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(fuzz_all PRIVATE -fsanitize=fuzzer,address,undefined)
    endif()

    message(STATUS "Fuzzing targets: fuzz_container, fuzz_decoder, fuzz_encoder, fuzz_math, fuzz_all")
endif()

# ──────────────────────────────────────────────────────────────
# Sanitizer-only builds (without fuzzing)
# ──────────────────────────────────────────────────────────────
if(MAPR_SANITIZERS AND NOT MAPR_FUZZING)
    message(STATUS "Building with sanitizers: ASan, UBSan, MSan")
    
    # ASan + UBSan build
    add_executable(mapr_asan tests/test_suite.cpp ${MAPR_LIB_SOURCES})
    target_compile_options(mapr_asan PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(mapr_asan PRIVATE -fsanitize=address,undefined)
    add_test(NAME mapr_asan_test COMMAND mapr_asan)

    # MSan build (memory sanitizer - no ASan)
    add_executable(mapr_msan tests/test_suite.cpp ${MAPR_LIB_SOURCES})
    target_compile_options(mapr_msan PRIVATE -fsanitize=memory -fno-omit-frame-pointer -fsanitize-memory-track-origins)
    target_link_options(mapr_msan PRIVATE -fsanitize=memory)
    add_test(NAME mapr_msan_test COMMAND mapr_msan)

    # TSan build (thread sanitizer)
    add_executable(mapr_tsan tests/test_suite.cpp ${MAPR_LIB_SOURCES})
    target_compile_options(mapr_tsan PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
    target_link_options(mapr_tsan PRIVATE -fsanitize=thread)
    add_test(NAME mapr_tsan_test COMMAND mapr_tsan)

    message(STATUS "Sanitizer targets: mapr_asan, mapr_msan, mapr_tsan")
endif()

# ──────────────────────────────────────────────────────────────
# Installation
# ──────────────────────────────────────────────────────────────

install(DIRECTORY include/mapr/
        DESTINATION include/mapr
        FILES_MATCHING PATTERN "*.h"
        PATTERN ".git*" EXCLUDE)

if(MAPR_BUILD_SHARED)
    install(TARGETS mapr_lib
        EXPORT mapr-targets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include
    )
endif()

if(MAPR_BUILD_STATIC)
    install(TARGETS mapr_static
        EXPORT mapr-targets
        ARCHIVE DESTINATION lib
    )
endif()

if(MAPR_BUILD_TOOLS)
    install(TARGETS mapr_cli
        RUNTIME DESTINATION bin
    )
endif()

# CMake config for find_package()
# Generate config file from template
configure_file(
    ${CMAKE_SOURCE_DIR}/packaging/cmake/mapr-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/mapr-config.cmake
    @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/mapr-config.cmake
    DESTINATION lib/cmake/mapr
)

install(EXPORT mapr-targets
    FILE mapr-targets.cmake
    DESTINATION lib/cmake/mapr
)

# Version config
include(CMakePackageConfigHelpers)
configure_file(
    ${CMAKE_SOURCE_DIR}/packaging/cmake/mapr-config-version.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/mapr-config-version.cmake
    @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/mapr-config-version.cmake
    DESTINATION lib/cmake/mapr
)

# ──────────────────────────────────────────────────────────────
# Packaging (CPack)
# ──────────────────────────────────────────────────────────────
set(CPACK_PACKAGE_NAME "mapr")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "MAPR Compression Library")
set(CPACK_PACKAGE_VENDOR "nexuss0781")
set(CPACK_PACKAGE_CONTACT "https://github.com/nexuss0781/MARP")
set(CPACK_GENERATOR "TGZ;ZIP")
set(CPACK_SOURCE_GENERATOR "TGZ;ZIP")

include(CPack)