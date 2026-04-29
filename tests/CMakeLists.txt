# Tachyon XDP Tunnel - Test Suite Build System
#
# Usage:
#   cmake -B build -S tests -DCMAKE_BUILD_TYPE=Debug
#   cmake --build build -j$(nproc)
#   ctest --test-dir build --output-on-failure
#
# Options:
#   -DBUILD_FUZZ_TESTS=ON      Build libFuzzer harnesses (requires clang)
#   -DBUILD_XDP_TESTS=ON       Build XDP test runner (requires libbpf)
#   -DBUILD_BENCHMARKS=ON      Build Google Benchmark harnesses
#   -DENABLE_COVERAGE=ON       Enable gcov coverage instrumentation
#   -DENABLE_SANITIZE=ON       Enable AddressSanitizer + UndefinedBehaviorSanitizer
#   -DENABLE_TSAN=ON           Enable ThreadSanitizer (incompatible with ENABLE_SANITIZE)

cmake_minimum_required(VERSION 3.16)
project(TachyonTests VERSION 1.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Options ──
option(BUILD_FUZZ_TESTS  "Build libFuzzer fuzz test harnesses" OFF)
option(BUILD_XDP_TESTS   "Build XDP/BPF test runner (requires libbpf)" OFF)
option(BUILD_BENCHMARKS  "Build Google Benchmark harnesses" OFF)
option(ENABLE_COVERAGE   "Enable code coverage instrumentation" OFF)
option(ENABLE_SANITIZE   "Enable AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(ENABLE_TSAN       "Enable ThreadSanitizer (incompatible with ENABLE_SANITIZE)" OFF)

# ── Project root (parent of tests/) ──
get_filename_component(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)

# ── Coverage flags ──
if(ENABLE_COVERAGE)
    if(ENABLE_SANITIZE)
        message(FATAL_ERROR "ENABLE_COVERAGE and ENABLE_SANITIZE are mutually exclusive")
    endif()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif()

# ── Sanitizer flags ──
if(ENABLE_SANITIZE)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        message(WARNING "Sanitizers work best with Clang or GCC")
    endif()
    if(ENABLE_TSAN)
        message(FATAL_ERROR "ENABLE_SANITIZE and ENABLE_TSAN are mutually exclusive")
    endif()
    set(SANITIZE_FLAGS
        "-fsanitize=address,undefined"
        "-fno-omit-frame-pointer"
        "-fno-sanitize-recover=undefined"
    )
    add_compile_options(${SANITIZE_FLAGS})
    add_link_options(${SANITIZE_FLAGS})
endif()

# ── ThreadSanitizer flags ──
if(ENABLE_TSAN)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        message(WARNING "ThreadSanitizer works best with Clang or GCC")
    endif()
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
    add_link_options(-fsanitize=thread)
endif()

# ── Google Test ──
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
    GIT_SHALLOW    TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()
include(GoogleTest)

# ── Find OpenSSL ──
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSL REQUIRED openssl>=3.0.0)

# ── Optional: post-quantum backend auto-detection ──
# Prefer native OpenSSL 3.5+ (ML-KEM built-in); else fall back to liboqs; else
# compile the stub backend so tests that skip-on-unavailable still link.
set(TACHYON_PQC_BACKEND "unavailable")
set(TACHYON_PQC_LIBS "")
set(TACHYON_PQC_INCLUDES "")
set(TACHYON_PQC_DEFINES "")

# OpenSSL 3.5+ has native ML-KEM via EVP_KEM — check version.
if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.5.0")
    set(TACHYON_PQC_BACKEND "openssl")
    list(APPEND TACHYON_PQC_DEFINES TACHYON_PQC_OPENSSL)
else()
    pkg_check_modules(LIBOQS liboqs)
    if(LIBOQS_FOUND)
        set(TACHYON_PQC_BACKEND "liboqs")
        list(APPEND TACHYON_PQC_DEFINES TACHYON_PQC_OQS)
        list(APPEND TACHYON_PQC_LIBS ${LIBOQS_LIBRARIES})
        list(APPEND TACHYON_PQC_INCLUDES ${LIBOQS_INCLUDE_DIRS})
    endif()
endif()

# ── tachyon_core static library ──
# Compiles all control-plane modules that don't pull in libbpf. Tests can link
# against this library and exercise every helper without needing kernel BPF.
add_library(tachyon_core STATIC
    ${PROJECT_ROOT}/loader/crypto.cpp
    ${PROJECT_ROOT}/loader/config.cpp
    ${PROJECT_ROOT}/loader/autoconf.cpp
    ${PROJECT_ROOT}/loader/padding.cpp
    ${PROJECT_ROOT}/loader/fingerprint.cpp
    ${PROJECT_ROOT}/loader/obfs.cpp
    ${PROJECT_ROOT}/loader/pqc.cpp
    ${PROJECT_ROOT}/loader/hybrid_kex.cpp
    ${PROJECT_ROOT}/loader/secmem.cpp
    ${PROJECT_ROOT}/loader/ratchet.cpp
    ${PROJECT_ROOT}/loader/transcript.cpp
    ${PROJECT_ROOT}/loader/replay.cpp
    ${PROJECT_ROOT}/loader/multipath.cpp
    ${PROJECT_ROOT}/loader/metrics.cpp
)

target_include_directories(tachyon_core PUBLIC
    ${PROJECT_ROOT}/loader
    ${PROJECT_ROOT}/src
    ${OPENSSL_INCLUDE_DIRS}
    ${TACHYON_PQC_INCLUDES}
)

target_link_libraries(tachyon_core PUBLIC ${OPENSSL_LIBRARIES} ${TACHYON_PQC_LIBS})

# Skip BPF includes - not needed for unit testing crypto/config
target_compile_definitions(tachyon_core PRIVATE
    TACHYON_VERSION="test"
    TACHYON_NO_BPF
    ${TACHYON_PQC_DEFINES}
)
target_compile_options(tachyon_core PRIVATE -Wall -Wextra)

# ── Helper function to add a unit test ──
function(add_tachyon_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE})
    target_link_libraries(${TEST_NAME} PRIVATE
        tachyon_core
        GTest::gtest_main
        GTest::gmock
    )
    target_include_directories(${TEST_NAME} PRIVATE
        ${PROJECT_ROOT}/loader
        ${PROJECT_ROOT}/src
    )
    target_compile_definitions(${TEST_NAME} PRIVATE TACHYON_NO_BPF)
    gtest_discover_tests(${TEST_NAME} PROPERTIES TIMEOUT 30)
endfunction()

# ── Unit Tests ──
add_tachyon_test(test_config      unit/test_config.cpp)
add_tachyon_test(test_crypto      unit/test_crypto.cpp)
add_tachyon_test(test_nonce_cache unit/test_nonce_cache.cpp)
add_tachyon_test(test_utils       unit/test_utils.cpp)
add_tachyon_test(test_protocol    unit/test_protocol.cpp)
add_tachyon_test(test_padding     unit/test_padding.cpp)
add_tachyon_test(test_fingerprint unit/test_fingerprint.cpp)
add_tachyon_test(test_obfs        unit/test_obfs.cpp)
add_tachyon_test(test_pqc         unit/test_pqc.cpp)
add_tachyon_test(test_secmem      unit/test_secmem.cpp)
add_tachyon_test(test_replay      unit/test_replay.cpp)
add_tachyon_test(test_transcript  unit/test_transcript.cpp)
add_tachyon_test(test_ratchet     unit/test_ratchet.cpp)
add_tachyon_test(test_hybrid_kex  unit/test_hybrid_kex.cpp)
add_tachyon_test(test_advanced    unit/test_advanced.cpp)
add_tachyon_test(test_phase23    unit/test_phase23.cpp)

# ── XDP Test Runner (requires libbpf + privileges) ──
if(BUILD_XDP_TESTS)
    pkg_check_modules(LIBBPF libbpf)
    if(NOT LIBBPF_FOUND)
        find_path(LIBBPF_INC bpf/libbpf.h PATHS /usr/include)
        if(LIBBPF_INC)
            set(LIBBPF_FOUND TRUE)
            set(LIBBPF_INCLUDE_DIRS ${LIBBPF_INC})
            set(LIBBPF_LIBRARIES bpf)
        endif()
    endif()
    if(LIBBPF_FOUND)
        add_executable(xdp_test_runner xdp/xdp_test_runner.cpp)
        target_include_directories(xdp_test_runner PRIVATE
            ${PROJECT_ROOT}/src ${LIBBPF_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIRS})
        target_link_libraries(xdp_test_runner PRIVATE
            GTest::gtest_main ${LIBBPF_LIBRARIES} ${OPENSSL_LIBRARIES} elf z)
        target_compile_definitions(xdp_test_runner PRIVATE
            XDP_OBJ_PATH="${PROJECT_ROOT}/src/xdp_core.o")
        add_test(NAME xdp_test_runner COMMAND xdp_test_runner)
        set_tests_properties(xdp_test_runner PROPERTIES
            LABELS "privileged" TIMEOUT 120)
    else()
        message(STATUS "libbpf not found - XDP tests disabled")
    endif()
endif()

# ── Google Benchmark harnesses ──
if(BUILD_BENCHMARKS)
    FetchContent_Declare(
        benchmark
        GIT_REPOSITORY https://github.com/google/benchmark.git
        GIT_TAG        v1.8.3
        GIT_SHALLOW    TRUE
    )
    set(BENCHMARK_ENABLE_TESTING    OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_INSTALL_DOCS      OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(benchmark)

    add_executable(bench_crypto benchmarks/bench_crypto.cpp)
    target_link_libraries(bench_crypto PRIVATE
        tachyon_core
        benchmark::benchmark_main
    )
    target_include_directories(bench_crypto PRIVATE
        ${PROJECT_ROOT}/loader
        ${PROJECT_ROOT}/src
    )
    target_compile_definitions(bench_crypto PRIVATE
        TACHYON_VERSION="bench"
        TACHYON_NO_BPF
    )
    target_compile_options(bench_crypto PRIVATE -O3 -Wall)
endif()

# ── Fuzz Tests (requires clang + libFuzzer) ──
if(BUILD_FUZZ_TESTS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(WARNING "Fuzz tests require clang compiler, skipping")
    else()
        add_executable(fuzz_config_parser fuzz/fuzz_config_parser.cpp)
        target_link_libraries(fuzz_config_parser PRIVATE tachyon_core)
        target_compile_options(fuzz_config_parser PRIVATE
            -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(fuzz_config_parser PRIVATE
            -fsanitize=fuzzer,address,undefined)

        add_executable(fuzz_crypto fuzz/fuzz_crypto.cpp)
        target_link_libraries(fuzz_crypto PRIVATE tachyon_core)
        target_compile_options(fuzz_crypto PRIVATE
            -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
        target_link_options(fuzz_crypto PRIVATE
            -fsanitize=fuzzer,address,undefined)
    endif()
endif()

# ── Summary ──
message(STATUS "")
message(STATUS "Tachyon Test Suite Configuration:")
message(STATUS "  Coverage:    ${ENABLE_COVERAGE}")
message(STATUS "  ASan+UBSan:  ${ENABLE_SANITIZE}")
message(STATUS "  TSan:        ${ENABLE_TSAN}")
message(STATUS "  XDP tests:   ${BUILD_XDP_TESTS}")
message(STATUS "  Fuzz tests:  ${BUILD_FUZZ_TESTS}")
message(STATUS "  Benchmarks:  ${BUILD_BENCHMARKS}")
message(STATUS "  PQC backend: ${TACHYON_PQC_BACKEND}")
message(STATUS "")
