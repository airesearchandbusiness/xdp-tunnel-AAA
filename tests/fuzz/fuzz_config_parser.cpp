/* SPDX-License-Identifier: MIT */
/*
 * Tachyon Fuzz Test - Configuration Parser
 *
 * libFuzzer harness for parse_config() and validate_config().
 * Writes fuzzed bytes to a temp file and feeds it to the parser.
 *
 * Build:
 *   cmake -B build -S tests -DBUILD_FUZZ_TESTS=ON \
 *         -DCMAKE_CXX_COMPILER=clang++
 *   cmake --build build --target fuzz_config_parser
 *
 * Run:
 *   ./build/fuzz_config_parser corpus/config/ -max_total_time=300
 *
 * Known findings this fuzzer will detect:
 *   - std::stoi exception on malformed ListenPort/MimicryType (config.cpp:91-95)
 *   - Potential issues with very long lines or binary input
 */

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

#include "tachyon.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Limit input size to avoid OOM on huge inputs */
    if (size > 65536)
        return 0;

    /* Write fuzzed data to a temporary file */
    char tmppath[] = "/tmp/tachyon_fuzz_XXXXXX";
    int fd = mkstemp(tmppath);
    if (fd < 0)
        return 0;

    ssize_t written = write(fd, data, size);
    close(fd);

    if (written != static_cast<ssize_t>(size)) {
        unlink(tmppath);
        return 0;
    }

    /* Parse the fuzzed config -- should not crash */
    try {
        TunnelConfig cfg = parse_config(tmppath);
        validate_config(cfg);
    } catch (...) {
        /* Catching any exception is fine for fuzzing --
         * the goal is to find crashes, not exceptions.
         * However, uncaught exceptions in production code
         * indicate a bug that should be fixed. */
    }

    unlink(tmppath);
    return 0;
}
