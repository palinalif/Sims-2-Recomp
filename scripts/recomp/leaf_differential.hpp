// Authored bounded comparison transport; no original-game code or states.
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>

namespace ts2_probe {
constexpr size_t page_bytes = 6 * 4096;
constexpr size_t record_bytes = 8 * 4 + page_bytes;
constexpr size_t cases = 64;
using Execute = void (*)(uint32_t*, unsigned char*);
struct Result { unsigned matched{}; bool complete{}; };
inline uint32_t word(const unsigned char* p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
// The private lifter globals and bridge are single-owner, even across JNI calls.
inline Result check(const unsigned char* input, size_t input_size,
                    const unsigned char* expected, size_t expected_size, Execute execute) {
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);
    Result result;
    if (!input || !expected || !execute || input_size != cases * record_bytes ||
        expected_size != input_size) return result;
    try {
        for (size_t n = 0; n < cases; ++n) {
            const auto* in = input + n * record_bytes;
            const auto* out = expected + n * record_bytes;
            std::array<uint32_t, 8> regs{};
            std::array<unsigned char, page_bytes> pages{};
            for (size_t r = 0; r < regs.size(); ++r) regs[r] = word(in + r * 4);
            std::memcpy(pages.data(), in + 32, page_bytes);
            execute(regs.data(), pages.data());
            bool equal = std::memcmp(pages.data(), out + 32, page_bytes) == 0;
            for (size_t r = 0; r < regs.size(); ++r) equal &= regs[r] == word(out + r * 4);
            if (equal) ++result.matched;
        }
        result.complete = true;
    } catch (...) { /* Any bridge rejection is an incomplete failure, not a match. */ }
    return result;
}
}
