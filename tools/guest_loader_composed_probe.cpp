// Authored composition transport; load/error responses are not Windows services.
#include "ts2/guest_loader_policy.hpp"
#include "ts2/guest_memory.hpp"
#include <array>
#include <iostream>
#include <vector>

namespace {
struct Provider : ts2::CheckedGuestLoaderServices {
    using CheckedGuestLoaderServices::CheckedGuestLoaderServices;
    std::array<uint32_t, 3> responses{};
    std::vector<std::array<uint32_t, 4>> calls;
    unsigned loads = 0;
    uint32_t load(uint32_t name, uint32_t file, uint32_t flags) override {
        if (loads >= 2) throw std::runtime_error("load budget");
        calls.push_back({1, name, file, flags});
        return responses[loads++ == 0 ? 0 : 2];
    }
    uint32_t last_error() override {
        calls.push_back({2, 0, 0, 0});
        return responses[1];
    }
};
uint32_t word(uint64_t limit = UINT32_MAX) {
    uint64_t v;
    if (!(std::cin >> v) || v > limit) throw std::runtime_error("invalid word");
    return static_cast<uint32_t>(v);
}
}
int main() {
    try {
        unsigned cases = 0;
        while (true) {
            std::cin >> std::ws;
            if (std::cin.eof()) break;
            if (++cases > 4096) return 2;
            ts2::GuestMemory m;
            Provider p(m);
            for (auto& v : p.responses) v = word();
            const auto nl = word(16), nr = word(16);
            const uint32_t addresses[]{0xc1234567u, 0xa0e06e20u};
            const uint32_t lengths[]{nl, nr};
            std::vector<uint8_t> before[2];
            for (unsigned side = 0; side < 2; ++side) {
                std::vector<uint8_t> bytes;
                for (uint32_t n = 0; n < lengths[side]; ++n) {
                    const auto v = word(65535);
                    bytes.push_back(static_cast<uint8_t>(v));
                    bytes.push_back(static_cast<uint8_t>(v >> 8));
                }
                if (bytes.empty()) continue; // deliberately unmapped operand
                const auto base = addresses[side] - addresses[side] % m.page_size();
                m.commit(base, m.page_size());
                m.write_bytes(addresses[side], bytes);
                for (size_t n = 0; n < m.page_size(); ++n)
                    before[side].push_back(m.read8(base + static_cast<uint32_t>(n)));
            }
            const auto result = ts2::legacy_loader_policy(addresses[0], p);
            for (unsigned side = 0; side < 2; ++side) {
                const auto base = addresses[side] - addresses[side] % m.page_size();
                for (size_t n = 0; n < before[side].size(); ++n)
                    if (m.read8(base + static_cast<uint32_t>(n)) != before[side][n])
                        throw std::runtime_error("input modified");
            }
            std::cout << result << ' ' << p.calls.size();
            for (const auto& call : p.calls)
                for (auto v : call) std::cout << ' ' << v;
            std::cout << '\n';
        }
        if (cases == 0) return 2;
    } catch (const std::exception&) { return 2; }
}
