// Authored transport for bounded resolver policy, never an OS module provider.
#include "ts2/guest_resolver.hpp"
#include "ts2/guest_memory.hpp"
#include <iostream>
#include <vector>

namespace {
constexpr uint32_t name = 0xc1234567u, prefix = 0xa0e06e20u;
struct Provider : ts2::CheckedGuestLoaderServices, ts2::GuestExportServices {
    using CheckedGuestLoaderServices::CheckedGuestLoaderServices;
    std::array<std::array<uint32_t, 3>, 2> responses{};
    std::array<unsigned, 2> attempts{};
    unsigned active = 0;
    uint32_t result = 0;
    std::vector<std::array<uint32_t, 4>> calls;
    uint32_t load(uint32_t n, uint32_t file, uint32_t flags) override {
        if (n != name && n != name + 128) throw std::runtime_error("name");
        active = n == name ? 0 : 1;
        if (attempts[active] >= 2) throw std::runtime_error("budget");
        calls.push_back({1, n, file, flags});
        return responses[active][attempts[active]++ == 0 ? 0 : 2];
    }
    uint32_t last_error() override {
        calls.push_back({2, 0, 0, 0});
        return responses[active][1];
    }
    uint32_t lookup(uint32_t module, uint32_t n) override {
        calls.push_back({3, module, n, 0});
        return result;
    }
};
uint32_t word(uint64_t limit = UINT32_MAX) {
    uint64_t v;
    if (!(std::cin >> v) || v > limit) throw std::runtime_error("word");
    return static_cast<uint32_t>(v);
}
}
int main() {
    try {
        unsigned count = 0;
        while (true) {
            std::cin >> std::ws;
            if (std::cin.eof()) break;
            if (++count > 4096) return 2;
            ts2::GuestMemory m;
            Provider p(m);
            const auto page = m.page_size();
            const uint32_t cache = 0xb1000000u;
            m.commit(cache, page);
            ts2::GuestResolverSlots slots{cache, {{{cache + 4, name}, {cache + 8, name + 128}}}};
            m.write32(cache + 4, word()); m.write32(cache + 8, word());
            for (auto& response : p.responses)
                for (auto& v : response) v = word();
            p.result = word();
            const auto n0 = word(16), n1 = word(16), np = word(16);
            const std::array<uint32_t, 3> addresses{name, name + 128, prefix};
            const std::array<uint32_t, 3> lengths{n0, n1, np};
            m.commit(name - name % page, page);
            m.commit(prefix - prefix % page, page);
            for (unsigned side = 0; side < 3; ++side) {
                std::vector<uint8_t> bytes;
                for (uint32_t i = 0; i < lengths[side]; ++i) {
                    const auto v = word(65535);
                    bytes.push_back(static_cast<uint8_t>(v));
                    bytes.push_back(static_cast<uint8_t>(v >> 8));
                }
                m.write_bytes(addresses[side], bytes);
            }
            std::array<std::vector<uint8_t>, 3> snapshots;
            const std::array<uint32_t, 3> pages{cache,
                static_cast<uint32_t>(name - name % page),
                static_cast<uint32_t>(prefix - prefix % page)};
            for (unsigned side = 0; side < pages.size(); ++side)
                for (size_t i = 0; i < page; ++i)
                    snapshots[side].push_back(m.read8(pages[side] + static_cast<uint32_t>(i)));
            const auto result = ts2::legacy_resolve_two(m, slots, name, p, p);
            // No callbacks at all may occur during a cached reentry.
            const auto before = p.calls.size();
            ts2::GuestLoaderServices missing_loader;
            ts2::GuestExportServices missing_exports;
            auto unreachable = slots;
            unreachable.candidates = {{{0, 0}, {0, 0}}};
            const auto again = ts2::legacy_resolve_two(m, unreachable, 0,
                                                      missing_loader, missing_exports);
            if (p.calls.size() != before) return 2;
            for (unsigned side = 0; side < pages.size(); ++side)
                for (size_t i = side == 0 ? 12 : 0; i < page; ++i)
                    if (m.read8(pages[side] + static_cast<uint32_t>(i)) != snapshots[side][i])
                        throw std::runtime_error("unexpected memory write");
            std::cout << result << ' ' << m.read32(cache) << ' ' << m.read32(cache + 4)
                      << ' ' << m.read32(cache + 8) << ' ' << again << ' ' << p.calls.size();
            for (const auto& call : p.calls)
                for (auto v : call) std::cout << ' ' << v;
            std::cout << '\n';
        }
        if (count == 0) return 2;
    } catch (const std::exception&) { return 2; }
}
