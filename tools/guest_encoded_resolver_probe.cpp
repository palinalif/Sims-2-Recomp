// Authored bounded transport; no Windows APIs or original code included.
#include "ts2/guest_encoded_resolver.hpp"
#include "ts2/guest_memory.hpp"
#include <array>
#include <iostream>
#include <vector>
namespace {
constexpr uint32_t cache = 0xb1000000u, name = 0xc1234567u;
struct Provider : ts2::GuestLoaderServices, ts2::GuestExportServices {
    std::array<std::array<uint32_t, 5>, 2> responses{};
    std::array<unsigned, 2> loads{}, comparisons{};
    unsigned active = 0;
    uint32_t result = 0;
    std::vector<std::array<uint32_t, 4>> calls;
    uint32_t load(uint32_t n, uint32_t file, uint32_t flags) override {
        if (n != name && n != name + 128) throw std::runtime_error("name");
        active = n == name ? 0 : 1;
        if (loads[active] >= 2) throw std::runtime_error("load budget");
        calls.push_back({1, n, file, flags});
        return responses[active][loads[active]++ == 0 ? 0 : 4];
    }
    uint32_t last_error() override {
        calls.push_back({2, 0, 0, 0}); return responses[active][1];
    }
    uint32_t compare(uint32_t a, uint32_t b, uint32_t n) override {
        if (comparisons[active] >= 2) throw std::runtime_error("compare budget");
        calls.push_back({4, a, b, n}); return responses[active][2 + comparisons[active]++];
    }
    uint32_t lookup(uint32_t module, uint32_t n) override {
        calls.push_back({3, module, n, 0}); return result;
    }
};
uint32_t word(uint32_t max = UINT32_MAX) {
    uint64_t v;
    if (!(std::cin >> v) || v > max) throw std::runtime_error("input");
    return static_cast<uint32_t>(v);
}
}
int main() {
    try {
        ts2::GuestMemory m;
        m.commit(cache, m.page_size());
        unsigned count = 0;
        while (true) {
            std::cin >> std::ws;
            if (std::cin.eof()) break;
            if (++count > 8192) return 2;
            Provider p;
            const auto cookie = word(), length = word(2);
            const std::array<ts2::GuestResolverCandidate, 2> candidates{{{cache+8,name},{cache+12,name+128}}};
            m.write32(cache,cookie); m.write32(cache+4,ts2::guest_encode_pointer(0,cookie));
            m.write32(cache+8,word()); m.write32(cache+12,word());
            for (auto& row : p.responses) for (auto& v : row) v = word();
            p.result = word();
            std::vector<uint8_t> before;
            for (size_t i=16; i<m.page_size(); ++i) before.push_back(m.read8(cache+static_cast<uint32_t>(i)));
            const auto value = ts2::legacy_resolve_encoded(m,cache,cache+4,
                std::span(candidates).first(length),name,p,p);
            ts2::GuestLoaderServices absent; ts2::GuestExportServices no_export;
            // Deliberately invalid cold layout: hot reentry must ignore it.
            const std::array<ts2::GuestResolverCandidate,1> bad{{{0,0}}};
            const auto again = ts2::legacy_resolve_encoded(m,cache,cache+4,bad,0,absent,no_export);
            if (m.read32(cache) != cookie) return 2;
            for (size_t i=16; i<m.page_size(); ++i)
                if (m.read8(cache+static_cast<uint32_t>(i)) != before[i-16]) return 2;
            std::cout << value << ' ' << m.read32(cache+4) << ' ' << m.read32(cache+8)
                      << ' ' << m.read32(cache+12) << ' ' << again << ' ' << p.calls.size();
            for (const auto& call : p.calls) for (auto v : call) std::cout << ' ' << v;
            std::cout << '\n';
        }
        return count ? 0 : 2;
    } catch (const std::exception&) { return 2; }
}
