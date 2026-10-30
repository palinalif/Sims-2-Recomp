#include "ts2/guest_loader_policy.hpp"
#include "ts2/guest_memory.hpp"
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)
constexpr uint32_t name = 0xc1234567u, prefix = 0xa0e06e20u;
struct Provider : ts2::CheckedGuestLoaderServices {
    using CheckedGuestLoaderServices::CheckedGuestLoaderServices;
    uint32_t first = 0, error = 87, retry = 0x80000000u;
    std::vector<uint32_t> calls;
    uint32_t load(uint32_t n, uint32_t file, uint32_t flags) override {
        CHECK(n == name && file == 0);
        calls.push_back(flags);
        CHECK(calls.size() == 1 || calls.size() == 3);
        return calls.size() == 1 ? first : retry;
    }
    uint32_t last_error() override {
        calls.push_back(87);
        return error;
    }
};
void map(ts2::GuestMemory& m, uint32_t address, uint8_t value) {
    const auto base = address - address % m.page_size();
    m.commit(base, m.page_size());
    m.write_bytes(address, std::vector<uint8_t>{value, 0, 0, 0});
}
}
int main() {
    try {
        ts2::GuestMemory a, b;
        Provider bypass(a);
        bypass.first = 0xfffffffeu;
        CHECK(ts2::legacy_loader_policy(name, bypass) == 0xfffffffeu);
        CHECK(bypass.calls == std::vector<uint32_t>{0x800});
        bypass.calls.clear(); bypass.first = 0; bypass.error = 5;
        CHECK(ts2::legacy_loader_policy(name, bypass) == 0);
        CHECK(bypass.calls == (std::vector<uint32_t>{0x800, 87}));
        Provider missing(a);
        bool threw = false;
        try { (void)ts2::legacy_loader_policy(name, missing); }
        catch (const std::out_of_range&) { threw = true; }
        CHECK(threw);
        CHECK(missing.calls == (std::vector<uint32_t>{0x800, 87}));
        map(a, name, 65); map(a, prefix, 65);
        map(b, name, 66); map(b, prefix, 65);
        Provider equal(a), unequal(b);
        CHECK(ts2::legacy_loader_policy(name, equal) == 0);
        CHECK(equal.calls == (std::vector<uint32_t>{0x800, 87}));
        CHECK(ts2::legacy_loader_policy(name, unequal) == 0x80000000u);
        CHECK(unequal.calls == (std::vector<uint32_t>{0x800, 87, 0}));
        CHECK(a.read16(name) == 65 && b.read16(name) == 66);
        CHECK(equal.compare(name, prefix, 7) == 0);
        CHECK(unequal.compare(name, prefix, 7) == 1);
        CHECK(equal.compare(0, UINT32_MAX, 0) == 0);
        // A binding supplies no load/error defaults and no implicit fixed data.
        ts2::CheckedGuestLoaderServices unavailable(a);
        threw = false;
        try { (void)ts2::legacy_loader_policy(name, unavailable); }
        catch (const std::runtime_error&) { threw = true; }
        CHECK(threw);
        std::cout << "composed loader: bypass, stop, comparison and isolation passed\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n'; return 1;
    }
}
