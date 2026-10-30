#include "ts2/guest_resolver.hpp"
#include "ts2/guest_memory.hpp"
#include <iostream>
#include <vector>

namespace {
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)
constexpr uint32_t cache = 0xb1000000u, neg = UINT32_MAX;
const ts2::GuestResolverSlots slots{cache, {{{cache + 4, 0xc1234567u},
                                           {cache + 8, 0xc12345e7u}}}};
struct Provider : ts2::GuestLoaderServices, ts2::GuestExportServices {
    std::array<uint32_t, 2> loads{0, 0x80000000u};
    uint32_t result = 0xfffffffeu;
    bool fail_load = false, fail_export = false;
    std::vector<uint32_t> calls;
    uint32_t load(uint32_t name, uint32_t file, uint32_t flags) override {
        CHECK(file == 0 && flags == 0x800);
        calls.push_back(name);
        if (fail_load) throw std::runtime_error("load");
        CHECK(name == slots.candidates[0].name || name == slots.candidates[1].name);
        return loads[name == slots.candidates[0].name ? 0 : 1];
    }
    uint32_t last_error() override { calls.push_back(5); return 5; }
    uint32_t lookup(uint32_t module, uint32_t name) override {
        calls.push_back(module); calls.push_back(name);
        if (fail_export) throw std::runtime_error("export");
        return result;
    }
};
template<class F> void rejects(F f) {
    bool caught = false;
    try { f(); } catch (const std::exception&) { caught = true; }
    CHECK(caught);
}
void init(ts2::GuestMemory& m, uint32_t function = 0, uint32_t a = 0, uint32_t b = 0) {
    m.write32(cache, function); m.write32(cache + 4, a); m.write32(cache + 8, b);
    m.write32(cache + 12, 0x12345678);
}
}
int main() {
    try {
        ts2::GuestMemory m, peer;
        m.commit(cache, m.page_size()); peer.commit(cache, peer.page_size());
        init(m); init(peer, 17, 18, 19);
        Provider p;
        CHECK(ts2::legacy_resolve_two(m, slots, 42, p, p) == p.result);
        CHECK(p.calls == (std::vector<uint32_t>{slots.candidates[0].name, 5,
            slots.candidates[1].name, 0x80000000u, 42}));
        CHECK(m.read32(cache) == p.result && m.read32(cache + 4) == neg);
        CHECK(m.read32(cache + 8) == 0x80000000u && m.read32(cache + 12) == 0x12345678);
        CHECK(peer.read32(cache) == 17 && peer.read32(cache + 4) == 18 && peer.read32(cache + 8) == 19);
        // Cache hit must ignore even malformed/unmapped candidate layout/providers.
        ts2::GuestLoaderServices absent; ts2::GuestExportServices no_export;
        auto bad = slots; bad.candidates = {{{0, 0}, {0, 0}}};
        for (auto value : {1u, 0x80000000u, 0xfffffffeu, neg}) {
            m.write32(cache, value);
            CHECK(ts2::legacy_resolve_two(m, bad, 0, absent, no_export) == (value == neg ? 0 : value));
        }
        // Export failure is NOT a reason to load the next candidate.
        init(m, 0, 0x80000001u); p.calls.clear(); p.result = 0;
        CHECK(ts2::legacy_resolve_two(m, slots, 7, p, p) == 0);
        CHECK(p.calls == (std::vector<uint32_t>{0x80000001u, 7}));
        CHECK(m.read32(cache) == neg && m.read32(cache + 8) == 0);
        // Missing providers are throws, not cached unavailable responses.
        init(m);
        rejects([&] { ts2::legacy_resolve_two(m, slots, 7, absent, no_export); });
        CHECK(m.read32(cache) == 0 && m.read32(cache + 4) == 0);
        init(m, 0, 0x80000001u);
        rejects([&] { ts2::legacy_resolve_two(m, slots, 7, absent, no_export); });
        CHECK(m.read32(cache) == 0);
        // Earlier load-cache effects survive a later export exception.
        init(m); p.loads[0] = 0x87654321u; p.fail_export = true;
        rejects([&] { ts2::legacy_resolve_two(m, slots, 7, p, p); });
        CHECK(m.read32(cache) == 0 && m.read32(cache + 4) == p.loads[0]);
        init(m); p.fail_load = true;
        rejects([&] { ts2::legacy_resolve_two(m, slots, 7, p, p); });
        CHECK(m.read32(cache + 4) == 0);
        // Negative modules bypass load. No usable module avoids export entirely.
        init(m, 0, neg, neg);
        CHECK(ts2::legacy_resolve_two(m, slots, 0, absent, no_export) == 0);
        CHECK(m.read32(cache) == neg);
        // Checked reads, overlap and wrap safety are policy (not guest SEH).
        init(m); bad = slots; bad.function_cache_address = 0;
        rejects([&] { ts2::legacy_resolve_two(m, bad, 0, absent, no_export); });
        init(m, 0, neg, 0); // reach bad second slot without invoking any provider
        for (auto address : {0u, 0xfffffffeu, cache + 2, cache + 4}) {
            bad = slots; bad.candidates[1].cache_address = address;
            rejects([&] { ts2::legacy_resolve_two(m, bad, 0, absent, no_export); });
        }
        // First usable module never reads an unreachable later candidate slot.
        init(m, 0, 23); bad = slots; bad.candidates[1].cache_address = 0;
        p.fail_export = false; p.result = 31;
        CHECK(ts2::legacy_resolve_two(m, bad, 99, absent, p) == 31);
        // Sentinel export is returned once, then indistinguishable from failure.
        init(m, 0, 23); p.result = neg;
        CHECK(ts2::legacy_resolve_two(m, slots, 99, absent, p) == neg);
        CHECK(ts2::legacy_resolve_two(m, slots, 99, absent, no_export) == 0);
        std::cout << "resolver: selection, cache, failures, guards and isolation passed\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
