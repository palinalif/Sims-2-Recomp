// Public authored integration fixture. No original game bytes or OS providers.
#include "ts2/guest_image.hpp"
#include "ts2/guest_resolver.hpp"
#include <iostream>
#include <vector>

namespace {
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)
constexpr uint32_t base = 0xa0000000u, cache = base + 0x1100;
constexpr uint32_t name1 = base + 0x1200, name2 = base + 0x1240;
constexpr uint32_t symbol = base + 0x1280, prefix = 0xa0e06e20u;
constexpr uint32_t module = 0xf1234567u, function = 0xe7654321u;
const ts2::GuestResolverSlots slots{cache, {{{cache + 4, name1}, {cache + 8, name2}}}};
void put16(std::vector<uint8_t>& b, size_t p, uint16_t v) {
    b.at(p) = uint8_t(v); b.at(p + 1) = uint8_t(v >> 8);
}
void put32(std::vector<uint8_t>& b, size_t p, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) b.at(p + i) = uint8_t(v >> (i * 8));
}
std::vector<uint8_t> fixture() {
    std::vector<uint8_t> b(0x1600);
    constexpr size_t opt = 0x98, section = opt + 224;
    put16(b, 0, 0x5a4d); put32(b, 0x3c, 0x80); put32(b, 0x80, 0x4550);
    put16(b, 0x84, 0x14c); put16(b, 0x86, 2); put16(b, 0x94, 224);
    put16(b, opt, 0x10b); put32(b, opt + 16, 0x1010); put32(b, opt + 28, base);
    put32(b, opt + 32, 0x1000); put32(b, opt + 36, 0x200);
    put32(b, opt + 56, 0xe07000); put32(b, opt + 60, 0x200);
    put32(b, opt + 92, 16);
    put32(b, section + 8, 0x1000); put32(b, section + 12, 0x1000);
    put32(b, section + 16, 0x400); put32(b, section + 20, 0x200);
    put32(b, section + 36, 0x60000020);
    put32(b, section + 48, 0x1000); put32(b, section + 52, 0xe06000);
    put32(b, section + 56, 0x1000); put32(b, section + 60, 0x600);
    put32(b, section + 76, 0x40000040);
    // Marker at the entry: data only, never executed as x86 instructions.
    put32(b, 0x210, 0x13579bdf);
    for (unsigned i = 0; i < 7; ++i) {
        put16(b, 0x400 + i * 2, uint16_t('X' + i));
        put16(b, 0x440 + i * 2, uint16_t('A' + i));
        put16(b, 0x1420 + i * 2, uint16_t('A' + i));
    }
    b.at(0x480) = 'f';
    return b;
}
template<class Exception, class F> void rejects(F f) {
    bool caught = false;
    try { f(); } catch (const Exception&) { caught = true; }
    CHECK(caught);
}
struct Event {
    uint32_t kind, a, b, c;
    bool operator==(const Event&) const = default;
};
struct Provider final : ts2::CheckedGuestLoaderServices, ts2::GuestExportServices {
    const ts2::GuestMemory& memory;
    unsigned scenario;
    std::vector<Event> events;
    Provider(const ts2::GuestMemory& m, unsigned s)
        : CheckedGuestLoaderServices(m), memory(m), scenario(s) {}
    uint32_t load(uint32_t name, uint32_t file, uint32_t flags) override {
        events.push_back({1, name, file, flags});
        CHECK(file == 0);
        CHECK(memory.read16(name) == (name == name1 ? 'X' : 'A'));
        if (name == name1) return flags == 0 && scenario != 1 ? module : 0;
        CHECK(name == name2 && flags == 0x800);
        return module;
    }
    uint32_t last_error() override {
        events.push_back({2, 0, 0, 0}); return 87;
    }
    uint32_t lookup(uint32_t handle, uint32_t name) override {
        events.push_back({3, handle, name, 0});
        CHECK(handle == module && name == symbol && memory.read8(name) == 'f');
        return scenario == 2 ? 0 : function;
    }
};
void run(unsigned scenario) {
    const auto bytes = fixture();
    auto image = ts2::load_guest_image(bytes);
    auto peer = ts2::load_guest_image(bytes);
    auto& m = *image.memory;
    CHECK(image.image_base == base && image.entry_rva == 0x1010);
    CHECK(image.image_size == 0xe07000 && image.sections.size() == 2);
    CHECK(m.read32(base + image.entry_rva) == 0x13579bdf);
    CHECK(m.read32(base + 0x210) == 0); // not a raw-file-offset mapping
    CHECK(m.read32(cache) == 0 && m.read32(base + 0x1800) == 0);
    CHECK(m.read16(prefix) == 'A' && m.read16(name1) == 'X');
    CHECK(ts2::guest_wide_compare(m, name2, prefix, 7) == 0);
    CHECK(ts2::guest_wide_compare(m, name1, prefix, 7) == uint32_t('X' - 'A'));
    rejects<std::out_of_range>([&] { (void)m.read32(base - 4); });
    // Outside rounded committed extent, independent of 4K/16K host page size.
    const auto end = base + uint32_t((image.image_size + m.page_size() - 1)
                                    / m.page_size() * m.page_size());
    rejects<std::out_of_range>([&] { (void)m.read8(end); });
    rejects<std::out_of_range>([&] { (void)m.read32(0xfffffffe); });
    m.write32(end - 4, 0xabcdef01);
    const uint8_t crossing[]{1, 2, 3, 4, 5};
    rejects<std::out_of_range>([&] { m.write_bytes(end - 4, crossing); });
    CHECK(m.read32(end - 4) == 0xabcdef01); // all-or-nothing bulk preflight
    ts2::GuestLoaderServices missing;
    ts2::GuestExportServices no_export;
    rejects<std::runtime_error>([&] {
        (void)ts2::legacy_resolve_two(m, slots, symbol, missing, no_export);
    });
    CHECK(m.read32(cache) == 0 && m.read32(cache + 4) == 0);
    Provider p(m, scenario);
    const auto result = ts2::legacy_resolve_two(m, slots, symbol, p, p);
    const uint32_t expected = scenario == 2 ? 0 : function;
    CHECK(result == expected);
    std::vector<Event> expected_events{{1, name1, 0, 0x800}, {2, 0, 0, 0},
                                       {1, name1, 0, 0}};
    if (scenario == 1) expected_events.push_back({1, name2, 0, 0x800});
    expected_events.push_back({3, module, symbol, 0});
    CHECK(p.events == expected_events);
    CHECK(m.read32(cache) == (scenario == 2 ? UINT32_MAX : function));
    CHECK(m.read32(cache + 4) == (scenario == 1 ? UINT32_MAX : module));
    CHECK(m.read32(cache + 8) == (scenario == 1 ? module : 0));
    // Cache reentry must bypass even invalid candidates and absent providers.
    const ts2::GuestResolverSlots invalid{cache, {{{0, 0}, {0, 0}}}};
    CHECK(ts2::legacy_resolve_two(m, invalid, 0, missing, no_export) == expected);
    CHECK(peer.memory->read32(cache) == 0 && peer.memory->read32(end - 4) == 0);
    CHECK(m.read32(base + 0x1010) == 0x13579bdf && m.read16(prefix) == 'A');
    std::cout << "scenario=" << scenario << " result=" << std::hex << result
              << " caches=" << m.read32(cache) << ',' << m.read32(cache + 4)
              << ',' << m.read32(cache + 8) << std::dec
              << " events=" << p.events.size() << '\n';
}
}
int main() {
    try {
        for (unsigned scenario = 0; scenario < 3; ++scenario) run(scenario);
        auto bad = fixture(); put32(bad, 0x98 + 28, base + 0x1000);
        rejects<std::invalid_argument>([&] { (void)ts2::load_guest_image(bad); });
        bad = fixture(); bad.pop_back();
        rejects<std::invalid_argument>([&] { (void)ts2::load_guest_image(bad); });
        std::cout << "synthetic-loading: mapping guards policies cache isolation passed\n";
    } catch (const std::exception& e) {
        std::cerr << "synthetic-loading FAIL: " << e.what() << '\n'; return 1;
    }
}
