#include "ts2/guest_os_error.hpp"
#include <iostream>
#include <stdexcept>

namespace {
int checks = 0;
void check(bool ok) {
    ++checks;
    if (!ok) throw std::runtime_error("OS-error policy check failed");
}
template<class F> void rejects(F f) {
    bool rejected = false;
    try { f(); } catch (const std::out_of_range&) { rejected = true; }
    check(rejected);
}
void fill(ts2::GuestMemory& m, uint32_t base) {
    for (uint32_t i = 0; i < 45; ++i) {
        m.write32(base + i * 8, 10000 + i);
        m.write32(base + i * 8 + 4, 0x80000000 + i);
    }
}
}
int main() {
    try {
        ts2::GuestMemory m, peer;
        const uint32_t page = static_cast<uint32_t>(m.page_size());
        const uint32_t base = 0xa1000000, table = base + page - 359;
        m.commit(base, page * 2); peer.commit(base, page * 2);
        fill(m, table); fill(peer, table);
        for (uint32_t i = 0; i < 45; ++i)
            check(ts2::legacy_map_os_error(m, table, 10000 + i) == 0x80000000 + i);
        for (auto [error, value] : {std::pair{0u,22u}, {18u,22u}, {19u,13u},
                {36u,13u}, {37u,22u}, {187u,22u}, {188u,8u}, {202u,8u},
                {203u,22u}, {0x7fffffffu,22u}, {0x80000000u,22u}, {0xffffffffu,22u}})
            check(ts2::legacy_map_os_error(m, table, error) == value);
        // Duplicates: preserve original ordering; zero and all-ones are values.
        for (uint32_t error : {0u, 19u, 188u, 0xffffffffu}) {
            fill(m, table);
            m.write32(table, error); m.write32(table + 4, 0);
            m.write32(table + 44 * 8, error); m.write32(table + 44 * 8 + 4, 0xffffffff);
            check(ts2::legacy_map_os_error(m, table, error) == 0);
            m.write32(table, 12345);
            check(ts2::legacy_map_os_error(m, table, error) == 0xffffffff);
        }
        for (uint32_t i = 0; i < 45; ++i)
            check(peer.read32(table + i * 8 + 4) == 0x80000000 + i);
        // Even an early exact match cannot authorize an incomplete table.
        const uint32_t partial = base + page * 2 - 8;
        m.write32(partial, 19); m.write32(partial + 4, 7);
        rejects([&] { ts2::legacy_map_os_error(m, partial, 19); });
        for (uint32_t bad : {0u, 0xfffffffcu, base - page, base + 2 * page})
            rejects([&] { ts2::legacy_map_os_error(m, bad, 19); });
        check(m.read32(partial) == 19 && m.read32(partial + 4) == 7);
        const uint32_t top = static_cast<uint32_t>((uint64_t{1} << 32) - page);
        m.commit(top, page);
        constexpr uint32_t last = 0xfffffe98; // exactly 360 bytes before 2^32
        fill(m, last);
        check(ts2::legacy_map_os_error(m, last, 10044) == 0x8000002c);
        rejects([&] { ts2::legacy_map_os_error(m, last + 1, 10000); });
        std::cout << "OS-error policy checks " << checks << '\n';
        return 0;
    } catch (const std::exception&) {
        std::cerr << "OS-error policy tests failed\n"; return 1;
    }
}
