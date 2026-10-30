#include "ts2/guest_loader_policy.hpp"
#include "ts2/guest_memory.hpp"
#include <array>
#include <iostream>
#include <stdexcept>

#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)
template<class F> void rejects(F f) {
    bool threw = false;
    try { f(); } catch (const std::out_of_range&) { threw = true; }
    CHECK(threw);
}
int main() {
    try {
        ts2::GuestMemory m;
        const uint32_t base = 0xc1000000u;
        const uint32_t end = base + static_cast<uint32_t>(m.page_size());
        m.commit(base, m.page_size());
        const std::array<uint8_t, 4> bytes{0xff, 0x80, 0, 0};
        m.write_bytes(end - 4, bytes);
        CHECK(m.read16(end - 4) == 0x80ff);
        CHECK(m.read16(end - 3) == 0x80); // unaligned, little-endian
        rejects([&] { (void)m.read16(end - 1); });
        rejects([&] { (void)m.read16(0); });
        rejects([&] { (void)m.read16(0xffffffffu); });
        CHECK(ts2::guest_wide_compare(m, 0, 0xffffffffu, 0) == 0);
        CHECK(ts2::guest_wide_compare(m, end - 2, end - 2, UINT32_MAX) == 0);
        CHECK(ts2::guest_wide_compare(m, end - 4, end - 2, UINT32_MAX) == 0x80ff);
        CHECK(ts2::guest_wide_compare(m, end - 2, end - 4, 1) == 0xffff7f01u);
        CHECK(ts2::guest_wide_compare(m, end - 4, end - 4, 1) == 0);
        // A valid first unit must not license a subsequent guard-page read.
        m.write_bytes(end - 2, std::array<uint8_t, 2>{1, 0});
        CHECK(ts2::guest_wide_compare(m, end - 2, end - 2, 1) == 0);
        rejects([&] { (void)ts2::guest_wide_compare(m, end - 2, end - 2, 2); });
        rejects([&] { (void)ts2::guest_wide_compare(m, end - 2, end, 1); });
        m.commit(0xffff0000u, 65536);
        m.write_bytes(0xfffffffeu, std::array<uint8_t, 2>{1, 0});
        CHECK(ts2::guest_wide_compare(m, 0xfffffffeu, 0xfffffffeu, 1) == 0);
        rejects([&] { (void)ts2::guest_wide_compare(m, 0xfffffffeu, 0xfffffffeu, 2); });
        rejects([&] { (void)ts2::guest_wide_compare(m, 0xffffffffu, end - 2, 1); });
        CHECK(m.read16(end - 4) == 0x80ff && m.read16(end - 2) == 1);
        std::cout << "checked wide-unit reads, early stops and overflow passed\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
