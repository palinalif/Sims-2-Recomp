#include "ts2/guest_fs.hpp"
#include <iostream>
#include <stdexcept>

namespace {
int checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error(#x); } while (false)
template<class F> void rejects(F f) {
    bool threw = false;
    try { f(); } catch (const std::out_of_range&) { threw = true; }
    CHECK(threw);
}
}
int main() {
    try {
        ts2::GuestMemory memory;
        constexpr uint32_t first = 0x82000000u, second = 0x93000000u;
        const auto page = static_cast<uint32_t>(memory.page_size());
        memory.commit(first, page);
        memory.commit(second, page);
        memory.commit(0xffffffffu, 1);
        const ts2::GuestFs a(first), b(second), flat(0);
        CHECK(a.base() == first);
        CHECK(b.base() == second);
        // Independent contexts in one address space; unaligned little-endian data.
        a.write32(memory, 0, 0xfedcba98u);
        b.write32(memory, 0, 0x12345678u);
        a.write32(memory, 5, 0x89abcdefu);
        CHECK(a.read32(memory, 0) == 0xfedcba98u);
        CHECK(b.read32(memory, 0) == 0x12345678u);
        CHECK(memory.read8(first + 5) == 0xef);
        CHECK(memory.read8(first + 8) == 0x89);
        CHECK(a.read32(memory, 5) == 0x89abcdefu);
        CHECK(b.read32(memory, 5) == 0);
        CHECK(flat.read32(memory, first) == a.read32(memory, 0));
        // Identical base in another process memory must not share data.
        ts2::GuestMemory peer;
        peer.commit(first, page);
        a.write32(peer, 0, 0x55555555u);
        CHECK(a.read32(peer, 0) == 0x55555555u);
        CHECK(a.read32(memory, 0) == 0xfedcba98u);
        a.write32(memory, page - 4, 0xaabbccddu);
        CHECK(a.read32(memory, page - 4) == 0xaabbccddu);
        // A crossing write must reject before changing even its committed bytes.
        rejects([&] { a.write32(memory, page - 3, 0); });
        CHECK(a.read32(memory, page - 4) == 0xaabbccddu);
        rejects([&] { (void)a.read32(memory, page - 3); });
        rejects([&] { (void)a.read32(memory, page); });
        rejects([&] { b.write32(memory, page, 1); });
        rejects([&] { (void)flat.read32(memory, 0); });
        // Last valid word is allowed, but crossing 4 GiB and base+offset wrap
        // reject even when the wrapped destination is committed.
        const ts2::GuestFs top(0xfffffffcu);
        top.write32(memory, 0, 0x76543210u);
        CHECK(top.read32(memory, 0) == 0x76543210u);
        for (uint32_t offset : {1u, 4u, first + 4u, 0xffffffffu}) {
            rejects([&] { (void)top.read32(memory, offset); });
            rejects([&] { top.write32(memory, offset, 0); });
        }
        rejects([&] { (void)flat.read32(memory, 0xfffffffdu); });
        rejects([&] { flat.write32(memory, 0xffffffffu, 0); });
        CHECK(memory.read32(first) == 0xfedcba98u);
        CHECK(memory.read32(second) == 0x12345678u);
        CHECK(memory.read32(0xfffffffcu) == 0x76543210u);
        CHECK(a.read32(peer, 0) == 0x55555555u);
        std::cout << "PASS " << checks << " guest FS checks\n";
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << '\n';
        return 1;
    }
}
