#include "ts2/guest_dispatch.hpp"
#include "ts2/guest_memory.hpp"
#include <array>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
int checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error(#x); } while (false)
using namespace ts2;
constexpr uint32_t leaf = 0xa0001000u;
constexpr uint32_t outer = 0xa0002000u;
constexpr uint32_t stack = 0xfffe0000u;
constexpr uint32_t object = 0x90000000u;
constexpr uint32_t vtable = 0x90010000u;

auto snapshot(const GuestRegisters& r) {
    return std::array{r.eax, r.ecx, r.edx, r.ebx, r.esp, r.ebp, r.esi, r.edi, r.eflags};
}
template<class Exception, class F> void rejects(F f) {
    bool threw = false;
    try { f(); } catch (const Exception&) { threw = true; }
    CHECK(threw);
}
// Authored call fixture, not original game code: reads a stack argument and
// stores it to a guest object. Stack/flags are intentionally left untouched.
void store(GuestRegisters& r, GuestMemory& m, const GuestDispatch&) {
    const auto value = m.read32(r.esp + 4);
    m.write32(r.ecx + 4, value);
    r.eax = value;
}
void virtual_call(GuestRegisters& r, GuestMemory& m, const GuestDispatch& d) {
    // Read a 32-bit guest vtable and target; neither is cast to a host pointer.
    d.invoke(m.read32(m.read32(r.ecx) + 8), r, m);
}
void throws(GuestRegisters&, GuestMemory&, const GuestDispatch&) {
    throw std::runtime_error("authored service failure");
}
}
int main() {
    try {
        GuestMemory memory;
        memory.commit(stack, memory.page_size());
        memory.commit(object, memory.page_size());
        memory.commit(vtable, memory.page_size());
        memory.write32(stack, 0xa0123456u);
        memory.write32(stack + 4, 0xfedcba98u);
        memory.write32(object, vtable);
        memory.write32(vtable + 8, leaf);
        GuestDispatch dispatch;
        rejects<std::invalid_argument>([&] { dispatch.bind(0, store); });
        rejects<std::invalid_argument>([&] { dispatch.bind(leaf, nullptr); });
        dispatch.bind(leaf, store);
        dispatch.bind(outer, virtual_call);
        rejects<std::invalid_argument>([&] { dispatch.bind(leaf, throws); });
        GuestRegisters r{1, object, 3, 4, stack, 6, 7, 8, 0x8d7};
        const auto initial = snapshot(r);
        for (uint32_t unknown : {0u, leaf + 1, leaf - 1, 0x1000u, 0xffffffffu}) {
            bool threw = false;
            try { dispatch.invoke(unknown, r, memory); }
            catch (const UnresolvedGuestCall& e) {
                threw = true;
                CHECK(e.target() == unknown);
                CHECK(std::string(e.what()).find("VA=0x") != std::string::npos);
            }
            CHECK(threw);
            CHECK(snapshot(r) == initial);
            CHECK(memory.read32(object + 4) == 0);
        }
        dispatch.invoke(outer, r, memory);
        auto expected = initial;
        expected[0] = 0xfedcba98u;
        CHECK(snapshot(r) == expected);
        CHECK(memory.read32(object + 4) == 0xfedcba98u);
        CHECK(memory.read32(stack) == 0xa0123456u);
        CHECK(memory.read32(stack + 4) == 0xfedcba98u);
        // An unknown callback and an uncommitted vtable must fail visibly.
        memory.write32(vtable + 8, leaf + 1);
        rejects<UnresolvedGuestCall>([&] { dispatch.invoke(outer, r, memory); });
        CHECK(snapshot(r) == expected);
        memory.write32(object, 0x80000000u);
        rejects<std::out_of_range>([&] { dispatch.invoke(outer, r, memory); });
        CHECK(snapshot(r) == expected);
        dispatch.bind(0xa0003000u, throws);
        bool propagated = false;
        try { dispatch.invoke(0xa0003000u, r, memory); }
        catch (const std::runtime_error& e) {
            propagated = std::string(e.what()) == "authored service failure";
        }
        CHECK(propagated);
        CHECK(snapshot(r) == expected);
        std::cout << "PASS " << checks << " guest dispatch checks\n";
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << '\n';
        return 1;
    }
}
