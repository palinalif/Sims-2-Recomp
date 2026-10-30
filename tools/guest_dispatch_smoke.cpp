// Public static-recompilation integration test, NOT original-game execution.
#include "ts2/guest_dispatch.hpp"
#include "ts2/guest_memory.hpp"
#include <array>
#include <bit>
#include <cstdio>
#include <iostream>
#include <vector>

namespace {
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)
constexpr uint32_t target = 0xa0001000u, stack = 0xfffe0000u;
constexpr uint32_t arithmetic = 0x8d5u; // CF PF AF ZF SF OF, all defined by ADD
// Deliberately narrow shim for this reviewed MOV/ADD/RET fixture only. No host
// pointer, global register bank, executable guest page or unchecked memory cast.
struct Word {
    ts2::GuestMemory& memory;
    uint32_t address;
    operator uint32_t() const { return memory.read32(address); }
    void operator=(uint32_t value) { memory.write32(address, value); }
};
uint32_t add_flags(uint32_t a, uint32_t b, uint32_t carry, uint32_t initial) {
    const uint32_t sum = a + b;
    return (initial & ~arithmetic) | carry
        | (std::popcount(sum & 255u) % 2 == 0 ? 4u : 0u)
        | ((a ^ b ^ sum) & 16u) | (sum == 0 ? 64u : 0u)
        | (sum & 0x80000000u ? 128u : 0u)
        | ((~(a ^ b) & (a ^ sum)) >> 20 & 0x800u);
}
// Only these macros are needed by the pinned generated body below. Local
// context parameters replace upstream process-global state. Unsupported emitted
// operations fail compilation, rather than silently using the host address space.
#define eax r.eax
#define esp r.esp
#define MEM32(address) Word{m, uint32_t(address)}
#define FK_NONE 0u
#define FK_ADD 1u
#define RECOMP_ENTER(va) CHECK((va) == target)
#define RECOMP_FLAGS_OUT() do { CHECK(_flag_k == FK_ADD); r.eflags = add_flags(_flag_a, _flag_b, _cf, r.eflags); } while (false)
// Upstream emits unused generic locals/entry labels for this narrow leaf.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-label"
#include "../tests/fixtures/synthetic_dispatch_lift.inc"
#pragma GCC diagnostic pop
#undef eax
#undef esp
#undef MEM32
#undef FK_NONE
#undef FK_ADD
#undef RECOMP_ENTER
#undef RECOMP_FLAGS_OUT

auto page_bytes(const ts2::GuestMemory& m) {
    std::vector<uint8_t> bytes(m.page_size());
    for (size_t j = 0; j < bytes.size(); ++j) bytes[j] = m.read8(stack + uint32_t(j));
    return bytes;
}
auto snapshot(const ts2::GuestRegisters& r) {
    return std::array{r.eax, r.ecx, r.edx, r.ebx, r.esp, r.ebp, r.esi, r.edi, r.eflags};
}
template<class Exception, class F> void rejects(F f) {
    bool caught = false;
    try { f(); } catch (const Exception&) { caught = true; }
    CHECK(caught);
}
}
int main() {
    try {
        ts2::GuestDispatch dispatch;
        dispatch.bind(target, synthetic_sum);
        ts2::GuestMemory memory, peer;
        memory.commit(stack, memory.page_size());
        peer.commit(stack, peer.page_size());
        peer.write32(stack + 12, 0x76543210);
        const std::array<std::array<uint32_t, 2>, 12> pairs{{
            {0, 0}, {1, 2}, {0xffffffff, 1}, {0x7fffffff, 1},
            {0x80000000, 0xffffffff}, {0xffffffff, 0xffffffff},
            {0x80000000, 0x80000000}, {15, 1}, {0x12345678, 0x87654321},
            {0xdeadbeef, 0x10203040}, {255, 1}, {0x7ffffffe, 1}}};
        for (size_t i = 0; i < pairs.size(); ++i) {
            memory.write_bytes(stack, std::vector<uint8_t>(memory.page_size(), 0xa5));
            memory.write32(stack, target + 13); // synthetic return marker
            memory.write32(stack + 4, pairs[i][0]);
            memory.write32(stack + 8, pairs[i][1]);
            const auto before = page_bytes(memory);
            ts2::GuestRegisters r{0x11111111u, 0x92345678u, 0x33333333u, 0x44444444u,
                                  stack, 0x66666666u, 0x87777777u, 0x98888888u,
                                  i % 2 ? 0xed7u : 0x202u};
            const auto initial = snapshot(r);
            for (uint32_t missing : {0u, target - 1, target + 1, 0x1000u, 0xffffffffu}) {
                try { dispatch.invoke(missing, r, memory); CHECK(false); }
                catch (const ts2::UnresolvedGuestCall& e) { CHECK(e.target() == missing); }
                CHECK(snapshot(r) == initial);
                CHECK(page_bytes(memory) == before);
            }
            dispatch.invoke(target, r, memory);
            CHECK(r.eax == uint32_t(pairs[i][0] + pairs[i][1]));
            CHECK(r.esp == stack + 4 && memory.read32(stack + 12) == r.eax);
            for (size_t j = 0; j < memory.page_size(); ++j)
                if (j < 12 || j >= 16) CHECK(memory.read8(stack + uint32_t(j)) == before[j]);
            CHECK(peer.read32(stack + 12) == 0x76543210);
            // State transport is strict: every GPR, full EFLAGS and stack window.
            std::printf("case=%zu", i);
            for (uint32_t value : snapshot(r)) std::printf(" %08x", unsigned(value));
            for (unsigned j = 0; j < 32; ++j) std::printf("%s%02x", j == 0 ? " " : "", unsigned(memory.read8(stack + j)));
            std::puts("");
        }
        // Invalid guest reads throw, not host SIGSEGV. No rollback is promised
        // for a fault partway through an adapter; this fixture faults on first read.
        ts2::GuestRegisters bad{};
        bad.esp = 0x90000000u;
        rejects<std::out_of_range>([&] { dispatch.invoke(target, bad, memory); });
        bad.esp = 0xfffffffeu;
        rejects<std::out_of_range>([&] { dispatch.invoke(target, bad, memory); });
        std::puts("synthetic-dispatch: exact VA checked lift guards isolation passed");
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << '\n';
        return 1;
    }
}
