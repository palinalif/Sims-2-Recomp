#include "ts2/guest_os_error_abi.hpp"
#include "ts2/guest_os_error.hpp"
#include "ts2/guest_memory.hpp"
#include <bit>
#include <stdexcept>

namespace ts2 {
namespace {
uint32_t arithmetic(uint32_t left, uint32_t right, bool subtract) {
    const uint32_t value = subtract ? left - right : left + right;
    const bool carry = subtract ? left < right : uint64_t(left) + right > UINT32_MAX;
    const auto overflow = (subtract ? left ^ right : ~(left ^ right)) & (left ^ value);
    return (carry ? 1u : 0u) | (std::popcount(value & 255u) % 2 == 0 ? 4u : 0u) |
        ((left ^ right ^ value) & 16u) | (value == 0 ? 0x40u : 0u) |
        (value & 0x80000000u ? 0x80u : 0u) | (overflow & 0x80000000u ? 0x800u : 0u);
}
}
void GuestOsErrorAbi::invoke(GuestRegisters& r, GuestMemory& m) const {
    const auto sp = r.esp;
    if (sp < 8 || uint64_t(sp) + 8 > (uint64_t{1} << 32))
        throw std::out_of_range("OS-error ABI stack bounds");
    if (uint64_t(table) < uint64_t(sp) + 8 && uint64_t(table) + 360 > sp - 8)
        throw std::invalid_argument("OS-error ABI stack aliases table");
    const auto error = m.read32(sp + 4);
    (void)m.read32(sp); (void)m.read32(sp - 4); (void)m.read32(sp - 8);
    const auto result = legacy_map_os_error(m, table, error);
    bool matched = false;
    for (uint32_t i = 0; i < 45; ++i)
        if (m.read32(table + i * 8) == error) { matched = true; break; }
    uint32_t flags;
    r.ecx = error;
    m.write32(sp - 4, r.ebp);
    if (matched) {
        flags = arithmetic(error, error, true);
    } else if (error >= 19 && error <= 36) {
        flags = arithmetic(error - 19, 17, true);
        m.write32(sp - 8, 13);
    } else {
        r.ecx = 14;
        flags = arithmetic(result - 8, 8, false);
        m.write32(sp - 8, 14);
    }
    r.eax = result; r.esp = sp + 4;
    r.eflags = (r.eflags & ~0x8d5u) | flags;
}
}
