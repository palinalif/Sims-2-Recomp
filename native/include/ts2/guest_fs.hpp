#pragma once
#include "ts2/guest_memory.hpp"
#include <cstdint>
#include <stdexcept>

namespace ts2 {
// Explicit per-context FS data base, not a selector, TEB or SEH implementation.
// The owner supplies the base and memory on every access; no current-thread global.
// Only flat 32-bit data addressing is supported, with overflow rejected rather
// than wrapped. Descriptor limits/privileges and exception dispatch are absent.
class GuestFs {
    uint32_t base_;
    uint32_t address32(uint32_t offset) const {
        const uint64_t address = uint64_t{base_} + offset;
        if (address > (uint64_t{1} << 32) - 4)
            throw std::out_of_range("Guest FS address overflow");
        return static_cast<uint32_t>(address);
    }
public:
    explicit GuestFs(uint32_t base) : base_(base) {}
    uint32_t base() const noexcept { return base_; }
    uint32_t read32(const GuestMemory& memory, uint32_t offset) const {
        return memory.read32(address32(offset));
    }
    void write32(GuestMemory& memory, uint32_t offset, uint32_t value) const {
        memory.write32(address32(offset), value);
    }
};
}
