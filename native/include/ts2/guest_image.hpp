#pragma once
#include "ts2/guest_memory.hpp"
#include <memory>
#include <span>
#include <vector>

namespace ts2 {
struct GuestImageSection {
    uint32_t rva, size, raw_size;
};
struct GuestImage {
    std::unique_ptr<GuestMemory> memory;
    uint32_t image_base, image_size, entry_rva;
    std::vector<GuestImageSection> sections;
};
// Maps PE32/i386 data into a fresh, isolated guest address space. Never executes
// bytes or binds dispatch targets. Caller must separately authorize/hash input.
// No relocation: the PE preferred base must equal expected_base exactly.
GuestImage load_guest_image(std::span<const uint8_t> file,
                           uint32_t expected_base = 0xa0000000u);
}
