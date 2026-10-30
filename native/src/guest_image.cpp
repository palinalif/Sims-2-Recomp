#include "ts2/guest_image.hpp"
#include <algorithm>
#include <stdexcept>

namespace ts2 {
namespace {
constexpr uint64_t budget = 256ull * 1024 * 1024;
void require(bool valid) {
    if (!valid) throw std::invalid_argument("Unsupported or malformed guest PE32 image");
}
struct Reader {
    std::span<const uint8_t> bytes;
    void range(uint64_t offset, uint64_t size) const {
        require(offset <= bytes.size() && size <= bytes.size() - offset);
    }
    uint32_t u32(uint64_t offset) const {
        range(offset, 4);
        return uint32_t(bytes[offset]) | uint32_t(bytes[offset+1]) << 8 |
               uint32_t(bytes[offset+2]) << 16 | uint32_t(bytes[offset+3]) << 24;
    }
    uint16_t u16(uint64_t offset) const {
        range(offset, 2);
        return uint16_t(bytes[offset]) | uint16_t(bytes[offset+1]) << 8;
    }
};
bool power_two(uint32_t value) { return value && !(value & (value-1)); }
uint64_t rounded(uint64_t value, uint32_t alignment) {
    return (value + alignment - 1) / alignment * alignment;
}
struct Range { uint64_t begin, end; };
void disjoint(std::vector<Range> ranges) {
    std::sort(ranges.begin(), ranges.end(), [](auto a, auto b) { return a.begin < b.begin; });
    for (size_t i=1; i<ranges.size(); ++i) require(ranges[i-1].end <= ranges[i].begin);
}
}
GuestImage load_guest_image(std::span<const uint8_t> file, uint32_t expected_base) {
    require(file.size() <= budget);
    const Reader r{file};
    require(r.u16(0) == 0x5a4d);
    const uint64_t pe = r.u32(0x3c);
    require(pe >= 0x40 && r.u32(pe) == 0x4550);
    require(r.u16(pe+4) == 0x14c); // i386, not PE32+ or another machine
    const auto count = r.u16(pe+6), optional_size = r.u16(pe+20);
    require(count && count <= 96 && optional_size >= 96);
    const uint64_t opt = pe+24, table = opt+optional_size;
    r.range(opt, optional_size);
    r.range(table, uint64_t(count)*40);
    require(r.u16(opt) == 0x10b);
    const auto entry = r.u32(opt+16), base = r.u32(opt+28);
    const auto alignment = r.u32(opt+32), file_alignment = r.u32(opt+36);
    const auto size = r.u32(opt+56), headers = r.u32(opt+60);
    require(power_two(alignment) && alignment >= 4096);
    require(power_two(file_alignment) && file_alignment >= 512 && file_alignment <= 65536);
    require(alignment >= file_alignment);
    require(size && size <= budget && size % alignment == 0);
    require(base == expected_base && base && base % alignment == 0);
    require(uint64_t(base)+size <= (1ull << 32));
    require(headers && headers <= size && headers % file_alignment == 0);
    require(table + uint64_t(count)*40 <= headers);
    r.range(0, headers);
    // Directory records must fit the optional header; they are not resolved here.
    require(r.u32(opt+92) <= (optional_size-96u)/8u);
    std::vector<Range> virtual_ranges{{0, rounded(headers, alignment)}};
    std::vector<Range> raw_ranges{{0, headers}};
    struct Copy { uint32_t rva, offset, size; };
    std::vector<Copy> copies;
    std::vector<GuestImageSection> sections;
    bool entry_backed = false;
    for (unsigned i=0; i<count; ++i) {
        const auto s = table+uint64_t(i)*40;
        const auto virtual_size = r.u32(s+8), va = r.u32(s+12);
        const auto raw_size = r.u32(s+16), offset = r.u32(s+20);
        const auto extent = std::max(virtual_size, raw_size);
        require(va % alignment == 0 && va < size);
        require(uint64_t(va)+extent <= size);
        if (extent) virtual_ranges.push_back({va, uint64_t(va)+rounded(extent, alignment)});
        if (raw_size) {
            // The pinned image's final raw length is not FileAlignment-sized.
            // Require aligned starts, but copy only the exact backed byte count.
            require(offset % file_alignment == 0);
            r.range(offset, raw_size);
            raw_ranges.push_back({offset, uint64_t(offset)+raw_size});
            copies.push_back({va, offset, raw_size});
        }
        if (entry >= va && uint64_t(entry) < uint64_t(va)+raw_size &&
            (r.u32(s+36) & 0x20000000u)) entry_backed = true;
        sections.push_back({va, extent, raw_size});
    }
    disjoint(virtual_ranges);
    disjoint(raw_ranges);
    require(entry && entry_backed);
    // All format validation precedes allocation/writes. The destination is fresh:
    // no caller memory can be overwritten and failure never returns partial data.
    auto memory = std::make_unique<GuestMemory>();
    memory->commit(base, size);
    memory->write_bytes(base, file.first(headers));
    for (const auto& c : copies)
        memory->write_bytes(base+c.rva, file.subspan(c.offset, c.size));
    return {std::move(memory), base, size, entry, std::move(sections)};
}
}
