#include "ts2/guest_os_error.hpp"
#include <array>
#include <stdexcept>
#include <utility>

namespace ts2 {
uint32_t legacy_map_os_error(const GuestMemory& memory, uint32_t table,
                             uint32_t error) {
    constexpr uint64_t count = 45;
    if (table == 0 || uint64_t(table) + count * 8 > (uint64_t{1} << 32))
        throw std::out_of_range("OS-error table range");
    std::array<std::pair<uint32_t, uint32_t>, count> pairs{};
    for (size_t i = 0; i < pairs.size(); ++i) {
        const auto address = static_cast<uint32_t>(uint64_t(table) + i * 8);
        pairs[i] = {memory.read32(address), memory.read32(address + 4)};
    }
    for (const auto& [key, value] : pairs)
        if (key == error) return value;
    if (error >= 19 && error <= 36) return 13;
    if (error >= 188 && error <= 202) return 8;
    return 22;
}
}
