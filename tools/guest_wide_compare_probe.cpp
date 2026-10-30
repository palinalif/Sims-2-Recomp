// Authored bounded host transport: no original bytes or host wide strings.
#include "ts2/guest_loader_policy.hpp"
#include "ts2/guest_memory.hpp"
#include <iostream>
#include <stdexcept>
#include <vector>

int main() {
    try {
        uint32_t count, nl, nr, unaligned;
        while (std::cin >> count >> nl >> nr >> unaligned) {
            if (count > 32 || nl > 32 || nr > 32 || unaligned > 1)
                throw std::runtime_error("invalid limits");
            ts2::GuestMemory m;
            uint32_t pointers[2]{};
            std::vector<uint8_t> before[2];
            const uint32_t bases[]{0xc1000000u, 0xc2000000u};
            const uint32_t lengths[]{nl, nr};
            for (unsigned side = 0; side < 2; ++side) {
                std::vector<uint8_t> bytes;
                for (uint32_t i = 0; i < lengths[side]; ++i) {
                    uint32_t value;
                    if (!(std::cin >> value) || value > 65535)
                        throw std::runtime_error("invalid unit");
                    bytes.push_back(static_cast<uint8_t>(value));
                    bytes.push_back(static_cast<uint8_t>(value >> 8));
                }
                pointers[side] = bases[side];
                if (!count) continue; // no pointer reads, no implicit NUL
                if (bytes.empty()) throw std::runtime_error("empty span");
                m.commit(bases[side], m.page_size());
                pointers[side] += static_cast<uint32_t>(m.page_size() - bytes.size() - unaligned);
                m.write_bytes(pointers[side], bytes);
                for (size_t i = 0; i < m.page_size(); ++i)
                    before[side].push_back(m.read8(bases[side] + static_cast<uint32_t>(i)));
            }
            const auto result = ts2::guest_wide_compare(m, pointers[0], pointers[1], count);
            for (unsigned side = 0; side < 2; ++side)
                for (size_t i = 0; i < before[side].size(); ++i)
                    if (m.read8(bases[side] + static_cast<uint32_t>(i)) != before[side][i])
                        throw std::runtime_error("input changed");
            std::cout << result << '\n';
        }
        if (!std::cin.eof()) throw std::runtime_error("invalid input");
    } catch (const std::exception&) {
        std::cerr << "wide native probe failed\n";
        return 2;
    }
}
