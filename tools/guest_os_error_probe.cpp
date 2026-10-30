// Diagnostic transport only; never emits the supplied table or private inputs.
#include "ts2/guest_os_error.hpp"
#include <array>
#include <charconv>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

int main() {
    try {
        ts2::GuestMemory memory;
        const uint32_t base = 0xa1000000;
        const auto page = static_cast<uint32_t>(memory.page_size());
        const uint32_t table = base + page - 359;
        memory.commit(base, page * 2);
        std::string line;
        uint32_t sequence = 0;
        while (std::getline(std::cin, line)) {
            if (line.size() > 2048 || sequence >= 4096) return 2;
            std::istringstream input(line);
            std::array<uint32_t, 91> words{};
            std::string token;
            for (auto& word : words) {
                if (!(input >> token) || token.empty()) return 2;
                const auto [end, ec] = std::from_chars(token.data(), token.data()+token.size(), word);
                if (ec != std::errc{} || end != token.data()+token.size()) return 2;
            }
            if (input >> token) return 2;
            for (uint32_t i = 0; i < 90; ++i) memory.write32(table + i * 4, words[i+1]);
            std::vector<uint8_t> before(page * 2);
            for (uint32_t i = 0; i < page * 2; ++i) before[i] = memory.read8(base + i);
            const auto result = ts2::legacy_map_os_error(memory, table, words[0]);
            for (uint32_t i = 0; i < page * 2; ++i)
                if (memory.read8(base + i) != before[i]) return 3;
            std::cout << sequence++ << ' ' << result << '\n';
        }
        return sequence != 0 && std::cin.eof() ? 0 : 2;
    } catch (const std::exception&) {
        std::cerr << "OS-error probe failed; details suppressed\n";
        return 2;
    }
}
