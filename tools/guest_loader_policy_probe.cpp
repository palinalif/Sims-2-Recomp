// Authored development transport, not an OS loader or a game execution tool.
#include "ts2/guest_loader_policy.hpp"
#include <array>
#include <iostream>
#include <vector>

namespace {
struct Provider : ts2::GuestLoaderServices {
    std::array<uint32_t, 4> responses{};
    std::vector<std::array<uint32_t, 4>> calls;
    unsigned loads = 0;
    uint32_t load(uint32_t name, uint32_t file, uint32_t flags) override {
        if (loads >= 2) throw std::runtime_error("load budget exceeded");
        calls.push_back({1, name, file, flags});
        return responses[loads++ == 0 ? 0 : 3];
    }
    uint32_t last_error() override {
        calls.push_back({2, 0, 0, 0});
        return responses[1];
    }
    uint32_t compare(uint32_t a, uint32_t b, uint32_t n) override {
        calls.push_back({3, a, b, n});
        return responses[2];
    }
};
}
int main() {
    try {
        uint64_t name;
        unsigned cases = 0;
        while (true) {
            std::cin >> std::ws;
            if (std::cin.eof()) break;
            if (!(std::cin >> name)) return 2;
            if (++cases > 4096 || name > 0xffffffffu) return 2;
            Provider provider;
            for (auto& response : provider.responses) {
                uint64_t word;
                if (!(std::cin >> word) || word > 0xffffffffu) return 2;
                response = static_cast<uint32_t>(word);
            }
            const auto value = ts2::legacy_loader_policy(static_cast<uint32_t>(name), provider);
            std::cout << value << ' ' << provider.calls.size();
            for (const auto& call : provider.calls)
                for (auto word : call) std::cout << ' ' << word;
            std::cout << '\n';
        }
        if (cases == 0) return 2;
    } catch (const std::exception&) { return 2; }
}
