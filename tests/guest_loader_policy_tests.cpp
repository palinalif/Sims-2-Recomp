#include "ts2/guest_loader_policy.hpp"
#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)
struct Provider : ts2::GuestLoaderServices {
    std::array<uint32_t, 4> responses{};
    std::vector<std::array<uint32_t, 4>> calls;
    int stop = -1;
    unsigned loads = 0;
    uint32_t record(std::array<uint32_t, 4> call, uint32_t value) {
        calls.push_back(call);
        if (static_cast<int>(calls.size()) == stop)
            throw std::runtime_error("provider stopped");
        return value;
    }
    uint32_t load(uint32_t name, uint32_t file, uint32_t flags) override {
        CHECK(loads < 2);
        return record({1, name, file, flags}, responses[loads++ == 0 ? 0 : 3]);
    }
    uint32_t last_error() override { return record({2, 0, 0, 0}, responses[1]); }
    uint32_t compare(uint32_t a, uint32_t b, uint32_t n) override {
        return record({3, a, b, n}, responses[2]);
    }
};
}
int main() {
    try {
        unsigned cases = 0;
        for (auto name : {0u, 1u, 0x80000000u, 0xffffffffu})
        for (auto first : {0u, 1u, 0x80000000u, 0xfffffffeu})
        for (auto error : {0u, 5u, 87u, 0xffffffffu})
        for (auto comparison : {0u, 1u, 0xffffffffu})
        for (auto retry : {0u, 1u, 0x80000000u, 0xfffffffeu}) {
            Provider p;
            p.responses = {first, error, comparison, retry};
            std::vector<std::array<uint32_t, 4>> expected{{1, name, 0, 0x800}};
            uint32_t value = first;
            if (!first) {
                expected.push_back({2, 0, 0, 0});
                if (error == 87) {
                    expected.push_back({3, name, 0xa0e06e20u, 7});
                    if (comparison) {
                        expected.push_back({1, name, 0, 0});
                        value = retry;
                    }
                }
            }
            CHECK(ts2::legacy_loader_policy(name, p) == value);
            CHECK(p.calls == expected);
            // Every reached dependency may stop; never convert a stop into
            // a null handle, a success or a fallback call. Prior effects remain.
            for (unsigned step = 1; step <= expected.size(); ++step) {
                Provider failing;
                failing.responses = p.responses;
                failing.stop = static_cast<int>(step);
                bool threw = false;
                try { (void)ts2::legacy_loader_policy(name, failing); }
                catch (const std::runtime_error& e) {
                    threw = std::string(e.what()) == "provider stopped";
                }
                CHECK(threw);
                CHECK(failing.calls.size() == step);
                CHECK(std::vector(expected.begin(), expected.begin() + step) == failing.calls);
            }
            ++cases;
        }
        ts2::GuestLoaderServices unavailable;
        bool stopped = false;
        try { (void)ts2::legacy_loader_policy(1, unavailable); }
        catch (const std::runtime_error& e) {
            stopped = std::string(e.what()) == "guest loader: load unavailable";
        }
        CHECK(stopped);
        // Missing later dependencies stop independently of an implemented load.
        struct LoadOnly : ts2::GuestLoaderServices {
            uint32_t load(uint32_t, uint32_t, uint32_t) override { return 0; }
        } load_only;
        stopped = false;
        try { (void)ts2::legacy_loader_policy(1, load_only); }
        catch (const std::runtime_error& e) {
            stopped = std::string(e.what()) == "guest loader: error unavailable";
        }
        CHECK(stopped);
        struct NoCompare : LoadOnly {
            uint32_t last_error() override { return 87; }
        } no_compare;
        stopped = false;
        try { (void)ts2::legacy_loader_policy(1, no_compare); }
        catch (const std::runtime_error& e) {
            stopped = std::string(e.what()) == "guest loader: comparison unavailable";
        }
        CHECK(stopped);
        std::cout << cases << " native policy cases and dependency stops passed\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
