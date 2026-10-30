#include "ts2/guest_cpu.hpp"
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
int checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error(#x); } while (false)
bool same(const ts2::GuestRegisters& a, const ts2::GuestRegisters& b) {
    return a.eax == b.eax && a.ebx == b.ebx && a.ecx == b.ecx && a.edx == b.edx &&
           a.esp == b.esp && a.ebp == b.ebp && a.esi == b.esi && a.edi == b.edi &&
           a.eflags == b.eflags;
}
template<class F> void rejects_unchanged(F f, ts2::GuestRegisters& r,
                                        const std::string& diagnostic) {
    const auto before = r;
    bool threw = false;
    try { f(); } catch (const std::out_of_range& e) {
        threw = true;
        CHECK(std::string(e.what()).find(diagnostic) != std::string::npos);
    }
    CHECK(threw);
    CHECK(same(r, before));
}
template<class F> void rejects_duplicate(F f) {
    bool threw = false;
    try { f(); } catch (const std::invalid_argument&) { threw = true; }
    CHECK(threw);
}
}
int main() {
    try {
        // Authored asymmetric outputs catch EAX/EBX/ECX/EDX ordering errors.
        // No profile here claims native ISA coverage or game-startup safety.
        const ts2::GuestCpu a({{0, 0, {1, 0xabcdef01u, 0x23456789u, 0xfedcba98u}},
                               {1, 0, {0, 0, 0, 0}},
                               {7, 0, {0x80000001u, 2, 3, 4}},
                               {7, 1, {5, 6, 7, 8}},
                               {0x80000000u, 0xffffffffu, {9, 10, 11, 12}}},
                              {{0, 0xfedcba9889abcdefull}, {1, 0}});
        const ts2::GuestCpu b({{0, 0, {13, 14, 15, 16}}}, {{0, 6}});
        const ts2::GuestCpu empty({});
        for (uint32_t i = 0; i < 128; ++i) {
            ts2::GuestRegisters r{0, 0, i * 0x1020304u, ~i, 0xa1000000u + i,
                                  0xb2000000u + i, 0xc3000000u + i,
                                  0xd4000000u + i, i * 0x01010101u};
            auto expected = r;
            expected.eax = 1; expected.ebx = 0xabcdef01u;
            expected.ecx = 0x23456789u; expected.edx = 0xfedcba98u;
            a.cpuid(r);
            CHECK(same(r, expected));
            r.eax = 0; r.ecx = 0;
            expected = r;
            expected.eax = 13; expected.ebx = 14; expected.ecx = 15; expected.edx = 16;
            b.cpuid(r);
            CHECK(same(r, expected));
            // CPUID must assign zero outputs, not treat zeros as no response.
            r.eax = 1; r.ecx = 0;
            expected = r;
            expected.eax = expected.ebx = expected.ecx = expected.edx = 0;
            a.cpuid(r);
            CHECK(same(r, expected));
            for (uint32_t subleaf : {0u, 1u}) {
                r.eax = 7; r.ecx = subleaf;
                expected = r;
                expected.eax = subleaf ? 5u : 0x80000001u;
                expected.ebx = subleaf ? 6u : 2u;
                expected.ecx = subleaf ? 7u : 3u;
                expected.edx = subleaf ? 8u : 4u;
                a.cpuid(r);
                CHECK(same(r, expected));
            }
            r.eax = 0x80000000u; r.ecx = 0xffffffffu;
            expected = r;
            expected.eax = 9; expected.ebx = 10; expected.ecx = 11; expected.edx = 12;
            a.cpuid(r);
            CHECK(same(r, expected));
            // XGETBV consumes only ECX; ignores prior EAX/EDX, preserves EBX,
            // ECX, flags, stack and non-output GPRs. High half must not truncate.
            r.ecx = 0; r.eax = ~i; r.edx = i;
            expected = r;
            expected.eax = 0x89abcdefu; expected.edx = 0xfedcba98u;
            a.xgetbv(r);
            CHECK(same(r, expected));
            expected.eax = 6; expected.edx = 0;
            b.xgetbv(r);
            CHECK(same(r, expected));
            r.ecx = 1; expected = r;
            expected.eax = expected.edx = 0;
            a.xgetbv(r);
            CHECK(same(r, expected));
        }
        ts2::GuestRegisters r{7, 2, 0xffffffffu, 0x87654321u, 5, 6, 7, 8, 0xffffffffu};
        rejects_unchanged([&] { a.cpuid(r); }, r, "subleaf=0x00000002");
        r.eax = 0xffffffffu; r.ecx = 0;
        rejects_unchanged([&] { a.cpuid(r); }, r, "leaf=0xffffffff");
        r.eax = 0; r.ecx = 1;
        rejects_unchanged([&] { a.cpuid(r); }, r, "subleaf=0x00000001");
        r.ecx = 0x80000000u;
        rejects_unchanged([&] { a.xgetbv(r); }, r, "index=0x80000000");
        r.eax = r.ecx = 0;
        rejects_unchanged([&] { empty.cpuid(r); }, r, "CPUID");
        rejects_unchanged([&] { empty.xgetbv(r); }, r, "XGETBV");
        // No maximum-leaf inference, nearest-subleaf fallback, host detection,
        // automatic XCR0, or global 'last selected CPU'.
        r.eax = 1;
        rejects_unchanged([&] { b.cpuid(r); }, r, "leaf=0x00000001");
        rejects_duplicate([] { const ts2::GuestCpu bad({{0, 0, {}}, {0, 0, {1, 2, 3, 4}}}); });
        rejects_duplicate([] { const ts2::GuestCpu bad({}, {{0, 0}, {0, 6}}); });
        std::cout << "PASS " << checks << " guest CPU checks\n";
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << '\n';
        return 1;
    }
}
