#include "ts2/guest_image.hpp"
#include <iostream>
#include <stdexcept>
#include <functional>

namespace {
int checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error(#x); } while (false)
void put16(std::vector<uint8_t>& b, size_t p, uint16_t v) {
    b.at(p)=uint8_t(v); b.at(p+1)=uint8_t(v>>8);
}
void put32(std::vector<uint8_t>& b, size_t p, uint32_t v) {
    for (unsigned i=0;i<4;++i) b.at(p+i)=uint8_t(v>>(i*8));
}
constexpr size_t opt=0x98, section=opt+224;
std::vector<uint8_t> fixture() {
    std::vector<uint8_t> b(0x600);
    put16(b,0,0x5a4d); put32(b,0x3c,0x80); put32(b,0x80,0x4550);
    put16(b,0x84,0x14c); put16(b,0x86,2); put16(b,0x94,224);
    put16(b,opt,0x10b); put32(b,opt+16,0x1010); put32(b,opt+28,0xa0000000);
    put32(b,opt+32,0x1000); put32(b,opt+36,0x200);
    put32(b,opt+56,0x4000); put32(b,opt+60,0x200); put32(b,opt+92,16);
    put32(b,section+8,0x300); put32(b,section+12,0x1000);
    put32(b,section+16,0x200); put32(b,section+20,0x200);
    put32(b,section+36,0x60000020);
    // raw bytes exceed VirtualSize: retain raw padding, as PE image data.
    put32(b,section+40+8,0x100); put32(b,section+40+12,0x3000);
    put32(b,section+40+16,0x200); put32(b,section+40+20,0x400);
    for (size_t i=0x200;i<b.size();++i) b[i]=uint8_t(i*7+3);
    return b;
}
void bad(const std::function<void(std::vector<uint8_t>&)>& mutate) {
    auto b=fixture(); mutate(b);
    bool rejected=false;
    try { (void)ts2::load_guest_image(b); }
    catch (const std::invalid_argument&) { rejected=true; }
    CHECK(rejected);
}
}
int main() {
    try {
        const auto b=fixture();
        auto image=ts2::load_guest_image(b);
        CHECK(image.image_base == 0xa0000000u);
        CHECK(image.image_size == 0x4000);
        CHECK(image.entry_rva == 0x1010);
        CHECK(image.sections.size() == 2);
        CHECK(image.sections[0].size == 0x300);
        CHECK(image.sections[1].size == 0x200);
        for (size_t i=0;i<0x200;++i) {
            CHECK(image.memory->read8(0xa0000000u+i) == b[i]);
            CHECK(image.memory->read8(0xa0001000u+i) == b[0x200+i]);
            CHECK(image.memory->read8(0xa0003000u+i) == b[0x400+i]);
        }
        // Explicit independent addresses catch file-offset-as-RVA and one-section
        // base displacement. Zero-fill, alignment tails and image gaps stay zero.
        CHECK(image.memory->read8(0xa0000200) == 0);
        CHECK(image.memory->read8(0xa0001010) == b[0x210]);
        CHECK(image.memory->read8(0xa0001210) == 0);
        CHECK(image.memory->read8(0xa0002000) == 0);
        CHECK(image.memory->read8(0xa0003fff) == 0);
        auto peer=ts2::load_guest_image(b);
        image.memory->write32(0xa0001010,0);
        CHECK(peer.memory->read8(0xa0001010) == b[0x210]);
        bad([](auto& x){ put32(x,opt+28,0xa0001000); });
        bad([](auto& x){ put16(x,0x84,0x8664); });
        bad([](auto& x){ put16(x,opt,0x20b); });
        bad([](auto& x){ put16(x,0,0); });
        bad([](auto& x){ put32(x,0x80,0); });
        bad([](auto& x){ put32(x,0x3c,0xfffffff0); });
        bad([](auto& x){ x.resize(0x180); });
        bad([](auto& x){ put16(x,0x86,0); });
        bad([](auto& x){ put16(x,0x86,97); });
        bad([](auto& x){ put16(x,0x94,95); });
        bad([](auto& x){ put32(x,opt+92,17); });
        bad([](auto& x){ put32(x,opt+32,0x1800); });
        bad([](auto& x){ put32(x,opt+32,512); });
        bad([](auto& x){ put32(x,opt+36,0); });
        bad([](auto& x){ put32(x,opt+56,0x10000001); });
        bad([](auto& x){ put32(x,opt+56,0x3100); });
        bad([](auto& x){ put32(x,opt+60,0x100); });
        bad([](auto& x){ put32(x,opt+60,0x800); });
        bad([](auto& x){ put32(x,section+12,0x1100); });
        bad([](auto& x){ put32(x,section+12,0); });
        bad([](auto& x){ put32(x,section+40+12,0x1000); });
        bad([](auto& x){ put32(x,section+8,0x2001); });
        bad([](auto& x){ put32(x,section+8,0xffffffff); });
        bad([](auto& x){ put32(x,section+12,0xfffff000); });
        bad([](auto& x){ put32(x,section+20,0); });
        bad([](auto& x){ put32(x,section+40+20,0x200); });
        bad([](auto& x){ put32(x,section+20,0x201); });
        bad([](auto& x){ put32(x,section+16,0x201); });
        bad([](auto& x){ put32(x,section+16,0xfffffe00); });
        bad([](auto& x){ x.pop_back(); });
        bad([](auto& x){ put32(x,opt+16,0); });
        bad([](auto& x){ put32(x,opt+16,0x2000); });
        bad([](auto& x){ put32(x,opt+16,0x1200); });
        bad([](auto& x){ put32(x,section+36,0x40000040); });
        // Pure zero-filled section has no raw pointer requirement.
        auto zero=fixture(); put32(zero,section+40+16,0); put32(zero,section+40+20,0);
        CHECK(ts2::load_guest_image(zero).memory->read32(0xa0003000) == 0);
        // The pinned image's final section has a non-FileAlignment raw length.
        // Exact checked byte extents are valid; never round the source read up.
        auto tail=fixture();
        put32(tail,section+40+16,0x1f0); tail.resize(0x5f0);
        auto tail_image=ts2::load_guest_image(tail);
        CHECK(tail_image.memory->read8(0xa00031ef) == tail[0x5ef]);
        CHECK(tail_image.memory->read8(0xa00031f0) == 0);
        // End-of-32-bit-space arithmetic must not wrap, even with expected base.
        auto top=fixture(); put32(top,opt+28,0xfffff000);
        bool rejected=false;
        try { (void)ts2::load_guest_image(top,0xfffff000); }
        catch (const std::invalid_argument&) { rejected=true; }
        CHECK(rejected);
        // Bulk write preflights the entire range; no partial prefix modification.
        ts2::GuestMemory mem;
        mem.commit(0x80000000,mem.page_size());
        const uint32_t end=0x80000000u+uint32_t(mem.page_size());
        mem.write32(end-4,0xabcdef01);
        const uint8_t bytes[]{1,2,3,4,5};
        rejected=false;
        try { mem.write_bytes(end-4,bytes); }
        catch (const std::out_of_range&) { rejected=true; }
        CHECK(rejected); CHECK(mem.read32(end-4) == 0xabcdef01);
        rejected=false;
        try { mem.write_bytes(0xfffffffe,bytes); }
        catch (const std::out_of_range&) { rejected=true; }
        CHECK(rejected);
        mem.write_bytes(0x80000001,bytes);
        CHECK(mem.read32(0x80000001) == 0x04030201);
        std::cout << "PASS " << checks << " guest image checks\n";
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << '\n'; return 1;
    }
}
