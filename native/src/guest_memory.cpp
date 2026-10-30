#include "ts2/guest_memory.hpp"
#include <sys/mman.h>
#include <unistd.h>
#include <stdexcept>
#include <algorithm>
#include <cstring>
namespace ts2 {
static constexpr uint64_t capacity=uint64_t{1}<<32;
GuestMemory::GuestMemory() {
    static_assert(sizeof(void*)>=8,"Guest memory requires a 64-bit host");
    const long size=sysconf(_SC_PAGESIZE);
    if (size<=0) throw std::runtime_error("Cannot query page size");
    page_=static_cast<size_t>(size);
    void* p=mmap(nullptr,capacity,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE,-1,0);
    if(p==MAP_FAILED) throw std::runtime_error("Cannot reserve guest address space");
    base_=static_cast<uint8_t*>(p);
}
GuestMemory::~GuestMemory() { munmap(base_,capacity); }
void GuestMemory::commit(uint32_t a,uint64_t bytes) {
    if (!bytes || bytes>capacity-a) throw std::out_of_range("Invalid guest commit range");
    uint64_t start=uint64_t(a)/page_*page_, end=(uint64_t(a)+bytes+page_-1)/page_*page_;
    if (!start) throw std::invalid_argument("Guest null page is protected");
    if (mprotect(base_+start,end-start,PROT_READ|PROT_WRITE)) throw std::runtime_error("Guest commit failed");
    auto it=regions_.lower_bound(start);
    if (it!=regions_.begin()) { auto prev=std::prev(it); if (prev->second>=start) it=prev; }
    while(it!=regions_.end() && it->first<=end) {
        start=std::min(start,it->first); end=std::max(end,it->second); it=regions_.erase(it);
    }
    regions_[start]=end;
}
uint8_t* GuestMemory::checked(uint32_t a,uint64_t bytes) const {
    if (bytes>capacity-a) throw std::out_of_range("Guest address overflow");
    auto it=regions_.upper_bound(a);
    if(it==regions_.begin() || uint64_t(a)+bytes>(--it)->second) throw std::out_of_range("Uncommitted guest address");
    return base_+a;
}
uint8_t GuestMemory::read8(uint32_t a) const { return *checked(a,1); }
uint16_t GuestMemory::read16(uint32_t a) const {
    const auto* p=checked(a,2);
    return uint16_t(uint16_t(p[0]) | uint16_t(p[1])<<8);
}
uint32_t GuestMemory::read32(uint32_t a) const {
    const auto* p=checked(a,4);
    return uint32_t(p[0]) | uint32_t(p[1])<<8 | uint32_t(p[2])<<16 | uint32_t(p[3])<<24;
}
void GuestMemory::write_bytes(uint32_t a,std::span<const uint8_t> bytes) {
    if (bytes.empty()) return;
    auto* destination=checked(a,bytes.size());
    std::memmove(destination,bytes.data(),bytes.size());
}
void GuestMemory::write32(uint32_t a,uint32_t value) {
    auto* p=checked(a,4); for(unsigned i=0;i<4;++i) p[i]=uint8_t(value>>(8*i));
}
}
