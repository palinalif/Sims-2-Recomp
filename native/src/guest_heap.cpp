#include "ts2/guest_heap.hpp"
#include "ts2/guest_dispatch.hpp"
#include "ts2/guest_memory.hpp"
#include <algorithm>
#include <array>
#include <iterator>
#include <stdexcept>

namespace ts2 {
GuestHeap::GuestHeap(GuestMemory& memory, uint32_t handle, uint32_t arena, uint64_t bytes)
    : memory_(memory), handle_(handle) {
    constexpr uint64_t capacity=uint64_t{1}<<32;
    const auto page=memory.page_size();
    if (!handle || !arena || arena%page || !bytes || bytes%page || bytes>capacity-arena)
        throw std::invalid_argument("Invalid guest heap arena or handle");
    // GuestMemory commits whole host pages. Check EVERY page, not just endpoints,
    // without writing or expanding permissions; caller owns exclusivity.
    for (uint64_t offset=0;offset<bytes;offset+=page)
        (void)memory_.read8(static_cast<uint32_t>(uint64_t(arena)+offset));
    blocks_.emplace(arena,Block{bytes,true});
}
void GuestHeap::check_handle(uint32_t handle) const {
    if (handle!=handle_) throw std::invalid_argument("Unknown guest heap handle");
}
uint32_t GuestHeap::allocate(uint32_t handle, uint32_t flags, uint32_t bytes) {
    check_handle(handle);
    if (flags!=0 && flags!=8) throw std::invalid_argument("Unsupported guest HeapAlloc flags");
    const uint64_t rounded=(std::max(uint64_t(bytes),uint64_t{1})+7)&~uint64_t{7};
    for (auto it=blocks_.begin();it!=blocks_.end();++it) {
        auto& block=it->second;
        if (!block.free || block.bytes<rounded) continue;
        const auto address=it->first;
        if (block.bytes>rounded) {
            // Insert before changing the existing block; metadata OOM must not
            // lose the free extent. The split address is strictly inside arena.
            blocks_.emplace(static_cast<uint32_t>(uint64_t(address)+rounded),
                            Block{block.bytes-rounded,true});
        }
        if (flags==8) {
            constexpr std::array<uint8_t,4096> zero{};
            for (uint64_t offset=0;offset<rounded;offset+=zero.size())
                memory_.write_bytes(static_cast<uint32_t>(uint64_t(address)+offset),
                    std::span(zero).first(static_cast<size_t>(std::min(uint64_t(zero.size()),rounded-offset))));
        }
        block={rounded,false,bytes};
        return address;
    }
    return 0;
}
bool GuestHeap::release(uint32_t handle, uint32_t flags, uint32_t address) {
    check_handle(handle);
    if (flags) throw std::invalid_argument("Unsupported guest HeapFree flags");
    auto it=blocks_.find(address);
    if (it==blocks_.end() || it->second.free) return false;
    it->second.free=true;
    const auto next=std::next(it);
    if (next!=blocks_.end() && next->second.free) {
        it->second.bytes+=next->second.bytes;
        blocks_.erase(next);
    }
    if (it!=blocks_.begin()) {
        const auto prev=std::prev(it);
        if (prev->second.free) {
            prev->second.bytes+=it->second.bytes;
            blocks_.erase(it);
        }
    }
    return true;
}
uint32_t GuestHeap::reallocate(uint32_t handle, uint32_t flags, uint32_t address, uint32_t bytes) {
    check_handle(handle);
    if (flags) throw std::invalid_argument("Unsupported guest HeapReAlloc flags");
    auto it=blocks_.find(address);
    if (it==blocks_.end() || it->second.free) return 0;
    auto& block=it->second;
    const uint64_t rounded=(std::max(uint64_t(bytes),uint64_t{1})+7)&~uint64_t{7};
    const auto next=std::next(it);
    if (rounded<=block.bytes) {
        if (rounded<block.bytes) {
            const auto extra=block.bytes-rounded;
            const bool merge=next!=blocks_.end() && next->second.free;
            // Prepare metadata first: host OOM must leave the old block intact.
            blocks_.emplace(static_cast<uint32_t>(uint64_t(address)+rounded),
                            Block{extra+(merge ? next->second.bytes : 0),true});
            if (merge) blocks_.erase(next);
        }
        block={rounded,false,bytes};
        return address;
    }
    if (next!=blocks_.end() && next->second.free && block.bytes+next->second.bytes>=rounded) {
        const auto remaining=block.bytes+next->second.bytes-rounded;
        if (remaining) blocks_.emplace(static_cast<uint32_t>(uint64_t(address)+rounded),Block{remaining,true});
        blocks_.erase(next);
        block={rounded,false,bytes};
        return address;
    }
    // Allocate before releasing: failure preserves both metadata and contents.
    const auto moved=allocate(handle,0,bytes);
    if (!moved) return 0;
    const uint32_t copy=std::min(block.requested,bytes);
    std::array<uint8_t,4096> buffer{};
    for (uint64_t offset=0;offset<copy;offset+=buffer.size()) {
        const auto count=static_cast<size_t>(std::min(uint64_t(buffer.size()),copy-offset));
        for (size_t i=0;i<count;++i)
            buffer[i]=memory_.read8(static_cast<uint32_t>(uint64_t(address)+offset+i));
        memory_.write_bytes(static_cast<uint32_t>(uint64_t(moved)+offset),std::span(buffer).first(count));
    }
    (void)release(handle,0,address);
    return moved;
}
void GuestHeap::invoke_reallocate(GuestRegisters& r) {
    const auto sp=r.esp;
    if (uint64_t(sp)+20>UINT32_MAX) throw std::out_of_range("Guest HeapReAlloc stack overflow");
    (void)memory_.read32(sp);
    const auto handle=memory_.read32(sp+4), flags=memory_.read32(sp+8);
    const auto address=memory_.read32(sp+12), bytes=memory_.read32(sp+16);
    const auto result=reallocate(handle,flags,address,bytes);
    r.eax=result; r.esp=sp+20;
}
void GuestHeap::invoke_allocate(GuestRegisters& r) {
    const auto sp=r.esp;
    // ESP after return must fit in uint32_t too, not merely the last argument.
    if (uint64_t(sp)+16>UINT32_MAX) throw std::out_of_range("Guest HeapAlloc stack overflow");
    (void)memory_.read32(sp);
    const auto handle=memory_.read32(sp+4), flags=memory_.read32(sp+8), bytes=memory_.read32(sp+12);
    const auto result=allocate(handle,flags,bytes);
    r.eax=result; r.esp=sp+16;
}
}
