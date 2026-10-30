#pragma once
#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
namespace ts2 {
class GuestMemory {
    uint8_t* base_;
    size_t page_;
    std::map<uint64_t,uint64_t> regions_;
    uint8_t* checked(uint32_t address,uint64_t bytes) const;
public:
    GuestMemory();
    ~GuestMemory();
    GuestMemory(const GuestMemory&)=delete;
    GuestMemory& operator=(const GuestMemory&)=delete;
    size_t page_size() const { return page_; }
    void commit(uint32_t address,uint64_t bytes);
    uint8_t read8(uint32_t address) const;
    uint16_t read16(uint32_t address) const;
    uint32_t read32(uint32_t address) const;
    void write32(uint32_t address,uint32_t value);
    void write_bytes(uint32_t address,std::span<const uint8_t> bytes);
};
}
