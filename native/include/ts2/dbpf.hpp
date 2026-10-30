#pragma once
#include <compare>
#include <cstdint>
#include <map>
#include <span>
#include <vector>

namespace ts2 {
struct ResourceKey {
    uint32_t type=0,group=0;
    uint64_t instance=0;
    auto operator<=>(const ResourceKey&) const = default;
};
struct DbpfEntry {
    ResourceKey key;
    uint32_t offset=0,stored_size=0,decoded_size=0;
    bool compressed=false;
};
// Caller owns the immutable package bytes and must keep them alive. Payloads are
// bounded borrowed spans; no game structures or host pointers are serialized.
class Dbpf {
    std::span<const uint8_t> bytes_;
    std::vector<DbpfEntry> entries_;
    std::map<ResourceKey,size_t> lookup_;
    const DbpfEntry& find(ResourceKey key) const;
public:
    explicit Dbpf(std::span<const uint8_t> bytes);
    std::span<const DbpfEntry> entries() const { return entries_; }
    std::span<const uint8_t> stored_resource(ResourceKey key) const;
    std::span<const uint8_t> resource(ResourceKey key) const; // Uncompressed borrowed view only.
    // Owned decoded output; validates the DIR/header size and budget before allocation.
    std::vector<uint8_t> decode_resource(ResourceKey key,size_t max_decoded_size=64*1024*1024) const;
};
}
