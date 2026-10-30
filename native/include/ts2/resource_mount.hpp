#pragma once
#include "ts2/dbpf.hpp"
#include <cstddef>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ts2 {
// Priority increases with position: the last package containing a key wins.
// The mount copies paths, but borrows packages and their underlying bytes.
struct PackageLayer {
    std::string path;
    const Dbpf* package=nullptr;
};
struct MountedResource {
    size_t layer_index=0;
    DbpfEntry entry;
};
class ReadOnlyResourceMount {
    std::vector<PackageLayer> layers_;
    std::map<std::string,size_t,std::less<>> paths_;
    std::map<ResourceKey,MountedResource> resources_;
    static std::string normalized_path(std::string_view path);
public:
    explicit ReadOnlyResourceMount(std::span<const PackageLayer> layers);
    size_t package_count() const { return layers_.size(); }
    std::string_view package_path(size_t index) const;
    const Dbpf* find_package(std::string_view path) const;
    std::optional<MountedResource> find_resource(ResourceKey key) const;
    std::vector<uint8_t> decode_resource(ResourceKey key,size_t max_decoded_size=64*1024*1024) const;
};
}
