#include "ts2/resource_mount.hpp"
#include <stdexcept>
#include <utility>

namespace ts2 {
std::string ReadOnlyResourceMount::normalized_path(std::string_view path) {
    if(path.empty()) throw std::invalid_argument("empty package path");
    std::string result;
    result.reserve(path.size());
    size_t component_start=0;
    for(size_t i=0;i<path.size();++i) {
        unsigned char ch=static_cast<unsigned char>(path[i]);
        if(ch<32 || ch==127 || ch==':') throw std::invalid_argument("invalid package path character");
        if(ch=='/' || ch=='\\') {
            if(i==component_start) throw std::invalid_argument("empty package path component");
            const auto component=path.substr(component_start,i-component_start);
            if(component=="." || component=="..") throw std::invalid_argument("traversing package path");
            result.push_back('/');
            component_start=i+1;
        } else {
            result.push_back(ch>='A' && ch<='Z' ? static_cast<char>(ch-'A'+'a') : static_cast<char>(ch));
        }
    }
    if(component_start==path.size()) throw std::invalid_argument("empty package path component");
    const auto component=path.substr(component_start);
    if(component=="." || component=="..") throw std::invalid_argument("traversing package path");
    return result;
}
ReadOnlyResourceMount::ReadOnlyResourceMount(std::span<const PackageLayer> layers) {
    layers_.reserve(layers.size());
    for(const auto& layer:layers) {
        if(!layer.package) throw std::invalid_argument("null package layer");
        const auto canonical=normalized_path(layer.path);
        const size_t index=layers_.size();
        if(!paths_.emplace(canonical,index).second) throw std::invalid_argument("duplicate package path");
        std::string display=layer.path;
        for(char& ch:display) if(ch=='\\') ch='/';
        layers_.push_back({std::move(display),layer.package});
        for(const auto& entry:layer.package->entries()) {
            // DIR is package compression metadata, not a game resource.
            if(entry.key.type==0xe86b1eef) continue;
            resources_.insert_or_assign(entry.key,MountedResource{index,entry});
        }
    }
}
std::string_view ReadOnlyResourceMount::package_path(size_t index) const { return layers_.at(index).path; }
const Dbpf* ReadOnlyResourceMount::find_package(std::string_view path) const {
    const auto it=paths_.find(normalized_path(path));
    return it==paths_.end() ? nullptr : layers_[it->second].package;
}
std::optional<MountedResource> ReadOnlyResourceMount::find_resource(ResourceKey key) const {
    const auto it=resources_.find(key);
    if(it==resources_.end()) return std::nullopt;
    return it->second;
}
std::vector<uint8_t> ReadOnlyResourceMount::decode_resource(ResourceKey key,size_t max_decoded_size) const {
    const auto resource=find_resource(key);
    if(!resource) throw std::out_of_range("resource not mounted");
    return layers_[resource->layer_index].package->decode_resource(key,max_decoded_size);
}
}
