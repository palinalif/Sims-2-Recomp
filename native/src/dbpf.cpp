#include "ts2/dbpf.hpp"
#include "ts2/qfs.hpp"
#include <stdexcept>

namespace ts2 {
static uint32_t read32(std::span<const uint8_t> data,size_t offset) {
    if(offset>data.size() || data.size()-offset<4) throw std::out_of_range("Truncated DBPF integer");
    return uint32_t(data[offset]) | uint32_t(data[offset+1])<<8 | uint32_t(data[offset+2])<<16 | uint32_t(data[offset+3])<<24;
}
static ResourceKey key_at(std::span<const uint8_t> data,size_t offset,bool wide) {
    ResourceKey key{read32(data,offset),read32(data,offset+4),read32(data,offset+8)};
    if(wide) key.instance|=uint64_t(read32(data,offset+12))<<32;
    return key;
}
Dbpf::Dbpf(std::span<const uint8_t> bytes):bytes_(bytes) {
    if(bytes.size()<96 || bytes[0]!='D' || bytes[1]!='B' || bytes[2]!='P' || bytes[3]!='F')
        throw std::invalid_argument("Invalid DBPF header");
    if(read32(bytes,4)!=1 || read32(bytes,8)>1 || read32(bytes,32)!=7 || read32(bytes,60)>2)
        throw std::invalid_argument("Unsupported DBPF/index version");
    const bool wide=read32(bytes,60)==2;
    const uint32_t count=read32(bytes,36),offset=read32(bytes,40),size=read32(bytes,44);
    const size_t width=wide?24:20;
    if(count>1000000 || uint64_t(count)*width!=size || uint64_t(offset)+size>bytes.size() || (count && offset<96))
        throw std::invalid_argument("Invalid DBPF index bounds/count");
    entries_.reserve(count);
    for(uint32_t i=0;i<count;++i) {
        const size_t position=size_t(offset)+i*width;
        DbpfEntry entry{key_at(bytes,position,wide),read32(bytes,position+width-8),read32(bytes,position+width-4),0,false};
        const uint64_t end=uint64_t(entry.offset)+entry.stored_size;
        if(end>bytes.size() || (entry.stored_size && (entry.offset<96 || (entry.offset<uint64_t(offset)+size && end>offset))))
            throw std::invalid_argument("DBPF resource overlaps header/index or exceeds file");
        if(!lookup_.emplace(entry.key,entries_.size()).second) throw std::invalid_argument("Duplicate DBPF resource key");
        entry.decoded_size=entry.stored_size;entries_.push_back(entry);
    }
    // TS2's DIR resource records which payloads require QFS/RefPack decoding.
    // Record decoded sizes for bounded QFS reads; leave stored bytes untouched.
    for(const auto& directory:entries_) {
        if(directory.key.type!=0xe86b1eef) continue;
        const auto data=bytes.subspan(directory.offset,directory.stored_size);
        const size_t record_size=wide?20:16;
        if(data.size()%record_size) throw std::invalid_argument("Malformed DBPF compression directory");
        for(size_t position=0;position<data.size();position+=record_size) {
            const auto key=key_at(data,position,wide);const auto found=lookup_.find(key);
            if(found==lookup_.end() || key.type==0xe86b1eef) throw std::invalid_argument("Invalid compression directory reference");
            auto& entry=entries_[found->second];const auto decoded=read32(data,position+record_size-4);
            if(!decoded || entry.compressed) throw std::invalid_argument("Invalid/duplicate compressed resource record");
            entry.compressed=true;entry.decoded_size=decoded;
        }
    }
}
const DbpfEntry& Dbpf::find(ResourceKey key) const {
    const auto it=lookup_.find(key);
    if(it==lookup_.end()) throw std::out_of_range("DBPF resource key not found");
    return entries_[it->second];
}
std::vector<uint8_t> Dbpf::decode_resource(ResourceKey key,size_t limit) const {
    const auto& entry=find(key);
    if(entry.decoded_size>limit) throw std::invalid_argument("DBPF decoded resource exceeds budget");
    const auto bytes=stored_resource(key);
    if(entry.compressed) return decode_qfs(bytes,entry.decoded_size,limit);
    return {bytes.begin(),bytes.end()};
}
std::span<const uint8_t> Dbpf::stored_resource(ResourceKey key) const {
    const auto& entry=find(key);return bytes_.subspan(entry.offset,entry.stored_size);
}
std::span<const uint8_t> Dbpf::resource(ResourceKey key) const {
    if(find(key).compressed) throw std::runtime_error("Compressed resource requires decode_resource()");
    return stored_resource(key);
}
}
