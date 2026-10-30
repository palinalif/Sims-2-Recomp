#include "ts2/package_probe.hpp"
#include "ts2/dbpf.hpp"
#include <sstream>
#include <stdexcept>

namespace ts2 {
PackageProbe probe_package(std::span<const uint8_t> bytes,size_t package_limit,size_t decoded_limit) {
    if(bytes.size()>package_limit) throw std::invalid_argument("Package exceeds diagnostic byte budget");
    const Dbpf package(bytes);
    size_t compressed=0;const DbpfEntry* selected=nullptr;
    for(const auto& entry:package.entries()) {
        compressed+=entry.compressed;
        if(!selected && entry.key.type!=0xe86b1eef) selected=&entry;
    }
    if(!selected) throw std::invalid_argument("Package has no non-DIR resource to probe");
    PackageProbe probe;
    probe.payload=package.decode_resource(selected->key,decoded_limit);
    std::ostringstream out;
    out<<"{\"execution_supported\":false,\"entry_count\":"<<package.entries().size()
       <<",\"compressed_count\":"<<compressed<<",\"selected\":{\"type\":\"0x"<<std::hex<<selected->key.type
       <<"\",\"group\":\"0x"<<selected->key.group<<"\",\"instance\":\"0x"<<selected->key.instance
       <<std::dec<<"\",\"stored_size\":"<<selected->stored_size<<",\"decoded_size\":"<<probe.payload.size()
       <<",\"compressed\":"<<(selected->compressed?"true":"false")<<"}}";
    probe.summary=out.str();return probe;
}
}
