#include "ts2/dbpf.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

static uint64_t number(const char* value) {
    size_t used=0;const std::string text(value);
    if(text.empty() || text.front()=='-') throw std::invalid_argument("Unsigned resource key required");
    const auto result=std::stoull(text,&used,0);
    if(used!=text.size()) throw std::invalid_argument("Malformed resource key");
    return result;
}
int main(int argc,char** argv) {
    if(argc!=2 && argc!=5) {
        std::cerr<<"Usage: ts2_dbpf_probe PACKAGE [TYPE GROUP INSTANCE]\n"
            <<"Lists metadata, or writes one decoded resource to stdout (64 MiB limit). No input files are modified.\n";
        return 2;
    }
    try {
        std::ifstream stream(argv[1],std::ios::binary|std::ios::ate);
        const auto size=stream.tellg();
        if(!stream || size<0 || size>256*1024*1024) throw std::runtime_error("Cannot read package or package exceeds 256 MiB probe budget");
        std::vector<uint8_t> bytes(static_cast<size_t>(size));stream.seekg(0);
        if(!stream.read(reinterpret_cast<char*>(bytes.data()),size)) throw std::runtime_error("Short package read");
        ts2::Dbpf package(bytes);
        if(argc==5) {
            const auto type=number(argv[2]),group=number(argv[3]),instance=number(argv[4]);
            if(type>std::numeric_limits<uint32_t>::max() || group>std::numeric_limits<uint32_t>::max()) throw std::invalid_argument("Type/group exceeds 32 bits");
            const auto data=package.decode_resource({uint32_t(type),uint32_t(group),instance});
#ifdef _WIN32
            if(_setmode(_fileno(stdout),_O_BINARY)==-1) throw std::runtime_error("Cannot set binary stdout mode");
#endif
            std::cout.write(reinterpret_cast<const char*>(data.data()),static_cast<std::streamsize>(data.size()));
            if(!std::cout) throw std::runtime_error("Resource output failed");
        } else {
            std::cout<<"{\"execution_supported\":false,\"entries\":[";bool comma=false;
            for(const auto& entry:package.entries()) {
                if(comma) std::cout<<',';
                comma=true;
                std::cout<<"{\"type\":\"0x"<<std::hex<<entry.key.type<<"\",\"group\":\"0x"<<entry.key.group
                    <<"\",\"instance\":\"0x"<<entry.key.instance<<std::dec<<"\",\"stored_size\":"<<entry.stored_size
                    <<",\"decoded_size\":"<<entry.decoded_size<<",\"compressed\":"<<(entry.compressed?"true":"false")<<'}';
            }
            std::cout<<"]}\n";
        }
    } catch(const std::exception& e) { std::cerr<<"DBPF probe failed: "<<e.what()<<'\n';return 1; }
}
