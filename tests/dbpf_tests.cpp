#include "ts2/dbpf.hpp"
#include "ts2/package_probe.hpp"
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

static int checks=0;
#define CHECK(x) do { ++checks; if(!(x)) throw std::runtime_error(#x); } while(false)
template<class F> void rejects(F f) { bool threw=false;try { f(); } catch(const std::exception&) { threw=true; } CHECK(threw); }
static void u32(std::vector<uint8_t>& bytes,size_t offset,uint32_t value) {
    for(unsigned n=0;n<4;++n) bytes.at(offset+n)=uint8_t(value>>(8*n));
}
static std::vector<uint8_t> fixture(unsigned minor=1,bool compressed=false) {
    const unsigned width=minor==2?24:20,count=compressed?2:1,index=compressed?(minor==2?120:116):100;
    std::vector<uint8_t> bytes(index+count*width);
    bytes[0]='D';bytes[1]='B';bytes[2]='P';bytes[3]='F';
    u32(bytes,4,1);u32(bytes,8,1);u32(bytes,32,7);u32(bytes,36,count);
    u32(bytes,40,index);u32(bytes,44,count*width);u32(bytes,60,minor);
    bytes[96]=1;bytes[97]=2;bytes[98]=3;bytes[99]=4;
    u32(bytes,index,1);u32(bytes,index+4,2);u32(bytes,index+8,3);
    if(minor==2) u32(bytes,index+12,0x12345678);
    u32(bytes,index+width-8,96);u32(bytes,index+width-4,4);
    if(compressed) {
        u32(bytes,100,1);u32(bytes,104,2);u32(bytes,108,3);
        if(minor==2) u32(bytes,112,0x12345678);
        u32(bytes,minor==2?116:112,12);
        const unsigned dir=index+width;
        u32(bytes,dir,0xe86b1eef);u32(bytes,dir+4,0xe86b1eef);u32(bytes,dir+8,0x286b1f03);
        u32(bytes,dir+width-8,100);u32(bytes,dir+width-4,minor==2?20:16);
    }
    return bytes;
}
int main() {
    using namespace ts2;
    try {
        for(unsigned minor:{0u,1u,2u}) {
            const auto bytes=fixture(minor);Dbpf package(bytes);
            CHECK(package.entries().size()==1);
            const uint64_t instance=minor==2?0x1234567800000003ULL:3;
            const auto resource=package.resource({1,2,instance});
            CHECK(resource.size()==4 && resource[0]==1 && resource[3]==4);
            CHECK(!package.entries()[0].compressed);
            rejects([&] { package.resource({1,2,999}); });
        }
        auto bytes=fixture(1,true);Dbpf compressed(bytes);
        CHECK(compressed.entries()[0].compressed);
        CHECK(compressed.entries()[0].decoded_size==12);
        CHECK(compressed.stored_resource({1,2,3}).size()==4);
        rejects([&] { compressed.resource({1,2,3}); });
        const auto wide_bytes=fixture(2,true);Dbpf wide_compressed(wide_bytes);
        CHECK(wide_compressed.entries()[0].key.instance==0x1234567800000003ULL);
        CHECK(wide_compressed.entries()[0].compressed);
        rejects([&] { wide_compressed.resource({1,2,0x1234567800000003ULL}); });
        // Authored valid QFS payload; DIR and index offsets move with insertion.
        auto packed=fixture(1,true);
        const std::vector<uint8_t> qfs{0x10,0xfb,0,0,4,0xe0,1,2,3,4,0xfc};
        packed.insert(packed.begin()+100,7,0);
        std::copy(qfs.begin(),qfs.end(),packed.begin()+96);
        u32(packed,40,123);u32(packed,123+16,11);
        u32(packed,123+20+12,107);u32(packed,107+12,4);
        Dbpf valid_packed(packed);
        CHECK(valid_packed.decode_resource({1,2,3})==std::vector<uint8_t>({1,2,3,4}));
        const auto probe=probe_package(packed);
        CHECK(probe.payload==std::vector<uint8_t>({1,2,3,4}));
        CHECK(probe.summary.find("\"entry_count\":2")!=std::string::npos);
        CHECK(probe.summary.find("\"compressed_count\":1")!=std::string::npos);
        CHECK(probe.summary.find("\"type\":\"0x1\"")!=std::string::npos);
        rejects([&] { probe_package(packed,packed.size()-1,8); });
        rejects([&] { probe_package(packed,packed.size(),3); });
        rejects([&] { valid_packed.decode_resource({1,2,3},3); });
        CHECK(compressed.stored_resource({1,2,3}).size()==4);
        const auto plain_bytes=fixture();Dbpf plain(plain_bytes);
        CHECK(plain.decode_resource({1,2,3})==std::vector<uint8_t>({1,2,3,4}));
        rejects([&] { plain.decode_resource({1,2,3},3); });
        bytes=fixture();bytes.resize(70);rejects([&] { Dbpf p(bytes); });
        bytes=fixture();bytes[0]='X';rejects([&] { Dbpf p(bytes); });
        bytes=fixture();u32(bytes,4,2);rejects([&] { Dbpf p(bytes); });
        bytes=fixture();u32(bytes,60,3);rejects([&] { Dbpf p(bytes); });
        bytes=fixture();u32(bytes,36,0xffffffff);rejects([&] { Dbpf p(bytes); });
        bytes=fixture();u32(bytes,40,0xfffffff0);rejects([&] { Dbpf p(bytes); });
        bytes=fixture();u32(bytes,100+12,0xfffffff0);rejects([&] { Dbpf p(bytes); });
        bytes=fixture();u32(bytes,100+12,100);rejects([&] { Dbpf p(bytes); });
        bytes=fixture();u32(bytes,100+12,8);rejects([&] { Dbpf p(bytes); });
        bytes=fixture(1,true);u32(bytes,116+20+16,15);rejects([&] { Dbpf p(bytes); });
        bytes=fixture(1,true);u32(bytes,136,1);u32(bytes,140,2);u32(bytes,144,3);
        rejects([&] { Dbpf p(bytes); });
        std::cout<<"PASS "<<checks<<" DBPF checks\n";
    } catch(const std::exception& e) { std::cerr<<"FAIL: "<<e.what()<<'\n';return 1; }
}
