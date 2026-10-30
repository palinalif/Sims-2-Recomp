#include "ts2/resource_mount.hpp"
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

static int checks=0;
#define CHECK(x) do { ++checks; if(!(x)) throw std::runtime_error(#x); } while(false)
template<class F> void rejects(F f) { bool threw=false; try { f(); } catch(const std::exception&) { threw=true; } CHECK(threw); }
static void u32(std::vector<uint8_t>& b,size_t offset,uint32_t value) {
    for(unsigned i=0;i<4;++i) b.at(offset+i)=uint8_t(value>>(8*i));
}
static std::vector<uint8_t> package_bytes(uint8_t value) {
    std::vector<uint8_t> b(120);
    b[0]='D';b[1]='B';b[2]='P';b[3]='F';
    u32(b,4,1);u32(b,8,1);u32(b,32,7);u32(b,36,1);
    u32(b,40,100);u32(b,44,20);u32(b,60,1);
    b[96]=value;b[97]=value+1;b[98]=value+2;b[99]=value+3;
    u32(b,100,1);u32(b,104,2);u32(b,108,3);
    u32(b,112,96);u32(b,116,4);
    return b;
}
static std::vector<uint8_t> package_with_dir() {
    auto b=package_bytes(1);
    b.resize(156);
    u32(b,36,2);u32(b,40,116);u32(b,44,40);
    u32(b,100,1);u32(b,104,2);u32(b,108,3);u32(b,112,12);
    u32(b,116,1);u32(b,120,2);u32(b,124,3);u32(b,128,96);u32(b,132,4);
    u32(b,136,0xe86b1eef);u32(b,140,0xe86b1eef);u32(b,144,0x286b1f03);
    u32(b,148,100);u32(b,152,16);
    return b;
}
int main() {
    using namespace ts2;
    try {
        const auto first_bytes=package_bytes(10),last_bytes=package_bytes(20);
        const Dbpf first(first_bytes),last(last_bytes);
        const ResourceKey key{1,2,3};
        const std::vector<PackageLayer> layers{{"Base\\Objects.package",&first},{"EP/Objects.package",&last}};
        const ReadOnlyResourceMount mount(layers);
        CHECK(mount.package_count()==2);
        CHECK(mount.find_package("base/OBJECTS.PACKAGE")==&first);
        CHECK(mount.find_package("EP\\objects.package")==&last);
        CHECK(mount.find_package("none.package")==nullptr);
        CHECK(mount.package_path(0)=="Base/Objects.package");
        CHECK(mount.package_path(1)=="EP/Objects.package");
        const auto found=mount.find_resource(key);
        CHECK(found.has_value());
        CHECK(found->layer_index==1);
        CHECK(found->entry.key==key);
        CHECK(mount.decode_resource(key)==std::vector<uint8_t>({20,21,22,23}));
        CHECK(!mount.find_resource({1,2,4}).has_value());
        const auto dir_bytes=package_with_dir();
        const Dbpf package_with_metadata(dir_bytes);
        const ReadOnlyResourceMount metadata_mount(std::vector<PackageLayer>{{"metadata.package",&package_with_metadata}});
        CHECK(metadata_mount.find_resource(key).has_value());
        CHECK(!metadata_mount.find_resource({0xe86b1eef,0xe86b1eef,0x286b1f03}).has_value());
        rejects([&] { mount.decode_resource({1,2,4}); });
        rejects([&] { mount.decode_resource(key,3); });
        rejects([&] { mount.package_path(2); });
        CHECK(ReadOnlyResourceMount(std::vector<PackageLayer>{{"a",&last},{"b",&first}}).decode_resource(key)==std::vector<uint8_t>({10,11,12,13}));
        rejects([&] { ReadOnlyResourceMount m(std::vector<PackageLayer>{{"a/B.package",&first},{"A\\b.PACKAGE",&last}}); });
        rejects([&] { ReadOnlyResourceMount m(std::vector<PackageLayer>{{"x",nullptr}}); });
        for(const std::string path:{"", "/root", "\\root", "C:drive", "a//b", "a/", "a/./b", "a/../b", "a\\..\\b", "a\nb"})
            rejects([&] { ReadOnlyResourceMount m(std::vector<PackageLayer>{{path,&first}}); });
        rejects([&] { mount.find_package("../Base/Objects.package"); });
        std::cout<<"PASS "<<checks<<" mount checks\n";
    } catch(const std::exception& e) { std::cerr<<"FAIL: "<<e.what()<<'\n';return 1; }
}
