#include "ts2/qfs.hpp"
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <span>
#include <stdexcept>
#include <vector>

static int checks=0;
#define CHECK(x) do { ++checks; if(!(x)) throw std::runtime_error(#x); } while(false)
template<class F> void rejects(F f) { bool threw=false;try { f(); } catch(const std::exception&) { threw=true; } CHECK(threw); }
static std::vector<uint8_t> stream(size_t decoded,std::initializer_list<uint8_t> commands,bool prefix=false) {
    std::vector<uint8_t> bytes{0x10,0xfb,uint8_t(decoded>>16),uint8_t(decoded>>8),uint8_t(decoded)};
    bytes.insert(bytes.end(),commands);
    if(prefix) {
        const auto size=bytes.size()+4;
        bytes.insert(bytes.begin(),{uint8_t(size),uint8_t(size>>8),uint8_t(size>>16),uint8_t(size>>24)});
    }
    return bytes;
}
int main() {
    try {
        using ts2::decode_qfs;
        // Authored literal/stop, short/medium/long copies and overlapping history.
        CHECK(decode_qfs(stream(4,{0xe0,1,2,3,4,0xfc}),4,64)==std::vector<uint8_t>({1,2,3,4}));
        CHECK(decode_qfs(stream(3,{0xff,'a','b','c'},true),3,64)==std::vector<uint8_t>({'a','b','c'}));
        CHECK(decode_qfs(stream(4,{0x01,0x00,'x',0xfc}),4,64)==std::vector<uint8_t>(4,'x'));
        CHECK(decode_qfs(stream(5,{0x80,0x40,0x00,'y',0xfc}),5,64)==std::vector<uint8_t>(5,'y'));
        CHECK(decode_qfs(stream(6,{0xc1,0x00,0x00,0x00,'z',0xfc}),6,64)==std::vector<uint8_t>(6,'z'));
        CHECK(decode_qfs(stream(0,{0xfc}),0,0).empty());
        // A raw stream's size/literal bytes may coincidentally spell 10 FB at offset 4.
        auto ambiguous=stream(272,{});
        for(unsigned block=0;block<3;++block) {
            const unsigned length=block<2?112:48;
            ambiguous.push_back(uint8_t(0xe0+(length-4)/4));
            ambiguous.insert(ambiguous.end(),length,'a');
        }
        ambiguous.push_back(0xfc);
        CHECK(decode_qfs(ambiguous,272,512)==std::vector<uint8_t>(272,'a'));
        // Even a coincidental prefix-size match must not override the DIR-matched raw header.
        auto size_alias=stream(262160,{});
        for(unsigned block=0;block<64250;++block) {
            const unsigned length=block<47?112:block==47?88:4;
            size_alias.push_back(uint8_t(0xe0+(length-4)/4));size_alias.insert(size_alias.end(),length,0);
        }
        size_alias.push_back(0xfc);
        CHECK(size_alias.size()==326416);
        CHECK(decode_qfs(size_alias,262160,300000)==std::vector<uint8_t>(262160,0));
        auto prefixed_alias=stream(262160,{});
        prefixed_alias.insert(prefixed_alias.begin(),{0x10,0xfb,4,0});
        for(unsigned block=0;block<64246;++block) {
            const unsigned length=block<47?112:block==47?104:4;
            prefixed_alias.push_back(uint8_t(0xe0+(length-4)/4));prefixed_alias.insert(prefixed_alias.end(),length,0);
        }
        prefixed_alias.push_back(0xfc);
        CHECK(prefixed_alias.size()==326416);
        CHECK(decode_qfs(prefixed_alias,262160,300000)==std::vector<uint8_t>(262160,0));
        // Exercise the high distance bits and maximum match lengths of all forms.
        for(unsigned form=0;form<3;++form) {
            const size_t distance=form==0?1024:form==1?16384:131072;
            const size_t copied=form==0?10:form==1?67:1028;
            auto encoded=stream(distance+copied,{});
            std::vector<uint8_t> expected;
            for(size_t start=0;start<distance;) {
                const size_t length=std::min(size_t(112),distance-start);
                encoded.push_back(uint8_t(0xe0+(length-4)/4));
                for(size_t i=0;i<length;++i) {
                    const auto value=uint8_t((start+i)^((start+i)>>8)^((start+i)>>16));
                    encoded.push_back(value);expected.push_back(value);
                }
                start+=length;
            }
            if(form==0) encoded.insert(encoded.end(),{0x7c,0xff});
            else if(form==1) encoded.insert(encoded.end(),{0xbf,0x3f,0xff});
            else encoded.insert(encoded.end(),{0xdc,0xff,0xff,0xff});
            encoded.push_back(0xfc);
            for(size_t i=0;i<copied;++i) expected.push_back(expected[i]);
            CHECK(decode_qfs(encoded,expected.size(),200000)==expected);
        }
        auto valid=stream(4,{0xe0,1,2,3,4,0xfc},true);
        for(size_t n=0;n<valid.size();++n) rejects([&] { decode_qfs(std::span(valid).first(n),4,64); });
        rejects([&] { decode_qfs(valid,4,3); });
        rejects([&] { decode_qfs(valid,5,64); });
        auto bad=valid;bad[0]++;rejects([&] { decode_qfs(bad,4,64); });
        bad=valid;bad[4]=0x90;rejects([&] { decode_qfs(bad,4,64); });
        bad=valid;bad.push_back(0);bad[0]++;rejects([&] { decode_qfs(bad,4,64); });
        rejects([&] { decode_qfs(stream(3,{0,0,0xfc}),3,64); }); // no history
        rejects([&] { decode_qfs(stream(4,{0x01,1,'x',0xfc}),4,64); }); // history underflow after literal
        rejects([&] { decode_qfs(stream(3,{0xe0,1,2,3,4,0xfc}),3,64); }); // output overflow
        rejects([&] { decode_qfs(stream(8,{0xe0,1,2,3,4,0xfc}),8,64); }); // output underflow
        rejects([&] { decode_qfs(stream(4,{0x80,0x40}),4,64); });
        rejects([&] { decode_qfs(stream(5,{0xc0,0,0}),5,64); });
        // Every single-byte mutation must either decode within the exact bound or reject.
        for(size_t pos=0;pos<valid.size();++pos) {
            for(unsigned value=0;value<256;++value) {
                auto mutation=valid;mutation[pos]=uint8_t(value);
                try { CHECK(decode_qfs(mutation,4,64).size()==4); }
                catch(const std::invalid_argument&) { ++checks; }
            }
        }
        std::cout<<"PASS "<<checks<<" QFS checks\n";
    } catch(const std::exception& e) { std::cerr<<"FAIL: "<<e.what()<<'\n';return 1; }
}
