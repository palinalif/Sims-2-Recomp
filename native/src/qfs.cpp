#include "ts2/qfs.hpp"
#include <stdexcept>

namespace ts2 {
static std::vector<uint8_t> decode_commands(std::span<const uint8_t> bytes,size_t position,size_t expected) {
    const auto take=[&]() -> uint8_t {
        if(position==bytes.size()) throw std::invalid_argument("Truncated QFS stream");
        return bytes[position++];
    };
    take();take();
    size_t declared=take();declared=(declared<<8)|take();declared=(declared<<8)|take();
    if(declared!=expected) throw std::invalid_argument("QFS header and DBPF decoded sizes disagree");
    std::vector<uint8_t> output;
    output.reserve(expected);
    const auto literals=[&](size_t count) {
        if(count>bytes.size()-position || count>expected-output.size())
            throw std::invalid_argument("QFS literal exceeds input/output bounds");
        output.insert(output.end(),bytes.begin()+position,bytes.begin()+position+count);
        position+=count;
    };
    for(;;) {
        const unsigned op=take();
        if(op>=0xfc) {
            literals(op&3);
            if(output.size()!=expected || position!=bytes.size())
                throw std::invalid_argument("QFS stop length mismatch or trailing data");
            return output;
        }
        size_t plain=0,count=0,distance=0;
        if(op>=0xe0) plain=((op&0x1f)<<2)+4;
        else if(op>=0xc0) {
            const unsigned a=take(),b=take(),c=take();
            plain=op&3;count=((op&0x0c)<<6)+c+5;
            distance=((op&0x10)<<12)+(a<<8)+b+1;
        } else if(op>=0x80) {
            const unsigned a=take(),b=take();
            plain=a>>6;count=(op&0x3f)+4;distance=((a&0x3f)<<8)+b+1;
        } else {
            const unsigned a=take();
            plain=op&3;count=((op&0x1c)>>2)+3;distance=((op&0x60)<<3)+a+1;
        }
        literals(plain);
        if(count) {
            if(distance>output.size() || count>expected-output.size())
                throw std::invalid_argument("QFS back-reference exceeds history/output bounds");
            // Deliberately bytewise: copies may consume bytes produced by this copy.
            for(size_t i=0;i<count;++i) output.push_back(output[output.size()-distance]);
        }
    }
}
std::vector<uint8_t> decode_qfs(std::span<const uint8_t> bytes,size_t expected,size_t limit) {
    if(expected>limit) throw std::invalid_argument("QFS decoded size exceeds budget");
    const auto header_matches=[&](size_t offset) {
        return bytes.size()>=offset+5 && bytes[offset]==0x10 && bytes[offset+1]==0xfb &&
            ((size_t(bytes[offset+2])<<16) | (size_t(bytes[offset+3])<<8) | bytes[offset+4])==expected;
    };
    const bool raw=header_matches(0);
    bool prefixed=header_matches(4);
    if(prefixed) {
        const uint32_t stored=uint32_t(bytes[0]) | uint32_t(bytes[1])<<8 |
                              uint32_t(bytes[2])<<16 | uint32_t(bytes[3])<<24;
        prefixed=stored==0 || stored==bytes.size();
    }
    if(!raw && !prefixed) throw std::invalid_argument("Unsupported QFS header or compressed/decoded size mismatch");
    // Both headers may be plausible. Validate the entire framing, including exact
    // output/stop/input consumption, before accepting it. At most two bounded
    // attempts; failed output storage is released before trying the other framing.
    if(raw) {
        try { return decode_commands(bytes,0,expected); }
        catch(const std::invalid_argument&) { if(!prefixed) throw; }
    }
    return decode_commands(bytes,4,expected);
}
}
