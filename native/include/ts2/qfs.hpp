#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace ts2 {
// Bounded TS2 QFS: 10 FB with a 24-bit size, optionally preceded by a
// little-endian compressed size. The DBPF DIR size must agree with the header.
// Other flag/header variants fail explicitly until independently validated.
std::vector<uint8_t> decode_qfs(std::span<const uint8_t> bytes,size_t expected_size,
                               size_t max_decoded_size=64*1024*1024);
}
