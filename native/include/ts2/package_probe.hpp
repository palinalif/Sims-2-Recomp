#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ts2 {
struct PackageProbe { std::string summary; std::vector<uint8_t> payload; };
// Diagnostic only: index one bounded package, decode its first non-DIR resource.
PackageProbe probe_package(std::span<const uint8_t> bytes,
                           size_t max_package_size=16*1024*1024,
                           size_t max_decoded_size=8*1024*1024);
}
