#include "ts2/guest_storage_selector.hpp"
#include <stdexcept>

namespace ts2 {
void GuestStorageServices::check_target(uint32_t) {
    throw std::runtime_error("storage selector: target guard unavailable");
}
uint32_t GuestStorageServices::read_fls(uint32_t, uint32_t) {
    throw std::runtime_error("storage selector: FLS unavailable");
}
uint32_t GuestStorageServices::read_tls(uint32_t) {
    throw std::runtime_error("storage selector: TLS unavailable");
}
uint32_t legacy_query_storage(GuestMemory& memory, uint32_t cookie_address,
    uint32_t function_cache_address, std::span<const GuestResolverCandidate> candidates,
    uint32_t export_name, uint32_t index, GuestLoaderServices& loader,
    GuestExportServices& exports, GuestStorageServices& storage) {
    const auto target = legacy_resolve_encoded(memory, cookie_address,
        function_cache_address, candidates, export_name, loader, exports);
    if (!target) return storage.read_tls(index);
    storage.check_target(target);
    return storage.read_fls(target, index);
}
}
