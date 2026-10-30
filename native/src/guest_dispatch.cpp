#include "ts2/guest_dispatch.hpp"
#include <cstdio>

namespace ts2 {
namespace {
std::string unresolved_message(uint32_t target) {
    char message[64];
    std::snprintf(message, sizeof(message), "Unresolved guest function VA=0x%08x",
                  static_cast<unsigned>(target));
    return message;
}
}
UnresolvedGuestCall::UnresolvedGuestCall(uint32_t target)
    : std::runtime_error(unresolved_message(target)), target_(target) {}

void GuestDispatch::bind(uint32_t va, Function function) {
    if (!va || !function) throw std::invalid_argument("Invalid guest function binding");
    if (!entries_.emplace(va, function).second)
        throw std::invalid_argument("Guest function VA already bound");
}

void GuestDispatch::invoke(uint32_t va, GuestRegisters& registers, GuestMemory& memory) const {
    const auto entry = entries_.find(va);
    if (entry == entries_.end()) throw UnresolvedGuestCall(va);
    entry->second(registers, memory, *this);
}
}
