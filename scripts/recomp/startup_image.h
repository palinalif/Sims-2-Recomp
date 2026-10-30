// Development-only scoped startup seam. No raw host pointers escape GuestMemory.
#pragma once
#include <cstdint>
void ts2_startup_bind(void (*init)(uint32_t*), void (*helper)(uint32_t*));
// Optional entry observation: stop throws through generated frames, never resumes
// the lifted tail. Only the outer observer returns the captured boundary state.
void ts2_startup_bind_entry(void (*entry)(uint32_t*));
uint32_t ts2_startup_observe_entry(uint32_t state[9]);
[[noreturn]] void ts2_startup_stop(uint32_t target, const uint32_t state[9]);
void ts2_startup_begin(uint32_t stack, uint32_t sp, uint32_t cookie);
void ts2_startup_invoke(uint32_t va, uint32_t state[9]);
uint32_t ts2_startup_read(uint32_t address);
void ts2_startup_write(uint32_t address, uint32_t value);
// Observation only: physical bytes, never the read-only IAT binding overlay.
uint32_t ts2_startup_peek(uint32_t address);
struct Ts2StartupWord {
    uint32_t address;
    operator uint32_t() const { return ts2_startup_read(address); }
    Ts2StartupWord& operator=(uint32_t value) {
        ts2_startup_write(address,value); return *this;
    }
    Ts2StartupWord& operator=(const Ts2StartupWord& other) {
        return *this=uint32_t(other);
    }
};
