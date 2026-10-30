#include "ts2/input.hpp"
#include "ts2/guest_memory.hpp"
#include "ts2/diagnostic.hpp"
#include <cmath>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

static int checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) throw std::runtime_error(#x); } while (false)
template<class F> void rejects(F f) {
    bool threw = false; try { f(); } catch (const std::exception&) { threw = true; }
    CHECK(threw);
}
int main() {
    using namespace ts2;
    try {
        Input in; Pad p; p.connected = true;
        p.lx = .1f; p.ly = .1f;
        CHECK(in.update(p, .016f).cursor_x == .5f);
        p.lx = 1; p.ly = 0;
        const auto start = in.update(p, .016f).cursor_x;
        CHECK(start > .5f);
        CHECK(in.update(p, 100.f).cursor_x - start < .1f);
        p.lx = std::numeric_limits<float>::quiet_NaN();
        CHECK(std::isfinite(in.update(p, .016f).cursor_x));
        p.buttons = bit(Button::A);
        CHECK(in.update(p, .016f).pressed & bit(Action::Select));
        CHECK(!(in.update(p, .016f).pressed & bit(Action::Select)));
        p.connected = false;
        CHECK(in.update(p, .016f).held == 0);
        p.connected = true;
        CHECK(in.update(p, .016f).pressed & bit(Action::Select));
        in.reset(); p = {}; p.connected = true; p.buttons = bit(Button::Mode);
        CHECK(in.update(p, .016f).mode == Mode::Navigation);
        p.buttons = bit(Button::Right);
        CHECK(in.update(p, .016f).pressed & bit(Action::FocusRight));
        bool repeated = false;
        for (int i = 0; i < 60; ++i) repeated |= bool(in.update(p, .016f).pressed & bit(Action::FocusRight));
        CHECK(repeated);
        Config config; config.mapping[static_cast<int>(Button::A)] = Action::Context;
        in.configure(config); in.reset(); p.buttons = bit(Button::A);
        CHECK(in.update(p, .016f).pressed & bit(Action::Context));
        config.deadzone = 1; rejects([&] { in.configure(config); });
        config.deadzone=.18f;config.mapping[0]=static_cast<Action>(-1);
        rejects([&] { in.configure(config); });
        config.mapping[0]=Action::Count; rejects([&] { in.configure(config); });
        Input sampled;Pad tapped;tapped.connected=true;tapped.buttons=bit(Button::A);
        sampled.sample(tapped);tapped.buttons=0;sampled.sample(tapped);
        const auto tap=sampled.update(tapped,.016f);
        CHECK(tap.pressed & bit(Action::Select));CHECK(tap.released & bit(Action::Select));CHECK(tap.held==0);
        CHECK(sampled.update(tapped,.016f).pressed==0);
        Input slow, fast; p.buttons = 0; p.lx = .7f;
        for (int i=0;i<30;i++) slow.update(p,1.f/30);
        for (int i=0;i<120;i++) fast.update(p,1.f/120);
        CHECK(std::abs(slow.state().cursor_x-fast.state().cursor_x)<.002f);
        Diagnostic d; ActionState s; s.mode=Mode::Navigation;
        s.pressed=bit(Action::FocusRight); d.update(s); CHECK(d.focus==1);
        s.pressed=bit(Action::FocusDown); d.update(s); CHECK(d.focus==4);
        s.pressed=bit(Action::Select); CHECK(d.update(s)==4);
        Diagnostic cursor_focus;ActionState cursor;
        cursor_focus.update(cursor);const int initial_focus=cursor_focus.focus;
        cursor.pressed=bit(Action::FocusRight);cursor_focus.update(cursor);
        CHECK(cursor_focus.focus!=initial_focus);
        cursor.mode=Mode::Navigation;cursor.cursor_x=.1f;cursor.cursor_y=.6f;
        cursor.pointer_event=true;cursor.pressed=bit(Action::Select);
        CHECK(cursor_focus.update(cursor)==3);
        std::vector<uint32_t> pixels(66*32+2,0x12345678);
        d.draw(pixels.data()+1,64,32,66,s);
        CHECK(pixels.front()==0x12345678 && pixels.back()==0x12345678);
        CHECK(pixels[65]==0x12345678); // stride padding untouched
        CHECK(pixels[1]!=0x12345678);
        GuestMemory mem; const auto page=mem.page_size();
        rejects([&] { mem.commit(0,4); });
        rejects([&] { mem.read32(0x400000); });
        mem.commit(0x400000, page);
        mem.write32(0x400001,0x89abcdef);
        CHECK(mem.read32(0x400001)==0x89abcdef);
        CHECK(mem.read8(0x400001)==0xef && mem.read8(0x400004)==0x89);
        mem.commit(0xffff0000u,page);
        mem.write32(0xffff0000u,0x80000000u);
        CHECK(mem.read32(0xffff0000u)==0x80000000u);
        rejects([&] { mem.commit(0xfffffff0u,64); });
        rejects([&] { mem.write32(0xffffffffu,1); });
        rejects([&] { mem.commit(0x10000,0); });
        std::cout << "PASS " << checks << " core checks; page_size=" << page << '\n';
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << '\n'; return 1;
    }
}
