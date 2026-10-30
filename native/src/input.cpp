#include "ts2/input.hpp"
#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace ts2 {
static float axis(float v) { return std::isfinite(v) ? std::clamp(v,-1.f,1.f) : 0.f; }
static std::array<float,2> stick(float x,float y,float deadzone,float exponent) {
    x=axis(x); y=axis(y); const float length=std::hypot(x,y);
    if (length<=deadzone) return {0,0};
    const float scale=std::pow((std::min(length,1.f)-deadzone)/(1-deadzone),exponent)/length;
    return {x*scale,y*scale};
}
void Input::configure(const Config& c) {
    if (!std::isfinite(c.deadzone) || c.deadzone<0 || c.deadzone>.8f ||
        !std::isfinite(c.sensitivity) || c.sensitivity<.05f || c.sensitivity>3 ||
        !std::isfinite(c.acceleration) || c.acceleration<1 || c.acceleration>4)
        throw std::invalid_argument("Invalid input configuration");
    for (auto action:c.mapping) if (static_cast<int>(action)<0 || action>=Action::Count) throw std::invalid_argument("Invalid action");
    config_=c; reset();
}
void Input::reset() {
    const auto mode=state_.mode; const float x=state_.cursor_x,y=state_.cursor_y;
    state_={}; state_.mode=mode; state_.cursor_x=x; state_.cursor_y=y;
    repeat_=0; prior_directions_=0;
    sampled_held_=pending_pressed_=pending_released_=0;
    has_samples_=pending_toggle_=pointer_pending_=false;
}
void Input::pointer(float x,float y) {
    state_.cursor_x=std::clamp(axis(x),0.f,1.f); state_.cursor_y=std::clamp(axis(y),0.f,1.f);
    pointer_pending_=true;
}
uint32_t Input::actions(const Pad& p) const {
    uint32_t held=0;
    if (p.connected) for (unsigned i=0;i<config_.mapping.size();++i)
        if (p.buttons & (1u<<i)) held|=bit(config_.mapping[i]);
    return held;
}
void Input::sample(const Pad& p) {
    const uint32_t held=actions(p), pressed=held & ~sampled_held_;
    pending_pressed_|=pressed; pending_released_|=sampled_held_ & ~held;
    if(pressed & bit(Action::ToggleMode)) pending_toggle_=!pending_toggle_;
    sampled_held_=held;has_samples_=true;
}
const ActionState& Input::update(const Pad& p,float seconds) {
    const float dt=std::isfinite(seconds) ? std::clamp(seconds,0.f,.05f) : 0.f;
    const uint32_t held=actions(p);
    state_.pressed=(held & ~state_.held) | pending_pressed_;
    state_.released=(state_.held & ~held) | pending_released_; state_.held=held;
    if(has_samples_?pending_toggle_:bool(state_.pressed & bit(Action::ToggleMode))) toggle_mode();
    sampled_held_=held;pending_pressed_=pending_released_=0;has_samples_=pending_toggle_=false;
    const float prior_x=state_.cursor_x,prior_y=state_.cursor_y;
    const auto left=stick(p.connected?p.lx:0,p.connected?p.ly:0,config_.deadzone,config_.acceleration);
    const auto right=stick(p.connected?p.rx:0,p.connected?p.ry:0,config_.deadzone,1);
    if (state_.mode==Mode::Cursor) {
        state_.cursor_x=std::clamp(state_.cursor_x+left[0]*config_.sensitivity*dt,0.f,1.f);
        state_.cursor_y=std::clamp(state_.cursor_y+left[1]*config_.sensitivity*dt,0.f,1.f);
    }
    state_.pointer_event=pointer_pending_ || prior_x!=state_.cursor_x || prior_y!=state_.cursor_y;
    pointer_pending_=false;
    state_.camera_x=right[0]; state_.camera_y=right[1];
    state_.zoom=p.connected?std::max(0.f,axis(p.rt))-std::max(0.f,axis(p.lt)):0;
    state_.rotation=float(bool(held & bit(Action::RotateRight)))-float(bool(held & bit(Action::RotateLeft)));
    constexpr uint32_t directions=bit(Action::FocusUp)|bit(Action::FocusDown)|bit(Action::FocusLeft)|bit(Action::FocusRight);
    const uint32_t active=held & directions;
    if (active!=prior_directions_) repeat_=.35f;
    else if (active && (repeat_-=dt)<=0) { state_.pressed|=active; repeat_+=.09f; }
    prior_directions_=active;
    return state_;
}
const char* action_name(Action a) {
    constexpr const char* names[]={"Select","Cancel","Context","Next Sim","Rotate left","Rotate right",
        "Pause / menu","Toggle mode","Speed down","Speed up","Focus up","Focus down","Focus left","Focus right","Build / Buy","Text entry"};
    return a<Action::Count?names[static_cast<unsigned>(a)]:"Unknown";
}
}
