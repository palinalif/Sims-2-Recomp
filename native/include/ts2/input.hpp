#pragma once
#include <array>
#include <cstdint>

namespace ts2 {
enum class Button { A, B, X, Y, L1, R1, Start, Mode, L3, R3, Up, Down, Left, Right, Count };
enum class Action { Select, Cancel, Context, NextSim, RotateLeft, RotateRight,
    Pause, ToggleMode, SpeedDown, SpeedUp, FocusUp, FocusDown, FocusLeft, FocusRight,
    BuildBuy, TextEntry, Count };
template<class E> constexpr uint32_t bit(E value) { return 1u << static_cast<unsigned>(value); }
enum class Mode { Cursor, Navigation };
struct Pad {
    bool connected = false;
    float lx=0, ly=0, rx=0, ry=0, lt=0, rt=0;
    uint32_t buttons=0;
};
struct Config {
    float deadzone=.18f, sensitivity=.55f, acceleration=1.8f;
    std::array<Action, static_cast<unsigned>(Button::Count)> mapping {
        Action::Select, Action::Cancel, Action::Context, Action::NextSim,
        Action::RotateLeft, Action::RotateRight, Action::Pause, Action::ToggleMode,
        Action::SpeedDown, Action::SpeedUp, Action::FocusUp, Action::FocusDown,
        Action::FocusLeft, Action::FocusRight
    };
};
struct ActionState {
    uint32_t held=0, pressed=0, released=0;
    float cursor_x=.5f, cursor_y=.5f, camera_x=0, camera_y=0, zoom=0, rotation=0;
    Mode mode=Mode::Cursor;
    bool pointer_event=false;
};
class Input {
    Config config_;
    ActionState state_;
    float repeat_=0;
    uint32_t prior_directions_=0;
    uint32_t sampled_held_=0, pending_pressed_=0, pending_released_=0;
    bool has_samples_=false, pending_toggle_=false, pointer_pending_=false;
    uint32_t actions(const Pad& pad) const;
public:
    void sample(const Pad& pad);
    const ActionState& update(const Pad& pad, float seconds);
    const ActionState& state() const { return state_; }
    void configure(const Config& config);
    void reset();
    void toggle_mode() { state_.mode=state_.mode==Mode::Cursor?Mode::Navigation:Mode::Cursor; }
    void pointer(float x, float y);
};
const char* action_name(Action action);
}
