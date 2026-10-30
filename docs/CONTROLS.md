# Controller experience

The portable core consumes normalized pad state and emits actions, not keyboard
scan codes. This pass shows actions in diagnostics; none are hooked into Sims 2.
Gameplay meanings below are provisional until actual UI/simulation initialization.

| Input | Default action | Current diagnostic |
|---|---|---|
| Left stick | Analog cursor | Radial deadzone, response curve, clamped normalized cursor |
| Right stick | Camera pan | Two native bars + numeric state |
| A | Select / confirm | Activate focused/cursor tile |
| B | Cancel / back | Action state/log; Android dialogs handle back themselves |
| X | Context | Action state/log |
| Y | Next Sim | Action state/log |
| D-pad | Context focus | Six-tile navigation in Navigation Mode, initial delay + repeat |
| LB / RB | Rotate camera | Signed rotation state/bar |
| LT / RT | Zoom out / in | Signed zoom state/bar |
| Start | Pause/menu | Action state/log |
| Select / Back button | Toggle Cursor/Navigation Mode | Changes control mode |
| L3 / R3 | Speed down/up | Action state/log |
| Configurable button | Build/Buy or text entry | Available as remappable actions; text tile opens native IME |

Prompts currently use positional A/B/X/Y names. Automatic PlayStation/Nintendo
glyph-family selection and device-specific layouts are not implemented. The AYN
Thor Max should be tested with its actual Android input descriptors, axis ranges,
trigger reports, mode switches and physical display behavior; no hardware was attached.

## Cursor Mode

Default radial deadzone 18%, adjustable to 10/18/25% in the diagnostic UI. Stick
response uses magnitude^1.8 after deadzone, with a configurable maximum normalized
speed (default 0.55 screen units/second). This gives fine near-center movement and
accelerates toward the stick edge. Integration uses a monotonic delta capped at
50 ms; pause/focus loss clears held state and the first resumed delta. Cursor
position is preserved and constrained to the visible surface.

Touch release selects a tile; mouse hover/motion moves the same cursor and clicks
use the touch dispatch path. UI controls are Android dialogs and can also receive
keyboard/D-pad input. Touch/mouse do not require a connected gamepad.

## Navigation Mode

D-pad moves a visible focus among a 3×2 diagnostic grid with wraparound, 350 ms
initial repeat delay and 90 ms repeats. It is a genuine local focus model; it does
not infer focus targets in the PC game or move a mouse to pretend a target is
focused. Implementing game menus needs UI-tree/hit-test knowledge and context.

The mode toggle is available on Select and on the Input mode tile. Input mode,
cursor and simulation pause are distinct concepts. Do not inject a large set of
gameplay hooks until initialization and a basic input path work.

## Configuration, hotplug and text

Sensitivity and deadzone presets plus per-button action mappings are persisted in
app-private SharedPreferences. Mappings includes Build/Buy and TextEntry; remapping
does not execute a missing game feature. Reset mappings restores defaults.
One controller is active at a time; input from a different device switches the
active controller and resets old state. Device removal/change, pause, focus loss
and surface loss release state. Hats and digital D-pad keys are combined so one
event source does not clear the other.

The Text entry tile opens an Android EditText/IME dialog, supports confirm/cancel,
and only reports character count. No text or controller descriptor is sent over
the network. Native game text injection, encoding/locale handling and TV-device
IME usability remain to be implemented and tested.

## Later gameplay integration

Add context layers for neighborhood, live, build/buy, modal UI and text entry;
map actions at the UI/simulation boundary rather than permanent keyboard aliases.
Implement Sim cycling, speed/pause, tool placement/rotation/grid constraints and
context cancel with explicit held/pressed/released semantics. Then investigate
native interaction lists and radial menus, preserving the game's queue semantics.
Keep mouse/touch paths active and ensure every required interaction has a
controller-accessible alternative before claiming controller-only playability.
