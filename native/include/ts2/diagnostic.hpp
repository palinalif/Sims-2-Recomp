#pragma once
#include "input.hpp"
namespace ts2 {
struct Diagnostic {
    int focus=0;
    bool pointer_owns_focus=true, hovering_tile=true;
    int update(const ActionState& state); // activated tile index or -1
    void draw(uint32_t* pixels,int width,int height,int stride,const ActionState& state) const;
};
}
