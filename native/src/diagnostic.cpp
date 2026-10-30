#include "ts2/diagnostic.hpp"
#include <algorithm>
#include <cmath>
namespace ts2 {
int Diagnostic::update(const ActionState& s) {
    constexpr uint32_t directions=bit(Action::FocusLeft)|bit(Action::FocusRight)|bit(Action::FocusUp)|bit(Action::FocusDown);
    if(s.pointer_event) pointer_owns_focus=true;
    if(s.pressed & directions) pointer_owns_focus=false;
    if(s.pressed & bit(Action::FocusLeft)) focus=focus/3*3+(focus%3+2)%3;
    if(s.pressed & bit(Action::FocusRight)) focus=focus/3*3+(focus%3+1)%3;
    if(s.pressed & (bit(Action::FocusUp)|bit(Action::FocusDown))) focus=(focus+3)%6;
    if(pointer_owns_focus && (s.mode==Mode::Cursor || s.pointer_event)) {
        const float x=s.cursor_x,y=s.cursor_y;
        hovering_tile=y>=.32f && y<.76f && x>=.08f && x<.92f;
        if(hovering_tile)
            focus=std::clamp(int((x-.08f)/.28f),0,2)+3*std::clamp(int((y-.32f)/.22f),0,1);
    }
    if(pointer_owns_focus && !hovering_tile) return -1;
    return s.pressed & bit(Action::Select)?focus:-1;
}
void Diagnostic::draw(uint32_t* pixels,int w,int h,int stride,const ActionState& s) const {
    if(!pixels || w<=0 || h<=0 || stride<w) return;
    auto rect=[&](int x,int y,int width,int height,uint32_t color) {
        for(int row=std::max(y,0);row<std::min(y+height,h);++row)
            std::fill(pixels+row*stride+std::clamp(x,0,w),pixels+row*stride+std::clamp(x+width,0,w),color);
    };
    rect(0,0,w,h,0xff21180f);
    for(int i=0;i<6;++i) rect(int((.08f+.28f*(i%3))*w),int((.32f+.22f*(i/3))*h),int(.26f*w),int(.19f*h),i==focus?0xff55bc67:0xff594633);
    // Bars show camera X/Y, trigger zoom and camera rotation, centered at zero.
    const float values[]={s.camera_x,s.camera_y,s.zoom,s.rotation};
    for(int i=0;i<4;++i) {
        const int y=int((.81f+i*.035f)*h); rect(w/4,y,w/2,std::max(h/70,1),0xff685544);
        const int value=int(std::clamp(values[i],-1.f,1.f)*w/4);
        rect(w/2+std::min(value,0),y,std::abs(value),std::max(h/70,1),0xffedc56a);
    }
    if(s.mode==Mode::Cursor) {
        int x=int(s.cursor_x*(w-1)),y=int(s.cursor_y*(h-1));
        rect(x-9,y-1,19,3,0xffffffff); rect(x-1,y-9,3,19,0xffffffff);
    }
}
}
