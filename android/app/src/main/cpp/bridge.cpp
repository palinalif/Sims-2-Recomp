#include <jni.h>
#include <android/native_window_jni.h>
#include <android/log.h>
#include <algorithm>
#include <cstdio>
#include <exception>
#include "ts2/input.hpp"
#include "ts2/diagnostic.hpp"
#include "ts2/package_probe.hpp"

// UI-thread ownership. No retained JNIEnv or Activity references.
namespace {
ts2::Input input;
ts2::Pad pad;
ts2::Diagnostic diagnostic;
ANativeWindow* window=nullptr;
bool pointer_select=false;
uint32_t last_pressed=0;
void log(const char* event) {
    __android_log_print(ANDROID_LOG_INFO,"TS2Native","{\"event\":\"%s\",\"component\":\"platform\"}",event);
}
}
extern "C" JNIEXPORT void JNICALL
Java_org_ts2native_diagnostic_MainActivity_nativeSurface(JNIEnv* env,jclass,jobject surface) {
    if(window) { ANativeWindow_release(window); window=nullptr; }
    if(surface) {
        window=ANativeWindow_fromSurface(env,surface);
        if(window && ANativeWindow_setBuffersGeometry(window,0,0,WINDOW_FORMAT_RGBA_8888)!=0) log("surface_format_failed");
        log("surface_acquired");
    } else log("surface_released");
}
extern "C" JNIEXPORT void JNICALL
Java_org_ts2native_diagnostic_MainActivity_nativePad(JNIEnv*,jclass,jboolean connected,jint buttons,
        jfloat lx,jfloat ly,jfloat rx,jfloat ry,jfloat lt,jfloat rt) {
    pad={bool(connected),lx,ly,rx,ry,lt,rt,static_cast<uint32_t>(buttons)};
    input.sample(pad);
}
extern "C" JNIEXPORT void JNICALL
Java_org_ts2native_diagnostic_MainActivity_nativeReset(JNIEnv*,jclass) {
    input.reset();pad={};pointer_select=false;last_pressed=0;log("input_reset");
}
extern "C" JNIEXPORT void JNICALL
Java_org_ts2native_diagnostic_MainActivity_nativeToggleMode(JNIEnv*,jclass) {
    input.toggle_mode();log("mode_changed");
}
extern "C" JNIEXPORT void JNICALL
Java_org_ts2native_diagnostic_MainActivity_nativePointer(JNIEnv*,jclass,jfloat x,jfloat y,jboolean select) {
    input.pointer(x,y); pointer_select|=bool(select);
}
extern "C" JNIEXPORT jint JNICALL
Java_org_ts2native_diagnostic_MainActivity_nativeFrame(JNIEnv*,jclass,jfloat seconds) {
    auto state=input.update(pad,seconds);
    if(pointer_select) { state.pressed|=ts2::bit(ts2::Action::Select); pointer_select=false; }
    if(state.pressed) {
        __android_log_print(ANDROID_LOG_INFO,"TS2Native","{\"event\":\"actions\",\"pressed\":%u,\"held\":%u}",state.pressed,state.held);
        last_pressed=state.pressed;
    }
    const int activated=diagnostic.update(state);
    if(window) {
        ANativeWindow_Buffer buffer{};
        const int result=ANativeWindow_lock(window,&buffer,nullptr);
        if(result==0) {
            if(buffer.format==WINDOW_FORMAT_RGBA_8888)
                diagnostic.draw(static_cast<uint32_t*>(buffer.bits),buffer.width,buffer.height,buffer.stride,state);
            if(ANativeWindow_unlockAndPost(window)!=0) log("surface_post_failed");
        } else log("surface_lock_failed");
    }
    return activated;
}
extern "C" JNIEXPORT jstring JNICALL
Java_org_ts2native_diagnostic_MainActivity_nativeStatus(JNIEnv* env,jclass) {
    const auto& s=input.state(); char buffer[512];
    std::snprintf(buffer,sizeof buffer,"%s Mode | Focus %d | Cursor %.2f, %.2f\nCamera %.2f, %.2f | Zoom %.2f | Rotation %.0f\nHeld 0x%04x | Last actions 0x%04x | ARM64 C++ runtime",
        s.mode==ts2::Mode::Cursor?"Cursor":"Navigation",diagnostic.focus+1,s.cursor_x,s.cursor_y,
        s.camera_x,s.camera_y,s.zoom,s.rotation,s.held,last_pressed);
    return env->NewStringUTF(buffer);
}
extern "C" JNIEXPORT jboolean JNICALL
Java_org_ts2native_diagnostic_MainActivity_nativeConfigure(JNIEnv* env,jclass,jfloat deadzone,jfloat sensitivity,jintArray mapping) {
    if(!mapping || env->GetArrayLength(mapping)!=static_cast<jsize>(ts2::Config{}.mapping.size())) return false;
    jint values[static_cast<int>(ts2::Button::Count)];
    env->GetIntArrayRegion(mapping,0,static_cast<jsize>(std::size(values)),values);
    if(env->ExceptionCheck()) return false;
    ts2::Config config;config.deadzone=deadzone;config.sensitivity=sensitivity;
    for(unsigned i=0;i<config.mapping.size();++i) config.mapping[i]=static_cast<ts2::Action>(values[i]);
    try { input.configure(config);log("input_configured");return true; }
    catch(const std::exception&) { log("invalid_input_configuration");return false; }
}
// Worker-thread entry. Local-only state; independent of the UI-owned input/window.
extern "C" JNIEXPORT jobjectArray JNICALL
Java_org_ts2native_diagnostic_PackageInspector_nativeProbe(JNIEnv* env,jclass,jbyteArray source) {
    try {
        if(!source || env->GetArrayLength(source)>16*1024*1024)
            throw std::invalid_argument("Package exceeds native diagnostic input budget");
        std::vector<uint8_t> bytes(static_cast<size_t>(env->GetArrayLength(source)));
        env->GetByteArrayRegion(source,0,static_cast<jsize>(bytes.size()),reinterpret_cast<jbyte*>(bytes.data()));
        if(env->ExceptionCheck()) return nullptr;
        const auto probe=ts2::probe_package(bytes);
        jclass byte_array=env->FindClass("[B");
        if(!byte_array) return nullptr;
        jobjectArray result=env->NewObjectArray(2,byte_array,nullptr);
        if(!result) return nullptr;
        const std::span<const uint8_t> parts[]={
            {reinterpret_cast<const uint8_t*>(probe.summary.data()),probe.summary.size()},probe.payload};
        for(unsigned i=0;i<2;++i) {
            jbyteArray part=env->NewByteArray(static_cast<jsize>(parts[i].size()));
            if(!part) return nullptr;
            env->SetByteArrayRegion(part,0,static_cast<jsize>(parts[i].size()),reinterpret_cast<const jbyte*>(parts[i].data()));
            if(env->ExceptionCheck()) return nullptr;
            env->SetObjectArrayElement(result,static_cast<jsize>(i),part);env->DeleteLocalRef(part);
            if(env->ExceptionCheck()) return nullptr;
        }
        __android_log_print(ANDROID_LOG_INFO,"TS2Native","{\"component\":\"assets\",\"event\":\"package_probe\",\"decoded_bytes\":%zu}",probe.payload.size());
        return result;
    } catch(const std::exception& e) {
        jclass type=env->FindClass("java/lang/IllegalArgumentException");
        if(type) env->ThrowNew(type,e.what());
        return nullptr;
    }
}
