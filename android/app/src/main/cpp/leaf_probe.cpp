// Optional owner-private original-function differential, never a gameplay gate.
#include <jni.h>
#include <cstdio>
#ifdef TS2_PRIVATE_LEAF_PROBE
extern "C" unsigned ts2_private_leaf_check();
#endif
extern "C" JNIEXPORT jstring JNICALL
Java_org_ts2native_diagnostic_MainActivity_nativeLeafDifferential(JNIEnv* env, jclass) {
#ifdef TS2_PRIVATE_LEAF_PROBE
    const unsigned matched = ts2_private_leaf_check();
    char result[160];
    std::snprintf(result, sizeof result,
        "{\"available\":true,\"cases\":64,\"matched\":%u,\"passed\":%s}",
        matched <= 64 ? matched : 0, matched == 64 ? "true" : "false");
    return env->NewStringUTF(result);
#else
    return env->NewStringUTF("{\"available\":false,\"cases\":0,\"matched\":0,\"passed\":false}");
#endif
}
