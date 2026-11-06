/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "NetworkStats"

#include <errno.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

#include <jni.h>

#include <nativehelper/JNIHelp.h>
#include <nativehelper/ScopedUtfChars.h>
#include <nativehelper/ScopedLocalRef.h>
#include <nativehelper/ScopedPrimitiveArray.h>

#include <utils/Log.h>
#include <utils/misc.h>

#include "android-base/properties.h"
#include "android-base/unique_fd.h"
#include "bpf/BpfUtils.h"
#include "netdbpf/BpfNetworkStats.h"

using android::bpf::parseBpfNetworkStatsDetail;
using android::bpf::stats_line;

namespace android {

static jclass gStringClass;

static struct {
    jfieldID size;
    jfieldID capacity;
    jfieldID iface;
    jfieldID uid;
    jfieldID set;
    jfieldID tag;
    jfieldID metered;
    jfieldID roaming;
    jfieldID defaultNetwork;
    jfieldID rxBytes;
    jfieldID rxPackets;
    jfieldID txBytes;
    jfieldID txPackets;
    jfieldID operations;
} gNetworkStatsClassInfo;

static jobjectArray get_string_array(JNIEnv* env, jobject obj, jfieldID field, int size, bool grow)
{
    if (!grow) {
        jobjectArray array = (jobjectArray)env->GetObjectField(obj, field);
        if (array != NULL) {
            return array;
        }
    }
    return env->NewObjectArray(size, gStringClass, NULL);
}

static jintArray get_int_array(JNIEnv* env, jobject obj, jfieldID field, int size, bool grow)
{
    if (!grow) {
        jintArray array = (jintArray)env->GetObjectField(obj, field);
        if (array != NULL) {
            return array;
        }
    }
    return env->NewIntArray(size);
}

static jlongArray get_long_array(JNIEnv* env, jobject obj, jfieldID field, int size, bool grow)
{
    if (!grow) {
        jlongArray array = (jlongArray)env->GetObjectField(obj, field);
        if (array != NULL) {
            return array;
        }
    }
    return env->NewLongArray(size);
}

static int statsLinesToNetworkStats(JNIEnv* env, jclass clazz, jobject stats,
                            std::vector<stats_line>& lines) {
    int size = lines.size();

    bool grow = size > env->GetIntField(stats, gNetworkStatsClassInfo.capacity);

    ScopedLocalRef<jobjectArray> iface(env, get_string_array(env, stats,
            gNetworkStatsClassInfo.iface, size, grow));
    if (iface.get() == NULL) return -1;
    ScopedIntArrayRW uid(env, get_int_array(env, stats,
            gNetworkStatsClassInfo.uid, size, grow));
    if (uid.get() == NULL) return -1;
    ScopedIntArrayRW set(env, get_int_array(env, stats,
            gNetworkStatsClassInfo.set, size, grow));
    if (set.get() == NULL) return -1;
    ScopedIntArrayRW tag(env, get_int_array(env, stats,
            gNetworkStatsClassInfo.tag, size, grow));
    if (tag.get() == NULL) return -1;
    ScopedIntArrayRW metered(env, get_int_array(env, stats,
            gNetworkStatsClassInfo.metered, size, grow));
    if (metered.get() == NULL) return -1;
    ScopedIntArrayRW roaming(env, get_int_array(env, stats,
            gNetworkStatsClassInfo.roaming, size, grow));
    if (roaming.get() == NULL) return -1;
    ScopedIntArrayRW defaultNetwork(env, get_int_array(env, stats,
            gNetworkStatsClassInfo.defaultNetwork, size, grow));
    if (defaultNetwork.get() == NULL) return -1;
    ScopedLongArrayRW rxBytes(env, get_long_array(env, stats,
            gNetworkStatsClassInfo.rxBytes, size, grow));
    if (rxBytes.get() == NULL) return -1;
    ScopedLongArrayRW rxPackets(env, get_long_array(env, stats,
            gNetworkStatsClassInfo.rxPackets, size, grow));
    if (rxPackets.get() == NULL) return -1;
    ScopedLongArrayRW txBytes(env, get_long_array(env, stats,
            gNetworkStatsClassInfo.txBytes, size, grow));
    if (txBytes.get() == NULL) return -1;
    ScopedLongArrayRW txPackets(env, get_long_array(env, stats,
            gNetworkStatsClassInfo.txPackets, size, grow));
    if (txPackets.get() == NULL) return -1;
    ScopedLongArrayRW operations(env, get_long_array(env, stats,
            gNetworkStatsClassInfo.operations, size, grow));
    if (operations.get() == NULL) return -1;

    for (int i = 0; i < size; i++) {
        ScopedLocalRef<jstring> ifaceString(env, env->NewStringUTF(lines[i].iface));
        env->SetObjectArrayElement(iface.get(), i, ifaceString.get());

        uid[i] = lines[i].uid;
        set[i] = lines[i].set;
        tag[i] = lines[i].tag;
        // Metered, roaming and defaultNetwork are populated in Java-land.
        rxBytes[i] = lines[i].rxBytes;
        rxPackets[i] = lines[i].rxPackets;
        txBytes[i] = lines[i].txBytes;
        txPackets[i] = lines[i].txPackets;
    }

    env->SetIntField(stats, gNetworkStatsClassInfo.size, size);
    if (grow) {
        env->SetIntField(stats, gNetworkStatsClassInfo.capacity, size);
        env->SetObjectField(stats, gNetworkStatsClassInfo.iface, iface.get());
        env->SetObjectField(stats, gNetworkStatsClassInfo.uid, uid.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.set, set.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.tag, tag.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.metered, metered.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.roaming, roaming.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.defaultNetwork,
                defaultNetwork.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.rxBytes, rxBytes.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.rxPackets, rxPackets.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.txBytes, txBytes.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.txPackets, txPackets.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.operations, operations.getJavaArray());
    }
    return 0;
}

// Legacy kernels expose cumulative qtaguid counters instead of BPF maps.
// The tag's upper 32 bits are the framework accounting tag (as in AOSP's
// legacyReadNetworkStatsDetail before 7106fed750 removed qtaguid support).
static int readLegacyNetworkStats(std::vector<stats_line>* lines, bool detail) {
    const char* path = detail ? "/proc/net/xt_qtaguid/stats"
                              : "/proc/net/xt_qtaguid/iface_stat_fmt";
    FILE* fp = fopen(path, "re");
    if (fp == nullptr) return -1;
    char buffer[1024];
    unsigned lastIndex = 1;
    int result = 0;
    while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
        stats_line line = {};
        unsigned index;
        uint64_t tag;
        int matched;
        if (detail) {
            if (strncmp(buffer, "idx ", 4) == 0) continue;
            matched = sscanf(buffer, "%u %31s %" SCNx64 " %u %u %" SCNd64
                             " %" SCNd64 " %" SCNd64 " %" SCNd64,
                             &index, line.iface, &tag, &line.uid, &line.set,
                             &line.rxBytes, &line.rxPackets, &line.txBytes, &line.txPackets);
            if (matched != 9 || index != lastIndex + 1) {
                result = -1;
                break;
            }
            lastIndex = index;
            line.tag = tag >> 32;
        } else {
            if (strncmp(buffer, "ifname ", 7) == 0) continue;
            matched = sscanf(buffer, "%31s %" SCNd64 " %" SCNd64 " %" SCNd64 " %" SCNd64,
                             line.iface, &line.rxBytes, &line.rxPackets,
                             &line.txBytes, &line.txPackets);
            if (matched != 5) {
                result = -1;
                break;
            }
            line.uid = static_cast<uint32_t>(-1);
            line.set = static_cast<uint32_t>(-1);
        }
        lines->push_back(line);
    }
    if (ferror(fp)) result = -1;
    if (fclose(fp) != 0) result = -1;
    return result;
}

static int readNetworkStatsDetail(JNIEnv* env, jclass clazz, jobject stats) {
    std::vector<stats_line> lines;

    const bool useBpf = android::base::GetBoolProperty("ro.kernel.ebpf.supported", true);
    if ((useBpf ? parseBpfNetworkStatsDetail(&lines)
                : readLegacyNetworkStats(&lines, true)) < 0) return -1;

    return statsLinesToNetworkStats(env, clazz, stats, lines);
}

static int readNetworkStatsDev(JNIEnv* env, jclass clazz, jobject stats) {
    std::vector<stats_line> lines;

    const bool useBpf = android::base::GetBoolProperty("ro.kernel.ebpf.supported", true);
    if ((useBpf ? parseBpfNetworkStatsDev(&lines)
                : readLegacyNetworkStats(&lines, false)) < 0) return -1;

    return statsLinesToNetworkStats(env, clazz, stats, lines);
}

static const JNINativeMethod gMethods[] = {
        { "nativeReadNetworkStatsDetail", "(Landroid/net/NetworkStats;)I",
                (void*) readNetworkStatsDetail },
        { "nativeReadNetworkStatsDev", "(Landroid/net/NetworkStats;)I",
                (void*) readNetworkStatsDev },
};

int register_android_server_net_NetworkStatsFactory(JNIEnv* env) {
    int err = jniRegisterNativeMethods(env,
            "android/net/connectivity/com/android/server/net/NetworkStatsFactory", gMethods,
            NELEM(gMethods));
    gStringClass = env->FindClass("java/lang/String");
    gStringClass = static_cast<jclass>(env->NewGlobalRef(gStringClass));

    jclass clazz = env->FindClass("android/net/NetworkStats");
    gNetworkStatsClassInfo.size = env->GetFieldID(clazz, "size", "I");
    gNetworkStatsClassInfo.capacity = env->GetFieldID(clazz, "capacity", "I");
    gNetworkStatsClassInfo.iface = env->GetFieldID(clazz, "iface", "[Ljava/lang/String;");
    gNetworkStatsClassInfo.uid = env->GetFieldID(clazz, "uid", "[I");
    gNetworkStatsClassInfo.set = env->GetFieldID(clazz, "set", "[I");
    gNetworkStatsClassInfo.tag = env->GetFieldID(clazz, "tag", "[I");
    gNetworkStatsClassInfo.metered = env->GetFieldID(clazz, "metered", "[I");
    gNetworkStatsClassInfo.roaming = env->GetFieldID(clazz, "roaming", "[I");
    gNetworkStatsClassInfo.defaultNetwork = env->GetFieldID(clazz, "defaultNetwork", "[I");
    gNetworkStatsClassInfo.rxBytes = env->GetFieldID(clazz, "rxBytes", "[J");
    gNetworkStatsClassInfo.rxPackets = env->GetFieldID(clazz, "rxPackets", "[J");
    gNetworkStatsClassInfo.txBytes = env->GetFieldID(clazz, "txBytes", "[J");
    gNetworkStatsClassInfo.txPackets = env->GetFieldID(clazz, "txPackets", "[J");
    gNetworkStatsClassInfo.operations = env->GetFieldID(clazz, "operations", "[J");

    return err;
}

}
