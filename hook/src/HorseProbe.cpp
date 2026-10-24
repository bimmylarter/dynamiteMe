#include "HorseProbe.h"

#include "DynamiteCore.h"
#include "DynamiteHook.h"
#include "SoldierWarp.h"
#include "dynamite.h"
#include "mgsvtpp_func_typedefs.h"
#include "spdlog/spdlog.h"
#include "windows.h"

#include <atomic>
#include <cmath>
#include <cstring>
#include <set>
#include <string>

namespace Dynamite::HorseProbe {
    namespace {
        struct Entry {
            uint64_t ctrl;
            uint32_t index;
            uint64_t vtable;
            uint64_t firstCaller, lastCaller;
            uint64_t lastState;
            uint32_t lastLayer;
            uint32_t count;
        };
        constexpr int maxEntries = 64;
        Entry entries[maxEntries]{};
        int entryCount = 0;
        std::atomic_flag lock = ATOMIC_FLAG_INIT;
        std::set<uint64_t> trustedVtables; // under lock

        struct Guard {
            Guard() {
                while (lock.test_and_set(std::memory_order_acquire)) {
                }
            }
            ~Guard() { lock.clear(std::memory_order_release); }
        };

        uint64_t exeBase = 0;
        uint64_t ToExe(const uint64_t a) {
            if (exeBase == 0) {
                exeBase = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
            }
            return a - exeBase + 0x140000000;
        }

        double Now() { return static_cast<double>(GetTickCount64()) / 1000.0; }
    }

    void OnMotion(void *ctrl, const uint32_t index, const uint32_t layer, const uint64_t state, const uint64_t caller, const bool trusted) {
        const auto c = reinterpret_cast<uint64_t>(ctrl);
        const auto vt = *reinterpret_cast<uint64_t *>(ctrl);
        Guard g;
        if (trusted) {
            trustedVtables.insert(vt);
            return;
        }
        for (int i = 0; i < entryCount; i++) {
            auto &e = entries[i];
            if (e.ctrl == c && e.index == index) {
                e.lastCaller = caller;
                e.lastState = state;
                e.lastLayer = layer;
                e.count++;
                return;
            }
        }
        if (entryCount < maxEntries) {
            entries[entryCount++] = {c, index, vt, caller, caller, state, layer, 1};
        }
    }

    void Tick() {
        static double next = 0, nextIds = 0;
        const auto now = Now();
        if (now < next) {
            return;
        }
        next = now + 0.5;

        // the horse's game object id, once a while (TppHorse2 is type 13: id 13 * 512 + index)
        if (now >= nextIds) {
            nextIds = now + 30.0;
            std::string ids;
            for (uint32_t id = 6656; id < 6656 + 4; id++) {
                if (FindGameObjectWithID(id) != nullptr) {
                    ids += " " + std::to_string(id);
                }
            }
            spdlog::info("[horseprobe] TppHorse2 objects:{}", ids.empty() ? " none" : ids);
        }

        const Vector3 players[2] = {DynamiteCore::GetPlayerPosition(0), DynamiteCore::GetPlayerPosition(1)};
        // soldier controllers are known motion controllers too
        Entry copy[maxEntries];
        int n;
        std::set<uint64_t> vts;
        {
            Guard g;
            n = entryCount;
            memcpy(copy, entries, sizeof(Entry) * n);
            vts = trustedVtables;
        }
        for (int i = 0; i < n; i++) {
            const auto &e = copy[i];
            int sameCtrl = 0;
            for (int j = 0; j < n; j++) {
                sameCtrl += copy[j].ctrl == e.ctrl;
            }
            if (sameCtrl > 4) {
                continue; // a controller with many characters: soldiers
            }
            if (vts.count(e.vtable) == 0) {
                static std::set<uint64_t> loggedUntrusted;
                if (loggedUntrusted.insert(e.ctrl ^ e.index).second) {
                    spdlog::info("[horseprobe] ctrl {:#x} index {} has another vtable {:#x}, first caller {:#x}, state {:012x} layer {}", e.ctrl, e.index,
                        ToExe(e.vtable), e.firstCaller, e.lastState & 0xffffffffffffull, e.lastLayer);
                }
                continue;
            }
            using GetCharaFunc = void *(__fastcall *)(void *ctrl, uint32_t localIndex);
            const auto ctrl = reinterpret_cast<void *>(e.ctrl);
            const auto obj = reinterpret_cast<GetCharaFunc>((*reinterpret_cast<void ***>(ctrl))[0x388 / 8])(ctrl, e.index);
            if (obj == nullptr) {
                continue;
            }
            const auto pos = reinterpret_cast<float *>(static_cast<char *>(obj) + 0x20);
            float d[2];
            for (int p = 0; p < 2; p++) {
                const auto dx = pos[0] - players[p].x, dy = pos[1] - players[p].y, dz = pos[2] - players[p].z;
                d[p] = std::sqrt(dx * dx + dy * dy + dz * dz);
            }
            if (d[0] > 40.0f && d[1] > 40.0f) {
                continue;
            }
            spdlog::info("[horseprobe] ctrl {:#x} index {} obj {} pos {:.2f} {:.2f} {:.2f} dist p0 {:.1f} p1 {:.1f} calls {} last state {:012x} layer {} from {:#x} (first {:#x})",
                e.ctrl, e.index, obj, pos[0], pos[1], pos[2], d[0], d[1], e.count, e.lastState & 0xffffffffffffull, e.lastLayer, e.lastCaller, e.firstCaller);
        }
        spdlog::info("[horseprobe] players p0 {:.2f} {:.2f} {:.2f} p1 {:.2f} {:.2f} {:.2f}", players[0].x, players[0].y, players[0].z, players[1].x, players[1].y,
            players[1].z);
    }
}
