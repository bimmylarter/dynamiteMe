#include "SoldierWarp.h"

#include "dynamite.h"
#include "mgsvtpp_func_typedefs.h"
#include "spdlog/spdlog.h"
#include "windows.h"

#include <atomic>
#include <map>
#include <mutex>
#include <chrono>
#include <cmath>
#include <cstring>
#include <thread>
#include <string>
#include <tlhelp32.h>

namespace Dynamite::SoldierWarp {
    namespace {
        constexpr uint32_t noSoldier = 0xffffffff;

        std::atomic<bool> capturing{false};
        std::atomic<uint32_t> captureObjectID{noSoldier};
        std::atomic<uint64_t> writerRip{0};

        std::atomic<uint32_t> capturedObjectID{noSoldier};
        std::atomic<uint64_t> capturedController{0};
        std::atomic<uint32_t> capturedLocalIndex{0};

        PVOID vehHandle = nullptr;

        // captured soldiers: controller and local index per soldier, with the position table they were captured from
        // (a new mission or a re-created soldier gives a different table, which invalidates the entry)
        struct Known {
            uint64_t controller;
            uint32_t localIndex;
            uint64_t table;
            bool placed = false;      // moved by Warp at least once
            float lastPlaced[3]{};    // where Warp last put it
        };
        std::mutex knownMutex;
        std::map<uint32_t, Known> known;

        constexpr uint64_t dr7Mask = 0xF0003ull;                                // L0/G0 + RW0/LEN0
        constexpr uint64_t dr7Write4 = 1ull | (1ull << 16) | (3ull << 18); // L0, write, 4 bytes

        LONG WINAPI Handler(EXCEPTION_POINTERS *info) {
            if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            auto *ctx = info->ContextRecord;
            if ((ctx->Dr6 & 1) == 0 || !capturing.load()) {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            ctx->Dr6 = 0;

            // registers are meaningful only at the known writer; ignore other writes (if any)
            if (ctx->Rip != writerRip.load()) {
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            if (capturedObjectID.load() != captureObjectID.load()) {
                capturedController = ctx->R14;
                capturedLocalIndex = static_cast<uint32_t>(ctx->R12);
                capturedObjectID = captureObjectID.load();
            }

            ctx->Dr7 &= ~dr7Mask;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // Set (address != 0) or clear DR0 write breakpoint on all threads except the calling one.
        void SetBreakpoint(const uint64_t address) {
            const auto pid = GetCurrentProcessId();
            const auto self = GetCurrentThreadId();
            const auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snap == INVALID_HANDLE_VALUE) {
                spdlog::error("{}, thread snapshot failed", __PRETTY_FUNCTION__);
                return;
            }

            THREADENTRY32 te{};
            te.dwSize = sizeof(te);
            for (auto ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
                if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) {
                    continue;
                }

                const auto th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (th == nullptr) {
                    continue;
                }

                if (SuspendThread(th) != static_cast<DWORD>(-1)) {
                    CONTEXT ctx{};
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(th, &ctx)) {
                        ctx.Dr0 = address;
                        ctx.Dr7 = (ctx.Dr7 & ~dr7Mask) | (address != 0 ? dr7Write4 : 0);
                        ctx.Dr6 = 0;
                        SetThreadContext(th, &ctx);
                    }
                    ResumeThread(th);
                }
                CloseHandle(th);
            }

            CloseHandle(snap);
        }

        // soldier's entry in position table read by GetPosition (Vector3, 16 bytes), see DynamiteCore::GetSoldierPosition
        float *PositionEntry(const uint32_t objectID) {
            if (objectID < 1024) {
                return nullptr;
            }

            auto go = FindGameObjectWithID(objectID);
            if (go == nullptr) {
                return nullptr;
            }

            go = *(void **)((char *)go + 0x40);
            go = *(void **)((char *)go + 0x10);

            const auto interfaceName = "TppSoldier2";
            const auto hash = FoxStrHash32(interfaceName, strlen(interfaceName));
            auto soldierInterface = Soldier2ImplGetInterface(go, hash);
            if (soldierInterface == nullptr) {
                return nullptr;
            }
            soldierInterface = (char *)soldierInterface - 0xc;

            const auto pos1 = *(void **)((char *)soldierInterface + 0x18);
            return reinterpret_cast<float *>(*(char **)((char *)pos1 + 0x20) + 0x10 * (objectID - 1024));
        }
    }

    bool Lookup(const uint32_t objectID, uint64_t &controller, uint32_t &localIndex);

    namespace {
        // --- v29 write watch on DR1 ---
        constexpr uint64_t dr7Mask1 = 0x00F0000Cull;                                 // L1/G1 + RW1/LEN1
        constexpr uint64_t dr7Write4At1 = (1ull << 2) | (1ull << 20) | (3ull << 22); // L1, write, 4 bytes
        std::atomic<bool> watching{false};
        constexpr int maxWriters = 16;
        std::atomic<uint64_t> writerRips[maxWriters]{};
        std::atomic<uint64_t> writerRets[maxWriters]{};
        std::atomic<uint32_t> writerCounts[maxWriters]{};
        PVOID watchHandle = nullptr;

        LONG WINAPI WatchHandler(EXCEPTION_POINTERS *info) {
            if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
                return EXCEPTION_CONTINUE_SEARCH;
            }
            auto *ctx = info->ContextRecord;
            if ((ctx->Dr6 & 2) == 0) {
                return EXCEPTION_CONTINUE_SEARCH;
            }
            ctx->Dr6 &= ~2ull;
            if (!watching.load()) {
                ctx->Dr7 &= ~dr7Mask1; // late hit after the watch: clear on this thread and go on
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            const uint64_t rip = ctx->Rip;
            for (int i = 0; i < maxWriters; i++) {
                uint64_t expected = 0;
                if (writerRips[i].load() == rip || writerRips[i].compare_exchange_strong(expected, rip)) {
                    if (writerCounts[i]++ == 0) {
                        writerRets[i] = *reinterpret_cast<uint64_t *>(ctx->Rsp); // hint only (not always a return address)
                    }
                    break;
                }
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        void SetBreakpoint1(const uint64_t address) {
            const auto pid = GetCurrentProcessId();
            const auto self = GetCurrentThreadId();
            const auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snap == INVALID_HANDLE_VALUE) {
                return;
            }
            THREADENTRY32 te{};
            te.dwSize = sizeof(te);
            for (auto ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
                if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) {
                    continue;
                }
                const auto th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (th == nullptr) {
                    continue;
                }
                if (SuspendThread(th) != static_cast<DWORD>(-1)) {
                    CONTEXT ctx{};
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(th, &ctx)) {
                        ctx.Dr1 = address;
                        ctx.Dr7 = (ctx.Dr7 & ~dr7Mask1) | (address != 0 ? dr7Write4At1 : 0);
                        SetThreadContext(th, &ctx);
                    }
                    ResumeThread(th);
                }
                CloseHandle(th);
            }
            CloseHandle(snap);
        }

        uint64_t ToExeAddr(const uint64_t a) {
            const auto base = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
            return a >= base && a < base + 0x10000000 ? a - base + 0x140000000 : a;
        }
    }

    bool WatchWrites(const uint32_t objectID, const char *why) {
        uint64_t controller;
        uint32_t localIndex;
        if (!Lookup(objectID, controller, localIndex) || watching.load()) {
            return false;
        }
        using GetCharaFunc = void *(__fastcall *)(void *ctrl, uint32_t localIndex);
        const auto ctrl = reinterpret_cast<void *>(controller);
        const auto obj = reinterpret_cast<GetCharaFunc>((*reinterpret_cast<void ***>(ctrl))[0x388 / 8])(ctrl, localIndex);
        if (obj == nullptr) {
            return false;
        }
        if (watchHandle == nullptr) {
            watchHandle = AddVectoredExceptionHandler(1, WatchHandler);
        }
        for (int i = 0; i < maxWriters; i++) {
            writerRips[i] = 0;
            writerRets[i] = 0;
            writerCounts[i] = 0;
        }
        watching = true;
        const auto address = reinterpret_cast<uint64_t>(obj) + 0x20;
        const std::string reason = why;
        spdlog::info("[writewatch] soldier {} obj {} ({}): watching writes to its position for 300 ms", objectID, obj, reason);
        std::thread([objectID, address, reason] {
            SetBreakpoint1(address);
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            SetBreakpoint1(0);
            watching = false;
            for (int i = 0; i < maxWriters; i++) {
                const auto rip = writerRips[i].load();
                if (rip == 0) {
                    break;
                }
                spdlog::info("[writewatch] soldier {} ({}): written by {:#x} x{} (stack top {:#x})", objectID, reason, ToExeAddr(rip), writerCounts[i].load(),
                    ToExeAddr(writerRets[i].load()));
            }
            if (writerRips[0].load() == 0) {
                spdlog::info("[writewatch] soldier {} ({}): no writes", objectID, reason);
            }
        }).detach();
        return true;
    }

    void DumpCharacter(const uint32_t objectID, const char *why) {
        uint64_t controller;
        uint32_t localIndex;
        if (!Lookup(objectID, controller, localIndex)) {
            return;
        }
        using GetCharaFunc = void *(__fastcall *)(void *ctrl, uint32_t localIndex);
        const auto ctrl = reinterpret_cast<void *>(controller);
        const auto obj = static_cast<uint8_t *>(reinterpret_cast<GetCharaFunc>((*reinterpret_cast<void ***>(ctrl))[0x388 / 8])(ctrl, localIndex));
        if (obj == nullptr) {
            return;
        }
        spdlog::info("[chardump] soldier {} obj {} vtable {:#x} ({})", objectID, (void *)obj, ToExeAddr(*reinterpret_cast<uint64_t *>(obj)), why);
        for (int off = 0; off < 0x400; off += 0x20) {
            std::string line;
            for (int i = 0; i < 0x20; i += 8) {
                line += fmt::format(" {:016x}", *reinterpret_cast<uint64_t *>(obj + off + i));
            }
            spdlog::info("[chardump] soldier {} +{:03x}:{}", objectID, off, line);
        }
    }

    bool Capture(const uint32_t objectID) {
        uint64_t c;
        uint32_t i;
        if (Lookup(objectID, c, i)) {
            return true;
        }

        const auto it = addressSet.find("SoldierPositionWriter");
        if (it == addressSet.end()) {
            spdlog::error("{}, no SoldierPositionWriter address for this game version", __PRETTY_FUNCTION__);
            return false;
        }

        if (capturing.exchange(true)) {
            return false;
        }

        const auto entry = PositionEntry(objectID);
        if (entry == nullptr) {
            spdlog::info("{}, soldier {} not found", __PRETTY_FUNCTION__, objectID);
            capturing = false;
            return false;
        }

        writerRip = it->second;
        captureObjectID = objectID;
        capturedObjectID = noSoldier;
        capturedController = 0;
        if (vehHandle == nullptr) {
            vehHandle = AddVectoredExceptionHandler(1, Handler);
        }

        std::thread([objectID, entry] {
            SetBreakpoint(reinterpret_cast<uint64_t>(entry));
            for (int i = 0; i < 50 && capturedObjectID.load() != objectID; i++) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            SetBreakpoint(0);
            capturing = false;

            if (capturedObjectID.load() == objectID) {
                {
                    std::lock_guard lock(knownMutex);
                    known[objectID] = {capturedController.load(), capturedLocalIndex.load(), reinterpret_cast<uint64_t>(entry) - 0x10 * (objectID - 1024), false, {}};
                }
                spdlog::info("SoldierWarp::Capture, soldier {} controller {:#x} local index {}", objectID, capturedController.load(), capturedLocalIndex.load());
            } else {
                spdlog::info("SoldierWarp::Capture, soldier {} was not updated within 500 ms", objectID);
            }
        }).detach();

        return false;
    }

    int Warp(const uint32_t objectID, const float x, const float y, const float z, const bool log, const float *rotation) {
        uint64_t controller;
        uint32_t localIndex;
        if (!Lookup(objectID, controller, localIndex)) {
            return 0;
        }

        using GetCharaFunc = void *(__fastcall *)(void *ctrl, uint32_t localIndex);
        using GetRotFunc = void *(__fastcall *)(void *obj);
        using SetRotFunc = void(__fastcall *)(void *obj, void *rot);
        using SetTransformFunc = void(__fastcall *)(void *obj, void *pos, void *rot);

        const auto ctrl = reinterpret_cast<void *>(controller);
        const auto ctrlVtable = *reinterpret_cast<void ***>(ctrl);
        const auto obj = reinterpret_cast<GetCharaFunc>(ctrlVtable[0x388 / 8])(ctrl, localIndex);
        const auto entry = PositionEntry(objectID);
        if (obj == nullptr || entry == nullptr) {
            spdlog::info("{}, soldier {} has no character object", __PRETTY_FUNCTION__, objectID);
            std::lock_guard lock(knownMutex);
            known.erase(objectID);
            return -1;
        }

        // character object must belong to this soldier: near its position table entry (the entry is not updated
        // while the soldier is carried or moved by us, so only a loose check is possible)
        // v28: or near where we last put it (a long carry takes it far from its stale table entry)
        const auto objPos = reinterpret_cast<float *>((char *)obj + 0x20);
        bool nearPlaced = false;
        {
            std::lock_guard lock(knownMutex);
            const auto it = known.find(objectID);
            nearPlaced = it != known.end() && it->second.placed && std::abs(objPos[0] - it->second.lastPlaced[0]) < 5.0f &&
                         std::abs(objPos[2] - it->second.lastPlaced[2]) < 5.0f;
        }
        if (!nearPlaced && (std::abs(objPos[0] - entry[0]) > 30.0f || std::abs(objPos[2] - entry[2]) > 30.0f)) {
            spdlog::info("{}, soldier {} character object does not match, recapture needed", __PRETTY_FUNCTION__, objectID);
            std::lock_guard lock(knownMutex);
            known.erase(objectID);
            return -1;
        }

        const auto objVtable = *reinterpret_cast<void ***>(obj);

        // keep current orientation
        alignas(16) float rot[4];
        memcpy(rot, reinterpret_cast<GetRotFunc>(objVtable[0x78 / 8])(obj), sizeof(rot));
        if (rotation != nullptr) {
            memcpy(rot, rotation, sizeof(rot));
        }
        alignas(16) float pos[4] = {x, y, z, 0.0f};

        reinterpret_cast<SetRotFunc>(objVtable[0x70 / 8])(obj, rot);
        reinterpret_cast<SetTransformFunc>(objVtable[0x68 / 8])(obj, pos, rot);
        {
            std::lock_guard lock(knownMutex);
            const auto it = known.find(objectID);
            if (it != known.end()) {
                it->second.placed = true;
                it->second.lastPlaced[0] = x;
                it->second.lastPlaced[1] = y;
                it->second.lastPlaced[2] = z;
            }
        }

        if (log) {
            spdlog::info("{}, soldier {} moved to {} {} {}", __PRETTY_FUNCTION__, objectID, x, y, z);
        }
        return 1;
    }

    bool LocalIndex(const uint32_t objectID, uint32_t &index) {
        uint64_t controller;
        return Lookup(objectID, controller, index);
    }

    uint64_t Controller(const uint32_t objectID) {
        uint64_t controller;
        uint32_t index;
        return Lookup(objectID, controller, index) ? controller : 0;
    }

    bool Lookup(const uint32_t objectID, uint64_t &controller, uint32_t &localIndex) {
        const auto entry = PositionEntry(objectID);
        std::lock_guard lock(knownMutex);
        const auto it = known.find(objectID);
        if (it == known.end()) {
            return false;
        }
        if (entry == nullptr || reinterpret_cast<uint64_t>(entry) - 0x10 * (objectID - 1024) != it->second.table) {
            known.erase(it); // different mission / soldier re-created
            return false;
        }
        controller = it->second.controller;
        localIndex = it->second.localIndex;
        return true;
    }

    bool GetTransform(const uint32_t objectID, float pos[3], float rot[4]) {
        uint64_t controller;
        uint32_t localIndex;
        if (!Lookup(objectID, controller, localIndex)) {
            return false;
        }
        using GetCharaFunc = void *(__fastcall *)(void *ctrl, uint32_t localIndex);
        using GetRotFunc = void *(__fastcall *)(void *obj);
        const auto ctrl = reinterpret_cast<void *>(controller);
        const auto obj = reinterpret_cast<GetCharaFunc>((*reinterpret_cast<void ***>(ctrl))[0x388 / 8])(ctrl, localIndex);
        if (obj == nullptr) {
            return false;
        }
        memcpy(pos, (char *)obj + 0x20, 3 * sizeof(float));
        memcpy(rot, reinterpret_cast<GetRotFunc>((*reinterpret_cast<void ***>(obj))[0x78 / 8])(obj), 4 * sizeof(float));
        return true;
    }
}
