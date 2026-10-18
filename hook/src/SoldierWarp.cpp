#include "SoldierWarp.h"

#include "dynamite.h"
#include "mgsvtpp_func_typedefs.h"
#include "spdlog/spdlog.h"
#include "windows.h"

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <thread>
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

    bool Capture(const uint32_t objectID) {
        if (capturedObjectID.load() == objectID && capturedController.load() != 0) {
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
                spdlog::info("SoldierWarp::Capture, soldier {} controller {:#x} local index {}", objectID, capturedController.load(), capturedLocalIndex.load());
            } else {
                spdlog::info("SoldierWarp::Capture, soldier {} was not updated within 500 ms", objectID);
            }
        }).detach();

        return false;
    }

    int Warp(const uint32_t objectID, const float x, const float y, const float z, const bool log, const float *rotation) {
        if (capturedObjectID.load() != objectID || capturedController.load() == 0) {
            return 0;
        }

        using GetCharaFunc = void *(__fastcall *)(void *ctrl, uint32_t localIndex);
        using GetRotFunc = void *(__fastcall *)(void *obj);
        using SetRotFunc = void(__fastcall *)(void *obj, void *rot);
        using SetTransformFunc = void(__fastcall *)(void *obj, void *pos, void *rot);

        const auto ctrl = reinterpret_cast<void *>(capturedController.load());
        const auto ctrlVtable = *reinterpret_cast<void ***>(ctrl);
        const auto obj = reinterpret_cast<GetCharaFunc>(ctrlVtable[0x388 / 8])(ctrl, capturedLocalIndex.load());
        const auto entry = PositionEntry(objectID);
        if (obj == nullptr || entry == nullptr) {
            spdlog::info("{}, soldier {} has no character object", __PRETTY_FUNCTION__, objectID);
            capturedObjectID = noSoldier;
            return -1;
        }

        // character object must belong to this soldier: its position is the source of the position table entry
        const auto objPos = reinterpret_cast<float *>((char *)obj + 0x20);
        if (std::abs(objPos[0] - entry[0]) > 1.0f || std::abs(objPos[2] - entry[2]) > 1.0f) {
            spdlog::info("{}, soldier {} character object does not match, recapture needed", __PRETTY_FUNCTION__, objectID);
            capturedObjectID = noSoldier;
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

        if (log) {
            spdlog::info("{}, soldier {} moved to {} {} {}", __PRETTY_FUNCTION__, objectID, x, y, z);
        }
        return 1;
    }

    bool LocalIndex(const uint32_t objectID, uint32_t &index) {
        if (capturedObjectID.load() != objectID || capturedController.load() == 0) {
            return false;
        }
        index = capturedLocalIndex.load();
        return true;
    }

    bool GetTransform(const uint32_t objectID, float pos[3], float rot[4]) {
        if (capturedObjectID.load() != objectID || capturedController.load() == 0) {
            return false;
        }
        using GetCharaFunc = void *(__fastcall *)(void *ctrl, uint32_t localIndex);
        using GetRotFunc = void *(__fastcall *)(void *obj);
        const auto ctrl = reinterpret_cast<void *>(capturedController.load());
        const auto obj = reinterpret_cast<GetCharaFunc>((*reinterpret_cast<void ***>(ctrl))[0x388 / 8])(ctrl, capturedLocalIndex.load());
        if (obj == nullptr) {
            return false;
        }
        memcpy(pos, (char *)obj + 0x20, 3 * sizeof(float));
        memcpy(rot, reinterpret_cast<GetRotFunc>((*reinterpret_cast<void ***>(obj))[0x78 / 8])(obj), 4 * sizeof(float));
        return true;
    }
}
