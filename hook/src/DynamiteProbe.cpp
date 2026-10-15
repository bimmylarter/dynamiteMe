#include "DynamiteProbe.h"

#include "DynamiteCore.h"
#include "dynamite.h"
#include "mgsvtpp_func_typedefs.h"
#include "spdlog/spdlog.h"
#include "windows.h"

#include <atomic>
#include <cmath>
#include <chrono>
#include <cstring>
#include <thread>
#include <tlhelp32.h>

namespace Dynamite::Probe {
    namespace {
        constexpr int maxHits = 32;

        struct Hit {
            uint64_t rip;
            uint64_t rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r12, r13, r14, r15;
            uint32_t count;
        };

        Hit hits[maxHits];
        std::atomic<int> hitCount{0};

        // controller capture state
        std::atomic<bool> capturing{false};
        std::atomic<uint64_t> captureAddress{0};
        std::atomic<uint32_t> captureObjectID{0};
        std::atomic<uint64_t> capturedController{0};
        std::atomic<uint32_t> capturedLocalIndex{0};
        std::atomic<uint32_t> capturedObjectID{0xffffffff};
        std::atomic<uint64_t> capturedRip{0};
        std::atomic<bool> watching{false};
        std::atomic<uint64_t> watchedAddress{0};
        PVOID vehHandle = nullptr;

        const uint64_t exeBase = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));

        // instruction after the first store of soldier position in per-frame soldier update (1.0.15.4)
        constexpr uint64_t knownWriterRip = 0x141377a83;

        uint64_t ToExeAddress(const uint64_t address) { return address - exeBase + 0x140000000; }

        LONG WINAPI Handler(EXCEPTION_POINTERS *info) {
            if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            auto *ctx = info->ContextRecord;
            if ((ctx->Dr6 & 1) == 0) {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            ctx->Dr6 = 0;

            if (capturing.load()) {
                // only trust registers of the known per-frame soldier update write: r14 = controller, r12 = local index
                if (ToExeAddress(ctx->Rip) != knownWriterRip) {
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                if (capturedObjectID.load() != captureObjectID.load()) {
                    capturedController = ctx->R14;
                    capturedLocalIndex = static_cast<uint32_t>(ctx->R12);
                    capturedRip = ctx->Rip;
                    capturedObjectID = captureObjectID.load();
                }
                // stop trapping on this thread, other threads are cleared by capture thread
                ctx->Dr7 &= ~0xF0003ull;
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            // no allocations or logging here, only record unique instruction addresses
            const auto rip = ctx->Rip;
            const auto n = hitCount.load();
            for (int i = 0; i < n && i < maxHits; i++) {
                if (hits[i].rip == rip) {
                    hits[i].count++;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }

            const auto slot = hitCount.fetch_add(1);
            if (slot < maxHits) {
                hits[slot] = Hit{
                    .rip = rip,
                    .rax = ctx->Rax,
                    .rbx = ctx->Rbx,
                    .rcx = ctx->Rcx,
                    .rdx = ctx->Rdx,
                    .rsi = ctx->Rsi,
                    .rdi = ctx->Rdi,
                    .r8 = ctx->R8,
                    .r9 = ctx->R9,
                    .r12 = ctx->R12,
                    .r13 = ctx->R13,
                    .r14 = ctx->R14,
                    .r15 = ctx->R15,
                    .count = 1,
                };
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // set (address != 0) or clear (address == 0) DR0 write breakpoint on all threads except the calling one
        void SetBreakpointAllThreads(const uint64_t address) {
            const auto pid = GetCurrentProcessId();
            const auto self = GetCurrentThreadId();
            const auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snap == INVALID_HANDLE_VALUE) {
                spdlog::error("{}, snapshot failed", __PRETTY_FUNCTION__);
                return;
            }

            THREADENTRY32 te{};
            te.dwSize = sizeof(te);
            int threads = 0;
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
                        if (address != 0) {
                            ctx.Dr0 = address;
                            // L0 enable, RW0 = 01 (write), LEN0 = 11 (4 bytes)
                            ctx.Dr7 = (ctx.Dr7 & ~0xF0003ull) | 1ull | (1ull << 16) | (3ull << 18);
                        } else {
                            ctx.Dr0 = 0;
                            ctx.Dr7 &= ~0xF0003ull;
                        }
                        ctx.Dr6 = 0;
                        if (SetThreadContext(th, &ctx)) {
                            threads++;
                        }
                    }
                    ResumeThread(th);
                }
                CloseHandle(th);
            }

            CloseHandle(snap);
            spdlog::info("{}, address {:#x}, threads updated {}", __PRETTY_FUNCTION__, address, threads);
        }
    }

    float *SoldierPositionEntry(const uint32_t objectID) {
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

    bool WatchSoldierPosition(const uint32_t objectID, const int seconds) {
        if (watching.exchange(true)) {
            spdlog::info("{}, already watching", __PRETTY_FUNCTION__);
            return false;
        }

        const auto entry = SoldierPositionEntry(objectID);
        if (entry == nullptr) {
            spdlog::info("{}, soldier {} not found", __PRETTY_FUNCTION__, objectID);
            watching = false;
            return false;
        }

        spdlog::info("{}, soldier {}, position entry {} = {} {} {}", __PRETTY_FUNCTION__, objectID, (void *)entry, entry[0], entry[1], entry[2]);

        hitCount = 0;
        memset(hits, 0, sizeof(hits));
        watchedAddress = reinterpret_cast<uint64_t>(entry);
        if (vehHandle == nullptr) {
            vehHandle = AddVectoredExceptionHandler(1, Handler);
        }

        std::thread([objectID, seconds, entry] {
            SetBreakpointAllThreads(reinterpret_cast<uint64_t>(entry));
            std::this_thread::sleep_for(std::chrono::seconds(seconds));
            SetBreakpointAllThreads(0);

            const auto n = std::min(hitCount.load(), maxHits);
            spdlog::info("[probe] soldier {} position writers: {} unique instructions", objectID, n);
            for (int i = 0; i < n; i++) {
                const auto &h = hits[i];
                spdlog::info("[probe] write #{} rip={:#x} (exe {:#x}) count={} rax={:#x} rbx={:#x} rcx={:#x} rdx={:#x} rsi={:#x} rdi={:#x} r8={:#x} r9={:#x} r12={:#x} r13={:#x} r14={:#x} r15={:#x}",
                    i,
                    h.rip,
                    ToExeAddress(h.rip),
                    h.count,
                    h.rax,
                    h.rbx,
                    h.rcx,
                    h.rdx,
                    h.rsi,
                    h.rdi,
                    h.r8,
                    h.r9,
                    h.r12,
                    h.r13,
                    h.r14,
                    h.r15);
            }
            spdlog::info("[probe] soldier {} position entry now {} {} {}", objectID, entry[0], entry[1], entry[2]);
            watching = false;
        }).detach();

        return true;
    }

    void TestWriteSoldierPosition(const uint32_t objectID, const float x, const float y, const float z) {
        const auto entry = SoldierPositionEntry(objectID);
        if (entry == nullptr) {
            spdlog::info("[probe] write test: soldier {} not found", objectID);
            return;
        }

        spdlog::info("[probe] write test: soldier {} entry {} before {} {} {}, writing {} {} {}", objectID, (void *)entry, entry[0], entry[1], entry[2], x, y, z);
        entry[0] = x;
        entry[1] = y;
        entry[2] = z;

        std::thread([objectID, entry, x, y, z] {
            for (const auto ms : {16, 100, 1000}) {
                std::this_thread::sleep_for(std::chrono::milliseconds(ms));
                const auto kept = entry[0] == x && entry[1] == y && entry[2] == z;
                spdlog::info("[probe] write test: soldier {} after +{}ms: {} {} {} ({})", objectID, ms, entry[0], entry[1], entry[2], kept ? "kept" : "overwritten");
            }
        }).detach();
    }

    bool CaptureSoldierController(const uint32_t objectID) {
        if (capturedObjectID.load() == objectID && capturedController.load() != 0) {
            return true;
        }

        if (watching.load() || capturing.exchange(true)) {
            spdlog::info("[probe] capture: busy");
            return false;
        }

        const auto entry = SoldierPositionEntry(objectID);
        if (entry == nullptr) {
            spdlog::info("[probe] capture: soldier {} not found", objectID);
            capturing = false;
            return false;
        }

        captureObjectID = objectID;
        capturedObjectID = 0xffffffff;
        capturedController = 0;
        captureAddress = reinterpret_cast<uint64_t>(entry);
        if (vehHandle == nullptr) {
            vehHandle = AddVectoredExceptionHandler(1, Handler);
        }

        std::thread([objectID, entry] {
            SetBreakpointAllThreads(reinterpret_cast<uint64_t>(entry));
            for (int i = 0; i < 50 && capturedObjectID.load() != objectID; i++) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            SetBreakpointAllThreads(0);
            capturing = false;

            if (capturedObjectID.load() == objectID) {
                spdlog::info("[probe] capture: soldier {} controller {:#x} local index {} (writer exe {:#x})",
                    objectID,
                    capturedController.load(),
                    capturedLocalIndex.load(),
                    ToExeAddress(capturedRip.load()));
            } else {
                spdlog::info("[probe] capture: soldier {} position was not written within 500 ms", objectID);
            }
        }).detach();

        return capturedObjectID.load() == objectID;
    }

    int WarpSoldier(const uint32_t objectID, const float x, const float y, const float z) {
        if (capturedObjectID.load() != objectID || capturedController.load() == 0) {
            return 0;
        }

        using GetCharaFunc = void *(__fastcall *)(void *ctrl, uint32_t localIndex);
        using SetRotFunc = void(__fastcall *)(void *obj, void *rot);
        using SetTransformFunc = void(__fastcall *)(void *obj, void *pos, void *rot);
        using GetRotFunc = void *(__fastcall *)(void *obj);

        const auto ctrl = reinterpret_cast<void *>(capturedController.load());
        const auto localIndex = capturedLocalIndex.load();
        const auto ctrlVtable = *reinterpret_cast<void ***>(ctrl);
        const auto getChara = reinterpret_cast<GetCharaFunc>(ctrlVtable[0x388 / 8]);
        const auto obj = getChara(ctrl, localIndex);
        if (obj == nullptr) {
            spdlog::info("[probe] warp: soldier {} no character object", objectID);
            return -1;
        }

        const auto objVtable = *reinterpret_cast<void ***>(obj);
        const auto objPos = reinterpret_cast<float *>((char *)obj + 0x20);
        const auto heightOffset = *reinterpret_cast<float *>((char *)obj + 0x160);
        const auto entry = SoldierPositionEntry(objectID);

        spdlog::info("[probe] warp: soldier {} obj {} vtable exe {:#x} vf68 exe {:#x} vf70 exe {:#x} vf78 exe {:#x}",
            objectID,
            obj,
            ToExeAddress(reinterpret_cast<uint64_t>(objVtable)),
            ToExeAddress(reinterpret_cast<uint64_t>(objVtable[0x68 / 8])),
            ToExeAddress(reinterpret_cast<uint64_t>(objVtable[0x70 / 8])),
            ToExeAddress(reinterpret_cast<uint64_t>(objVtable[0x78 / 8])));
        spdlog::info("[probe] warp: obj pos {} {} {} height offset {}, table entry {} {} {}",
            objPos[0],
            objPos[1],
            objPos[2],
            heightOffset,
            entry ? entry[0] : 0.0f,
            entry ? entry[1] : 0.0f,
            entry ? entry[2] : 0.0f);

        // make sure object belongs to this soldier before touching it
        if (entry == nullptr || std::abs(objPos[0] - entry[0]) > 1.0f || std::abs(objPos[2] - entry[2]) > 1.0f) {
            spdlog::info("[probe] warp: soldier {} object position does not match table, not warping", objectID);
            capturedObjectID = 0xffffffff;
            return -1;
        }

        // keep current orientation
        const auto getRot = reinterpret_cast<GetRotFunc>(objVtable[0x78 / 8]);
        alignas(16) float rot[4];
        memcpy(rot, getRot(obj), sizeof(rot));
        alignas(16) float pos[4] = {x, y, z, 0.0f};

        const auto setRot = reinterpret_cast<SetRotFunc>(objVtable[0x70 / 8]);
        const auto setTransform = reinterpret_cast<SetTransformFunc>(objVtable[0x68 / 8]);
        setRot(obj, rot);
        setTransform(obj, pos, rot);

        spdlog::info("[probe] warp: soldier {} moved to {} {} {}, obj pos now {} {} {}", objectID, x, y, z, objPos[0], objPos[1], objPos[2]);

        std::thread([objectID, entry, x, z] {
            for (const auto ms : {50, 500, 2000}) {
                std::this_thread::sleep_for(std::chrono::milliseconds(ms));
                const auto ok = std::abs(entry[0] - x) < 0.5f && std::abs(entry[2] - z) < 0.5f;
                spdlog::info("[probe] warp: soldier {} after +{}ms table {} {} {} ({})", objectID, ms, entry[0], entry[1], entry[2], ok ? "at target" : "not at target");
            }
        }).detach();

        return 1;
    }
}
