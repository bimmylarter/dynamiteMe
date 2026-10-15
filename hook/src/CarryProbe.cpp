#include "CarryProbe.h"

#include "DynamiteCore.h"
#include "DynamiteHook.h"
#include "dynamite.h"
#include "mgsvtpp_func_typedefs.h"
#include "spdlog/spdlog.h"
#include "windows.h"

#include <atomic>
#include <intrin.h>
#include <cmath>
#include <cstring>
#include <mutex>
#include <thread>
#include <tlhelp32.h>

namespace Dynamite::CarryProbe {
    namespace {
        constexpr int maxTraces = 24;
        constexpr int maxFrames = 14;
        constexpr int noSoldier = -1;

        struct Trace {
            uint64_t rip;
            uint32_t dr;
            uint32_t count;
            uint64_t before[3]; // watched values at time of hit
            uint64_t rcx, rdx, r8, r9, rbx, rsi, rdi, rbp, r12, r13, r14, r15;
            uint64_t frames[maxFrames];
            int frameCount;
        };

        Trace traces[maxTraces];
        std::atomic<int> traceCount{0};
        std::atomic<int> armedSoldier{noSoldier};
        uint64_t watched[3] = {0, 0, 0};
        PVOID vehHandle = nullptr;
        std::mutex armMutex;

        const uint64_t exeBase = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
        uint64_t exeEnd = 0;

        uint64_t ToExe(const uint64_t a) { return a - exeBase + 0x140000000; }

        bool InExe(const uint64_t a) { return a > exeBase + 0x1000 && a < exeEnd; }

        LONG WINAPI Handler(EXCEPTION_POINTERS *info) {
            if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            auto *ctx = info->ContextRecord;
            const auto drHit = ctx->Dr6 & 7;
            if (drHit == 0 || armedSoldier.load() == noSoldier) {
                return EXCEPTION_CONTINUE_SEARCH;
            }
            ctx->Dr6 = 0;

            const auto rip = ctx->Rip;
            const auto n = std::min(traceCount.load(), maxTraces);
            for (int i = 0; i < n; i++) {
                if (traces[i].rip == rip) {
                    traces[i].count++;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }

            const auto slot = traceCount.fetch_add(1);
            if (slot >= maxTraces) {
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            auto &t = traces[slot];
            t = Trace{};
            t.rip = rip;
            t.dr = static_cast<uint32_t>(drHit);
            t.count = 1;
            for (int i = 0; i < 3; i++) {
                t.before[i] = watched[i] ? *reinterpret_cast<uint64_t *>(watched[i]) : 0;
            }
            t.rcx = ctx->Rcx;
            t.rdx = ctx->Rdx;
            t.r8 = ctx->R8;
            t.r9 = ctx->R9;
            t.rbx = ctx->Rbx;
            t.rsi = ctx->Rsi;
            t.rdi = ctx->Rdi;
            t.rbp = ctx->Rbp;
            t.r12 = ctx->R12;
            t.r13 = ctx->R13;
            t.r14 = ctx->R14;
            t.r15 = ctx->R15;

            // exact call chain using exe unwind tables (no allocation, safe in exception handler)
            CONTEXT walk = *ctx;
            for (int f = 0; f < maxFrames; f++) {
                DWORD64 imageBase = 0;
                const auto fn = RtlLookupFunctionEntry(walk.Rip, &imageBase, nullptr);
                if (fn == nullptr) {
                    break;
                }
                PVOID handlerData = nullptr;
                DWORD64 establisher = 0;
                RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, walk.Rip, fn, &walk, &handlerData, &establisher, nullptr);
                if (walk.Rip == 0 || !InExe(walk.Rip)) {
                    break;
                }
                t.frames[t.frameCount++] = walk.Rip;
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // DR0..DR2 write breakpoints, 8 bytes each; zero address disables slot
        void SetBreakpoints(const uint64_t a[3]) {
            const auto pid = GetCurrentProcessId();
            const auto self = GetCurrentThreadId();
            const auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snap == INVALID_HANDLE_VALUE) {
                return;
            }

            uint64_t dr7 = 0;
            for (int i = 0; i < 3; i++) {
                if (a[i] != 0) {
                    dr7 |= 1ull << (i * 2);                 // Ln
                    dr7 |= (0x1ull | (0x2ull << 2)) << (16 + i * 4); // RW = write, LEN = 8 bytes
                }
            }
            constexpr uint64_t mask = 0x15ull | (0xFFFull << 16);

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
                        ctx.Dr0 = a[0];
                        ctx.Dr1 = a[1];
                        ctx.Dr2 = a[2];
                        ctx.Dr6 = 0;
                        ctx.Dr7 = (ctx.Dr7 & ~mask) | dr7;
                        SetThreadContext(th, &ctx);
                    }
                    ResumeThread(th);
                }
                CloseHandle(th);
            }
            CloseHandle(snap);
        }

        void *SoldierInterface(const uint32_t objectID) {
            auto go = FindGameObjectWithID(objectID);
            if (go == nullptr) {
                return nullptr;
            }
            go = *(void **)((char *)go + 0x40);
            go = *(void **)((char *)go + 0x10);
            const auto interfaceName = "TppSoldier2";
            const auto hash = FoxStrHash32(interfaceName, strlen(interfaceName));
            auto iface = Soldier2ImplGetInterface(go, hash);
            if (iface == nullptr) {
                return nullptr;
            }
            return (char *)iface - 0xc;
        }

        // watched soldier fields (1.0.15.x):
        //   *(iface+0x50):  {+8 base}, 0xd0 bytes per soldier, current action id (u16) at +0xba
        //                   (soldier update reacts to its change, 0x141378475 in 1.0.15.4)
        //   *(iface+0x110): {+8 base, +0x10 count}, 0x28 bytes per soldier, state flags at +0 (read by GetStatus)
        // true if [p, p+size) is committed readable memory
        bool Readable(const void *p, const size_t size) {
            if (p == nullptr) {
                return false;
            }
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT) {
                return false;
            }
            if ((mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
                return false;
            }
            const auto end = (const char *)mbi.BaseAddress + mbi.RegionSize;
            return (const char *)p + size <= end;
        }

        bool StateRecords(const uint32_t objectID, uint64_t out[3]) {
            const auto iface = (char *)SoldierInterface(objectID);
            if (!Readable(iface, 0x120)) {
                spdlog::info("[carryprobe] soldier {} interface {} not readable", objectID, (void *)iface);
                return false;
            }
            const auto idx = objectID - 1024;
            const auto actions = *(char **)(iface + 0x50);
            const auto t1 = *(char **)(iface + 0x110);
            spdlog::info("[carryprobe] soldier {} iface {} +0x50 {} +0x110 {}", objectID, (void *)iface, (void *)actions, (void *)t1);
            if (!Readable(actions, 0x18) || !Readable(t1, 0x18) || idx >= *(uint32_t *)(t1 + 0x10)) {
                spdlog::info("[carryprobe] soldier {} tables not readable", objectID);
                return false;
            }
            const auto actionBase = *(char **)(actions + 8);
            const auto recBase = *(char **)(t1 + 8);
            if (!Readable(actionBase + idx * 0xd0, 0xd0) || !Readable(recBase + idx * 0x28, 0x28)) {
                spdlog::info("[carryprobe] soldier {} records not readable (actions {} records {})", objectID, (void *)actionBase, (void *)recBase);
                return false;
            }
            const auto action = actionBase + idx * 0xd0;
            const auto r1 = recBase + idx * 0x28;
            out[0] = reinterpret_cast<uint64_t>(action + 0xb8);
            out[1] = reinterpret_cast<uint64_t>(r1);
            out[2] = 0;
            return true;
        }

        float Distance(const Vector3 &a, const Vector3 &b) {
            const auto dx = a.x - b.x, dy = a.y - b.y, dz = a.z - b.z;
            return std::sqrt(dx * dx + dy * dy + dz * dz);
        }
    }

    void ArmNearest() {
        std::lock_guard lock(armMutex);

        if (exeEnd == 0) {
            const auto dos = reinterpret_cast<IMAGE_DOS_HEADER *>(exeBase);
            const auto nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(exeBase + dos->e_lfanew);
            exeEnd = exeBase + nt->OptionalHeader.SizeOfImage;
        }

        const auto localIndex = g_hook->cfg.Host ? 0 : 1;
        const auto me = DynamiteCore::GetPlayerPosition(localIndex);

        int best = noSoldier;
        float bestDist = 4.0f;
        for (uint32_t id = 1024; id < 1024 + 512; id++) {
            if (FindGameObjectWithID(id) == nullptr) {
                continue;
            }
            const auto life = DynamiteCore::GetSoldierLifeStatus(id);
            if (life != ENPCLifeState::SLEEP && life != ENPCLifeState::FAINT && life != ENPCLifeState::DYING && life != ENPCLifeState::DEAD) {
                continue;
            }
            const auto pos = DynamiteCore::GetSoldierPosition(id);
            const auto d = Distance(me, pos);
            if (d < bestDist) {
                bestDist = d;
                best = static_cast<int>(id);
            }
        }

        if (best == noSoldier || best == armedSoldier.load()) {
            return;
        }

        uint64_t rec[3];
        if (!StateRecords(best, rec)) {
            return;
        }

        if (vehHandle == nullptr) {
            vehHandle = AddVectoredExceptionHandler(1, Handler);
        }

        traceCount = 0;
        memcpy(watched, rec, sizeof(watched));
        armedSoldier = best;
        std::thread([rec] {
            uint64_t r[3] = {rec[0], rec[1], rec[2]};
            SetBreakpoints(r);
        }).detach();

        spdlog::info("[carryprobe] watching soldier {} ({:.1f} m) records {:#x} {:#x} {:#x} = {:#x} {:#x} {:#x}",
            best,
            bestDist,
            rec[0],
            rec[1],
            rec[2],
            rec[0] ? *(uint64_t *)rec[0] : 0,
            rec[1] ? *(uint64_t *)rec[1] : 0,
            rec[2] ? *(uint64_t *)rec[2] : 0);
    }

    void Dump(const std::string &tag) {
        const auto soldier = armedSoldier.load();
        const auto n = std::min(traceCount.load(), maxTraces);
        spdlog::info("[carryprobe] {} soldier {}: {} unique writers, records now {:#x} {:#x} {:#x}",
            tag,
            soldier,
            n,
            watched[0] ? *(uint64_t *)watched[0] : 0,
            watched[1] ? *(uint64_t *)watched[1] : 0,
            watched[2] ? *(uint64_t *)watched[2] : 0);
        for (int i = 0; i < n; i++) {
            const auto &t = traces[i];
            std::string frames;
            for (int f = 0; f < t.frameCount; f++) {
                frames += fmt::format(" {:#x}", ToExe(t.frames[f]));
            }
            spdlog::info("[carryprobe] {} #{} rip {:#x} dr{} count {} before {:#x} {:#x} {:#x}", tag, i, ToExe(t.rip), t.dr, t.count, t.before[0], t.before[1], t.before[2]);
            spdlog::info("[carryprobe] {} #{} regs rcx {:#x} rdx {:#x} r8 {:#x} r9 {:#x} rbx {:#x} rsi {:#x} rdi {:#x} rbp {:#x} r12 {:#x} r13 {:#x} r14 {:#x} r15 {:#x}",
                tag,
                i,
                t.rcx,
                t.rdx,
                t.r8,
                t.r9,
                t.rbx,
                t.rsi,
                t.rdi,
                t.rbp,
                t.r12,
                t.r13,
                t.r14,
                t.r15);
            spdlog::info("[carryprobe] {} #{} stack{}", tag, i, frames);
        }
        traceCount = 0;
    }

    void Disarm() {
        std::lock_guard lock(armMutex);
        if (armedSoldier.exchange(noSoldier) == noSoldier) {
            return;
        }
        memset(watched, 0, sizeof(watched));
        std::thread([] {
            uint64_t r[3] = {0, 0, 0};
            SetBreakpoints(r);
        }).detach();
    }
}
