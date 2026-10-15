#include "PlayerProbe.h"

#include "DynamiteHook.h"
#include "dynamite.h"
#include "spdlog/spdlog.h"
#include "windows.h"

#include <atomic>
#include <cstring>
#include <string>
#include <thread>
#include <tlhelp32.h>

namespace Dynamite::PlayerProbe {
    namespace {
        // 1.0.15.4: PlayerInfoService records, base 0x142bd3ff0 + (buffer * 16 + player) * 0xe0, read buffer index at 0x142bd3fd0
        constexpr uint64_t infoBase = 0x142bd3ff0;
        constexpr uint64_t infoBufferIndex = 0x142bd3fd0;
        constexpr uint64_t infoSize = 0xe0;
        constexpr uint64_t positionGetter = 0x14053ca40; // movsxd rax, [rip+...]; cmp ecx, 0x10

        const uint64_t exeBase = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
        uint64_t exeEnd = 0;

        uint8_t *Exe(const uint64_t a) { return reinterpret_cast<uint8_t *>(a - 0x140000000 + exeBase); }
        uint64_t ToExe(const uint64_t a) { return a - exeBase + 0x140000000; }
        bool InExe(const uint64_t a) { return a > exeBase + 0x1000 && a < exeEnd; }

        uint8_t *Record(const int buffer, const int player) { return Exe(infoBase) + (buffer * 16 + player) * infoSize; }

        // --- record diff ---
        uint32_t previous[2][infoSize / 4];
        bool havePrevious = false;
        double nextDiff = 0;

        // --- writer capture (DR1, DR2 only; DR0 belongs to SoldierWarp) ---
        constexpr int maxWriters = 8;
        constexpr int maxFrames = 16;
        struct Writer {
            uint64_t rip;
            uint32_t count;
            uint64_t rcx, rdx, r8, rbx, rsi, rdi;
            uint64_t frames[maxFrames];
            int frameCount;
        };
        Writer writers[maxWriters];
        std::atomic<int> writerCount{0};
        std::atomic<bool> watching{false};
        bool watchDone = false;
        double watchStart = 0;
        PVOID vehHandle = nullptr;

        constexpr uint64_t dr7Mask = (0x3ull << 2) | (0x3ull << 4) | (0xFFull << 20); // L1/G1, L2/G2, RW/LEN 1-2
        uint64_t Dr7For(const bool on) {
            if (!on) {
                return 0;
            }
            // L1, L2; RW=01 (write), LEN=11 (4 bytes)
            return (1ull << 2) | (1ull << 4) | (0xDull << 20) | (0xDull << 24);
        }

        LONG WINAPI Handler(EXCEPTION_POINTERS *info) {
            if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
                return EXCEPTION_CONTINUE_SEARCH;
            }
            auto *ctx = info->ContextRecord;
            if ((ctx->Dr6 & 6) == 0 || !watching.load()) {
                return EXCEPTION_CONTINUE_SEARCH;
            }
            ctx->Dr6 = 0;

            const auto rip = ctx->Rip;
            const auto n = std::min(writerCount.load(), maxWriters);
            for (int i = 0; i < n; i++) {
                if (writers[i].rip == rip) {
                    writers[i].count++;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            const auto slot = writerCount.fetch_add(1);
            if (slot >= maxWriters) {
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            auto &w = writers[slot];
            w = Writer{};
            w.rip = rip;
            w.count = 1;
            w.rcx = ctx->Rcx;
            w.rdx = ctx->Rdx;
            w.r8 = ctx->R8;
            w.rbx = ctx->Rbx;
            w.rsi = ctx->Rsi;
            w.rdi = ctx->Rdi;
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
                w.frames[w.frameCount++] = walk.Rip;
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        void SetBreakpoints(const uint64_t a1, const uint64_t a2) {
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
                        ctx.Dr1 = a1;
                        ctx.Dr2 = a2;
                        ctx.Dr7 = (ctx.Dr7 & ~dr7Mask) | Dr7For(a1 != 0);
                        SetThreadContext(th, &ctx);
                    }
                    ResumeThread(th);
                }
                CloseHandle(th);
            }
            CloseHandle(snap);
        }

        double Now() {
            static LARGE_INTEGER freq{};
            if (freq.QuadPart == 0) {
                QueryPerformanceFrequency(&freq);
            }
            LARGE_INTEGER c;
            QueryPerformanceCounter(&c);
            return static_cast<double>(c.QuadPart) / static_cast<double>(freq.QuadPart);
        }

        bool CheckVersion() {
            static int ok = -1;
            if (ok < 0) {
                const auto dos = reinterpret_cast<IMAGE_DOS_HEADER *>(exeBase);
                const auto nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(exeBase + dos->e_lfanew);
                exeEnd = exeBase + nt->OptionalHeader.SizeOfImage;
                const uint8_t expected[] = {0x48, 0x63, 0x05}; // movsxd rax, [rip+...]
                ok = memcmp(Exe(positionGetter), expected, sizeof(expected)) == 0 ? 1 : 0;
                spdlog::info("[playerprobe] {}", ok ? "enabled" : "player info functions not found (game version?), disabled");
            }
            return ok == 1;
        }

        void DumpWriters() {
            const auto n = std::min(writerCount.load(), maxWriters);
            spdlog::info("[playerprobe] remote player record writers: {}", n);
            for (int i = 0; i < n; i++) {
                const auto &w = writers[i];
                std::string frames;
                for (int f = 0; f < w.frameCount; f++) {
                    frames += fmt::format(" {:#x}", ToExe(w.frames[f]));
                }
                spdlog::info("[playerprobe] writer #{} rip {:#x} count {} rcx {:#x} rdx {:#x} r8 {:#x} rbx {:#x} rsi {:#x} rdi {:#x}",
                    i, ToExe(w.rip), w.count, w.rcx, w.rdx, w.r8, w.rbx, w.rsi, w.rdi);
                spdlog::info("[playerprobe] writer #{} stack{}", i, frames);
            }
        }
    }

    void Tick() {
        if (!CheckVersion()) {
            return;
        }
        const auto now = Now();
        static const double firstTick = now;
        const int remote = g_hook->cfg.Host ? 1 : 0;

        // catch writers of remote player's record once, 20 s into the mission, for 3 seconds
        if (!watchDone && !watching.load() && now - firstTick > 20.0) {
            if (vehHandle == nullptr) {
                vehHandle = AddVectoredExceptionHandler(1, Handler);
            }
            const auto a1 = reinterpret_cast<uint64_t>(Record(0, remote) + 0x10);
            const auto a2 = reinterpret_cast<uint64_t>(Record(1, remote) + 0x10);
            writerCount = 0;
            watching = true;
            watchStart = now;
            std::thread([a1, a2] { SetBreakpoints(a1, a2); }).detach();
            spdlog::info("[playerprobe] watching remote player {} records {:#x} {:#x}", remote, a1, a2);
        }
        if (watching.load() && now - watchStart > 3.0) {
            watching = false;
            watchDone = true;
            std::thread([] { SetBreakpoints(0, 0); }).detach();
            DumpWriters();
        }

        // record field changes, twice a second
        if (now < nextDiff) {
            return;
        }
        nextDiff = now + 0.5;
        const auto buffer = *reinterpret_cast<int32_t *>(Exe(infoBufferIndex));
        if (buffer != 0 && buffer != 1) {
            return;
        }
        for (int p = 0; p < 2; p++) {
            uint32_t cur[infoSize / 4];
            memcpy(cur, Record(buffer, p), infoSize);
            if (havePrevious) {
                std::string changed;
                for (size_t i = 0; i < infoSize / 4; i++) {
                    // skip position (+0x10..+0x1c), changes constantly while moving
                    if (i >= 4 && i < 8) {
                        continue;
                    }
                    if (cur[i] != previous[p][i]) {
                        changed += fmt::format(" +{:02x}:{:08x}->{:08x}", i * 4, previous[p][i], cur[i]);
                    }
                }
                if (!changed.empty()) {
                    spdlog::info("[playerprobe] player {}{} changed:{}", p, p == remote ? " (partner)" : " (me)", changed);
                }
            } else {
                std::string all;
                for (size_t i = 0; i < infoSize / 4; i++) {
                    all += fmt::format(" {:08x}", cur[i]);
                }
                spdlog::info("[playerprobe] player {} record:{}", p, all);
            }
            memcpy(previous[p], cur, infoSize);
        }
        havePrevious = true;
    }
}
