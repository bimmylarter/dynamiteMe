#include "PlayerProbe.h"

#include "BodyFollow.h"
#include "CarryProbe.h"
#include "DynamiteHook.h"
#include "MinHook.h"
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
            if ((ctx->Dr6 & 6) == 0) {
                return EXCEPTION_CONTINUE_SEARCH;
            }
            ctx->Dr6 = 0;
            if (!watching.load()) {
                // late hit after watching stopped: switch our slots off on this thread and carry on
                ctx->Dr7 &= ~dr7Mask;
                return EXCEPTION_CONTINUE_EXECUTION;
            }

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
                spdlog::info("[playerprobe] probe build v15, {}", ok ? "enabled" : "player info functions not found (game version?), disabled");
            }
            return ok == 1;
        }

        // --- per-player state arrays (read by the PlayerInfoService update 0x1412ce870, rcx = updater) ---
        // state = *(*(updater + 0x50) + 0x60):
        //   +0x18 u16[] action state code, +0x20 u8[], +0x28 u8[] carrying (1 -> info +0xd0 bit 0x40),
        //   +0x30 u8[] stance (1 stand, 2 squat, 3/4 crawl), +0x38 u8[] speed, +0xd8 u16[] carried object, +0xe0 u16[]
        constexpr uint64_t infoUpdate = 0x1412ce870;
        using InfoUpdateFunc = void *(__fastcall *)(void *self, void *a2, void *a3, void *a4);
        InfoUpdateFunc oInfoUpdate = nullptr;
        std::atomic<uint64_t> infoUpdater{0};

        void *__fastcall hkInfoUpdate(void *self, void *a2, void *a3, void *a4) {
            infoUpdater = reinterpret_cast<uint64_t>(self);
            return oInfoUpdate(self, a2, a3, a4);
        }

        void InstallInfoHook() {
            static bool done = false;
            if (done) {
                return;
            }
            done = true;
            const uint8_t expected[] = {0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x10, 0x48, 0x89, 0x70, 0x18};
            if (memcmp(Exe(infoUpdate), expected, sizeof(expected)) != 0) {
                spdlog::info("[playerprobe] info update function not found");
                return;
            }
            if (MH_CreateHook(Exe(infoUpdate), reinterpret_cast<void *>(&hkInfoUpdate), reinterpret_cast<void **>(&oInfoUpdate)) != MH_OK ||
                MH_EnableHook(Exe(infoUpdate)) != MH_OK) {
                spdlog::info("[playerprobe] cannot hook info update");
                return;
            }
            spdlog::info("[playerprobe] info update hooked");
        }

        char *StateArrays() {
            const auto u = reinterpret_cast<char *>(infoUpdater.load());
            if (u == nullptr) {
                return nullptr;
            }
            const auto a = *(char **)(u + 0x50);
            return a ? *(char **)(a + 0x60) : nullptr;
        }

        struct PlayerState {
            uint16_t code;
            uint8_t b20, carry, stance, speed;
            uint16_t target, other;
            bool operator==(const PlayerState &) const = default;
        };

        PlayerState ReadState(char *st, const int p) {
            PlayerState s{};
            s.code = (*(uint16_t **)(st + 0x18))[p];
            s.b20 = (*(uint8_t **)(st + 0x20))[p];
            s.carry = (*(uint8_t **)(st + 0x28))[p];
            s.stance = (*(uint8_t **)(st + 0x30))[p];
            s.speed = (*(uint8_t **)(st + 0x38))[p];
            s.target = (*(uint16_t **)(st + 0xd8))[p];
            s.other = (*(uint16_t **)(st + 0xe0))[p];
            return s;
        }

        PlayerState lastState[2]{};
        bool haveState = false;
        bool injecting = false;

        // --- motion controller (v14) ---
        // Carry code changes the player's animation with ctrl->vf[0x170](ctrl, playerIndex, layer, stateHash, float blend, int flags),
        // ctrl = *(*(playerSystem + 0x78) + 0x238). Player systems: net = *(updater + 0x50),
        // system index of player p = (*(u8 **)(net + 0x78))[p], system = (*(void ***)(net + 0x50))[index].
        using MotionFunc = uint64_t(__fastcall *)(void *ctrl, uint32_t player, uint32_t layer, uint64_t state, float blend, int32_t flags);
        constexpr int maxMotionHooks = 4;
        struct MotionHook {
            uint64_t target;
            MotionFunc original;
        };
        MotionHook motionHooks[maxMotionHooks]{};
        int motionHookCount = 0;
        void *motionCtrl[2] = {nullptr, nullptr};

        std::atomic<int> motionLogBudget{0};
        constexpr int maxMotionSeen = 600;
        uint64_t motionSeen[maxMotionSeen][3];
        int motionSeenCount = 0;
        std::atomic_flag motionLock = ATOMIC_FLAG_INIT;

        void LogMotion(const int hook, void *ctrl, const uint32_t player, const uint32_t layer, const uint64_t state, const float blend, const int32_t flags, const uint64_t ret) {
            bool fresh = false;
            while (motionLock.test_and_set(std::memory_order_acquire)) {
            }
            const uint64_t key = (static_cast<uint64_t>(player) << 56) ^ (static_cast<uint64_t>(layer) << 48) ^ state;
            int i = 0;
            for (; i < motionSeenCount; i++) {
                if (motionSeen[i][0] == key && motionSeen[i][1] == ret) {
                    motionSeen[i][2]++;
                    break;
                }
            }
            if (i == motionSeenCount && motionSeenCount < maxMotionSeen) {
                motionSeen[i][0] = key;
                motionSeen[i][1] = ret;
                motionSeen[i][2] = 1;
                motionSeenCount++;
                fresh = true;
            }
            motionLock.clear(std::memory_order_release);
            // every new (player, layer, state, caller), plus every call during a short window after a carry starts
            if (fresh || (motionLogBudget.load() > 0 && motionLogBudget.fetch_sub(1) > 0)) {
                spdlog::info("[playerprobe] motion{} ctrl {} player {} layer {} state {:012x} blend {} flags {:#x} from {:#x}{}",
                    hook, ctrl, player, layer, state & 0xffffffffffffull, blend, flags, ret, fresh ? " (new)" : "");
            }
        }

        template <int N>
        uint64_t __fastcall hkMotion(void *ctrl, uint32_t player, uint32_t layer, uint64_t state, float blend, int32_t flags) {
            LogMotion(N, ctrl, player, layer, state, blend, flags, ToExe(reinterpret_cast<uint64_t>(__builtin_return_address(0))));
            return motionHooks[N].original(ctrl, player, layer, state, blend, flags);
        }

        void *hookFuncs[maxMotionHooks] = {
            reinterpret_cast<void *>(&hkMotion<0>), reinterpret_cast<void *>(&hkMotion<1>),
            reinterpret_cast<void *>(&hkMotion<2>), reinterpret_cast<void *>(&hkMotion<3>)};

        void HookMotion(const int p, void *ctrl, const char *how) {
            if (ctrl == nullptr || ctrl == motionCtrl[p]) {
                return;
            }
            motionCtrl[p] = ctrl;
            const auto vt = *(uint64_t **)ctrl;
            const auto fn = vt[0x170 / 8];
            spdlog::info("[playerprobe] player {} motion ctrl {} ({}) vtable {:#x} vf170 {:#x}", p, ctrl, how, ToExe(reinterpret_cast<uint64_t>(vt)), ToExe(fn));
            bool hooked = false;
            for (int h = 0; h < motionHookCount; h++) {
                hooked |= motionHooks[h].target == fn;
            }
            if (!hooked && motionHookCount < maxMotionHooks && InExe(fn)) {
                const auto h = motionHookCount;
                motionHooks[h].target = fn;
                if (MH_CreateHook(reinterpret_cast<void *>(fn), hookFuncs[h], reinterpret_cast<void **>(&motionHooks[h].original)) == MH_OK &&
                    MH_EnableHook(reinterpret_cast<void *>(fn)) == MH_OK) {
                    motionHookCount++;
                    spdlog::info("[playerprobe] motion function {:#x} hooked as motion{}", ToExe(fn), h);
                } else {
                    spdlog::info("[playerprobe] cannot hook motion function {:#x}", ToExe(fn));
                }
            }
        }

        bool Ptr(const void *p) { return p != nullptr && (reinterpret_cast<uint64_t>(p) & 7) == 0 && reinterpret_cast<uint64_t>(p) > 0x10000; }

        void FindMotionControllers() {
            static double nextDiag = 0;
            const auto now = Now();
            const bool diag = now >= nextDiag;
            if (diag) {
                nextDiag = now + 15.0;
            }

            // route 1: local player through the carry component (known after a local carry event)
            const auto comp = reinterpret_cast<char *>(CarryProbe::Component());
            if (comp != nullptr) {
                const auto ctx = *(char **)(comp + 8);
                const auto tbl = Ptr(ctx) ? *(char **)(ctx + 0x78) : nullptr;
                const auto ctrl = Ptr(tbl) ? *(void **)(tbl + 0x238) : nullptr;
                if (Ptr(ctrl)) {
                    HookMotion(g_hook->cfg.Host ? 0 : 1, ctrl, "carry component");
                }
            }

            // route 2: every player through the info updater's player systems
            const auto u = reinterpret_cast<char *>(infoUpdater.load());
            if (u == nullptr) {
                return;
            }
            const auto net = *(char **)(u + 0x50);
            if (!Ptr(net)) {
                if (diag) {
                    spdlog::info("[playerprobe] diag: updater {} net {}", (void *)u, (void *)net);
                }
                return;
            }
            const auto systems = *(char ***)(net + 0x50);
            const auto playerObj = *(uint16_t **)(net + 0x70);
            const auto sysIndex = *(uint8_t **)(net + 0x78);
            if (diag) {
                spdlog::info("[playerprobe] diag: updater {} net {} systems {} playerObj {} sysIndex {} count {}",
                    (void *)u, (void *)net, (void *)systems, (void *)playerObj, (void *)sysIndex, *(uint32_t *)(u + 0x90));
                if (Ptr(playerObj)) {
                    spdlog::info("[playerprobe] diag: player objects {:#x} {:#x}", playerObj[0], playerObj[1]);
                }
            }
            if (!Ptr(systems) || sysIndex == nullptr || playerObj == nullptr) {
                return;
            }
            for (int p = 0; p < 2; p++) {
                // the updater uses the system map only when the player has an object (0xffff = none)
                const auto si = playerObj[p] == 0xffff ? 0xff : sysIndex[p];
                static int loggedIndex[2] = {-1, -1};
                if (loggedIndex[p] != si) {
                    loggedIndex[p] = si;
                    spdlog::info("[playerprobe] player {} object {:#x} player system #{}", p, playerObj[p], si);
                }
                if (si == 0xff) {
                    continue;
                }
                const auto sys = systems[si];
                const auto tbl = Ptr(sys) ? *(char **)(sys + 0x78) : nullptr;
                const auto ctrl = Ptr(tbl) ? *(void **)(tbl + 0x238) : nullptr;
                if (diag) {
                    spdlog::info("[playerprobe] diag: player {} system {} table {} ctrl {} table base {}", p, (void *)sys, (void *)tbl, ctrl,
                        Ptr(tbl) ? *(uint32_t *)(tbl + 8) : 0xffffffff);
                }
                if (Ptr(ctrl)) {
                    HookMotion(p, ctrl, "player system");
                }
            }
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
        if (false && !watchDone && !watching.load() && now - firstTick > 20.0) { // v12: disabled, writers found (0x1412cf26a)
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

        InstallInfoHook();
        FindMotionControllers();

        // log every motion call for a few seconds after a carry starts (local or partner)
        {
            static bool wasCarrying = false;
            bool carrying = BodyFollow::FollowedID() != 0xffffffff;
            if (auto st = StateArrays()) {
                carrying |= (*(uint8_t **)(st + 0x28))[g_hook->cfg.Host ? 0 : 1] != 0;
            }
            if (carrying && !wasCarrying) {
                motionLogBudget = 150;
                spdlog::info("[playerprobe] carry started, logging motion calls");
            }
            if (!carrying && wasCarrying) {
                motionLogBudget = 150;
                spdlog::info("[playerprobe] carry ended, logging motion calls");
            }
            wasCarrying = carrying;
        }

        if (auto st = StateArrays()) {
            for (int p = 0; p < 2; p++) {
                const auto cur = ReadState(st, p);
                if (!haveState || !(cur == lastState[p])) {
                    spdlog::info("[playerprobe] state player {}{}: code {:#x} b20 {} carry {} stance {} speed {} target {:#x} other {:#x}",
                        p, p == remote ? " (partner)" : " (me)", cur.code, cur.b20, cur.carry, cur.stance, cur.speed, cur.target, cur.other);
                    lastState[p] = cur;
                }
            }
            haveState = true;
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
                    // skip positions / vectors (+0x10..+0x5c) and +0x98 (float), they change constantly while moving
                    if ((i >= 4 && i < 0x18) || i == 0x98 / 4) {
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
