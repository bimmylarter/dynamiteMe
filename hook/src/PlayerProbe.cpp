#include "PlayerProbe.h"

#include "BodyFollow.h"
#include "DynamiteCore.h"
#include "mgsvtpp_func_typedefs.h"
#include "CarryProbe.h"
#include "SoldierWarp.h"
#include "DynamiteSyncImpl/DynamiteSyncImpl.h"
#include <mutex>
#include <vector>
#include "DynamiteHook.h"
#include "MinHook.h"
#include "dynamite.h"
#include "spdlog/spdlog.h"
#include "windows.h"

#include <atomic>
#include <iterator>
#include <array>
#include <intrin.h>
#include <utility>
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
                spdlog::info("[playerprobe] probe build v23, {}", ok ? "enabled" : "player info functions not found (game version?), disabled");
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
            const auto res = oInfoUpdate(self, a2, a3, a4);
            // player info was just refreshed for this frame: move the carried body with the partner now, not a frame later
            BodyFollow::PlaceAttached();
            return res;
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
            uint16_t method; // vtable offset: 0x170 change state, 0x160 / 0x190 used for the soldier's pickup and put-down
        };
        constexpr uint16_t motionMethods[] = {0x170, 0x160, 0x190};
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

        // --- v17: carry animation forwarding ---
        // carrier side: requests made by the local player's carry code (player ctrl) and by the carried soldier's
        // carried-AI (soldier ctrl) are sent to the partner, who replays them on our character / that soldier.
        constexpr uint64_t carryCodeStart = 0x141128000, carryCodeEnd = 0x141140000;       // player carry component
        constexpr uint64_t carriedAiStart = 0x1413b2000, carriedAiEnd = 0x1413b6000;       // soldier carried AI
        std::mutex outMutex;
        std::vector<CarryMotionUpdate> outgoing;
        std::atomic<uint32_t> localCarryTarget{0xffff};
        std::atomic<bool> replaying{false};
        // carried soldier's motion ctrl / index on the carrier, learned from its carried-AI requests
        std::atomic<uint64_t> carriedCtrl{0};
        std::atomic<uint32_t> carriedIndex{0xffffffff};
        std::atomic<uint32_t> carriedID{0xffff};
        std::atomic<uint64_t> forwardUntil{0}; // GetTickCount64: keep forwarding soldier requests a while after the drop
        // recent soldier requests (carrier side), so the start of a pickup can be sent once the soldier is identified
        struct RecentMotion {
            uint64_t tick;
            uint64_t ctrl;
            uint32_t index;
            CarryMotionUpdate m;
        };
        constexpr size_t maxRecent = 96;
        std::vector<RecentMotion> recent;
        uint64_t carryStartTick = 0;

        // watcher side: soldier motion ctrl by soldier local index, learned from soldier motion requests
        constexpr int maxSoldierSlots = 64;
        std::atomic<uint64_t> soldierCtrlByIndex[maxSoldierSlots]{};

        template <int N>
        uint64_t __fastcall hkMotion(void *ctrl, uint32_t player, uint32_t layer, uint64_t state, float blend, int32_t flags) {
            const auto ret = ToExe(reinterpret_cast<uint64_t>(__builtin_return_address(0)));
            LogMotion(N, ctrl, player, layer, state, blend, flags, ret);
            if (!replaying.load()) {
                const int local = g_hook->cfg.Host ? 0 : 1;
                if (ctrl == motionCtrl[local] && player == static_cast<uint32_t>(local) && ret >= carryCodeStart && ret < carryCodeEnd) {
                    std::lock_guard lock(outMutex);
                    outgoing.push_back({.body = false, .objectID = 0, .layer = layer, .state = state, .blend = blend, .flags = flags, .method = motionHooks[N].method});
                } else if (reinterpret_cast<uint64_t>(ctrl) == carriedCtrl.load() && player == carriedIndex.load() &&
                           (localCarryTarget.load() != 0xffff || GetTickCount64() < forwardUntil.load())) {
                    // everything the carried soldier plays while picked up, carried and put down
                    std::lock_guard lock(outMutex);
                    outgoing.push_back({.body = true, .objectID = carriedID.load(), .layer = layer, .state = state, .blend = blend, .flags = flags, .method = motionHooks[N].method});
                } else if (ret >= carriedAiStart && ret < carriedAiEnd && localCarryTarget.load() != 0xffff) {
                    carriedCtrl = reinterpret_cast<uint64_t>(ctrl);
                    carriedIndex = player;
                    carriedID = localCarryTarget.load();
                    std::lock_guard lock(outMutex);
                    outgoing.push_back({.body = true, .objectID = carriedID.load(), .layer = layer, .state = state, .blend = blend, .flags = flags, .method = motionHooks[N].method});
                } else if (ctrl != motionCtrl[0] && ctrl != motionCtrl[1]) {
                    std::lock_guard lock(outMutex);
                    if (recent.size() >= maxRecent) {
                        recent.erase(recent.begin());
                    }
                    recent.push_back({GetTickCount64(), reinterpret_cast<uint64_t>(ctrl), player,
                        {.body = true, .objectID = 0, .layer = layer, .state = state, .blend = blend, .flags = flags, .method = motionHooks[N].method}});
                }
                if (ctrl != motionCtrl[0] && ctrl != motionCtrl[1] && player < maxSoldierSlots) {
                    soldierCtrlByIndex[player] = reinterpret_cast<uint64_t>(ctrl);
                }
            }
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
            spdlog::info("[playerprobe] player {} motion ctrl {} ({}) vtable {:#x} vf170 {:#x}", p, ctrl, how, ToExe(reinterpret_cast<uint64_t>(vt)), ToExe(vt[0x170 / 8]));
            for (const auto method : motionMethods) {
                const auto fn = vt[method / 8];
                bool hooked = false;
                for (int h = 0; h < motionHookCount; h++) {
                    hooked |= motionHooks[h].target == fn;
                }
                if (hooked || motionHookCount >= maxMotionHooks || !InExe(fn)) {
                    continue;
                }
                const auto h = motionHookCount;
                motionHooks[h].target = fn;
                motionHooks[h].method = method;
                if (MH_CreateHook(reinterpret_cast<void *>(fn), hookFuncs[h], reinterpret_cast<void **>(&motionHooks[h].original)) == MH_OK &&
                    MH_EnableHook(reinterpret_cast<void *>(fn)) == MH_OK) {
                    motionHookCount++;
                    spdlog::info("[playerprobe] motion method {:#x} ({:#x}) hooked as motion{}", method, ToExe(fn), h);
                } else {
                    spdlog::info("[playerprobe] cannot hook motion method {:#x} ({:#x})", method, ToExe(fn));
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

        void Replay(void *ctrl, const uint32_t index, const CarryMotionUpdate &m) {
            const auto method = m.method == 0 ? 0x170 : m.method;
            const auto fn = reinterpret_cast<MotionFunc>((*(void ***)ctrl)[method / 8]);
            bool known = false;
            for (int h = 0; h < motionHookCount; h++) {
                known |= motionHooks[h].target == reinterpret_cast<uint64_t>(fn) && motionHooks[h].method == method;
            }
            if (!known) {
                spdlog::info("[playerprobe] replay: ctrl {} method {:#x} is not a known motion method, skipped", ctrl, method);
                return;
            }
            replaying = true;
            fn(ctrl, index, m.layer, m.state, m.blend, m.flags);
            replaying = false;
        }

        struct PendingBody {
            uint64_t tick;
            CarryMotionUpdate m;
        };
        std::vector<PendingBody> pendingBody;

        void ApplyCarryMotion(const int remote, const CarryMotionUpdate &m);

        // replay queued soldier requests once the soldier is captured (in order), drop them after 1.5 s
        void FlushPendingBody(const int remote) {
            if (pendingBody.empty()) {
                return;
            }
            const auto now = GetTickCount64();
            std::vector<PendingBody> keep;
            std::vector<CarryMotionUpdate> ready;
            for (const auto &p : pendingBody) {
                uint32_t index;
                if (SoldierWarp::LocalIndex(p.m.objectID, index)) {
                    ready.push_back(p.m);
                } else if (now - p.tick < 1500) {
                    keep.push_back(p);
                } else {
                    spdlog::info("[playerprobe] replay: soldier {} never captured, state {:012x} dropped", p.m.objectID, p.m.state);
                }
            }
            pendingBody.swap(keep);
            for (const auto &m : ready) {
                ApplyCarryMotion(remote, m);
            }
        }

        void ApplyCarryMotion(const int remote, const CarryMotionUpdate &m) {
            if (!m.body) {
                const auto ctrl = motionCtrl[remote];
                spdlog::info("[playerprobe] replay: partner {} vf{:#x} layer {} state {:012x} blend {} flags {:#x}{}", remote, m.method, m.layer, m.state, m.blend, m.flags,
                    ctrl ? "" : " (no ctrl)");
                if (ctrl) {
                    Replay(ctrl, static_cast<uint32_t>(remote), m);
                }
                return;
            }
            if (m.objectID == localCarryTarget.load()) {
                return; // we carry it here, our own game animates it
            }
            uint32_t index = 0;
            if (!SoldierWarp::LocalIndex(m.objectID, index)) {
                // soldier not captured here yet (usually the first request of a pickup): keep it, replay once captured
                SoldierWarp::Capture(m.objectID);
                if (pendingBody.size() < 32) {
                    pendingBody.push_back({GetTickCount64(), m});
                }
                spdlog::info("[playerprobe] replay: soldier {} not captured yet, state {:012x} queued", m.objectID, m.state);
                return;
            }
            const auto ctrl = reinterpret_cast<void *>(SoldierWarp::Controller(m.objectID));
            spdlog::info("[playerprobe] replay: soldier {} (index {}, ctrl {}) vf{:#x} layer {} state {:012x} blend {} flags {:#x}", m.objectID, index, ctrl, m.method, m.layer, m.state,
                m.blend, m.flags);
            if (ctrl) {
                Replay(ctrl, index, m);
                BodyFollow::SetAttached(true);
            }
        }

        // --- v18: carried soldier transform relative to the carrier ---
        void QuatMul(const float a[4], const float b[4], float out[4]) {
            const float x = a[3] * b[0] + a[0] * b[3] + a[1] * b[2] - a[2] * b[1];
            const float y = a[3] * b[1] - a[0] * b[2] + a[1] * b[3] + a[2] * b[0];
            const float z = a[3] * b[2] + a[0] * b[1] - a[1] * b[0] + a[2] * b[3];
            const float w = a[3] * b[3] - a[0] * b[0] - a[1] * b[1] - a[2] * b[2];
            out[0] = x; out[1] = y; out[2] = z; out[3] = w;
        }

        void QuatRotate(const float q[4], const float v[3], float out[3]) {
            const float p[4] = {v[0], v[1], v[2], 0.0f};
            const float c[4] = {-q[0], -q[1], -q[2], q[3]};
            float t[4], r[4];
            QuatMul(q, p, t);
            QuatMul(t, c, r);
            out[0] = r[0]; out[1] = r[1]; out[2] = r[2];
        }

        bool RecordTransform(const int player, float pos[3], float rot[4]) {
            const auto buffer = *reinterpret_cast<int32_t *>(Exe(infoBufferIndex));
            if (buffer != 0 && buffer != 1) {
                return false;
            }
            const auto rec = Record(buffer, player);
            memcpy(pos, rec + 0x10, 3 * sizeof(float));
            memcpy(rot, rec + 0x70, 4 * sizeof(float));
            return rot[3] != 0.0f || rot[1] != 0.0f;
        }

        void SendCarryOffset(const int local, const double now) {
            static double next = 0;
            static uint32_t logged = 0xffff;
            const auto target = localCarryTarget.load() != 0xffff ? localCarryTarget.load() : (GetTickCount64() < forwardUntil.load() ? carriedID.load() : 0xffff);
            if (target == 0xffff || now < next) {
                return;
            }
            next = now + 0.1;
            float sp[3], sr[4], cp[3], cr[4];
            if (!SoldierWarp::GetTransform(target, sp, sr)) {
                SoldierWarp::Capture(target);
                return;
            }
            if (!RecordTransform(local, cp, cr)) {
                return;
            }
            const float d[3] = {sp[0] - cp[0], sp[1] - cp[1], sp[2] - cp[2]};
            const float inv[4] = {-cr[0], -cr[1], -cr[2], cr[3]};
            float off[3], rel[4];
            QuatRotate(inv, d, off);
            QuatMul(inv, sr, rel);
            static double nextTrace = 0;
            if (now >= nextTrace) {
                // v22: offset trace while carrying, to see whether the soldier's root follows the carrier
                nextTrace = now + 0.25;
                spdlog::info("[playerprobe] offset trace {}: off {:.2f} {:.2f} {:.2f} rel {:.2f} {:.2f} {:.2f} {:.2f} soldier {:.2f} {:.2f} {:.2f} carrier {:.2f} {:.2f} {:.2f}",
                    target, off[0], off[1], off[2], rel[0], rel[1], rel[2], rel[3], sp[0], sp[1], sp[2], cp[0], cp[1], cp[2]);
            }
            if (logged != target) {
                logged = target;
                spdlog::info("[playerprobe] carry offset {}: soldier pos {} {} {} rot {} {} {} {} | carrier pos {} {} {} rot {} {} {} {} | offset {} {} {} rel {} {} {} {}",
                    target, sp[0], sp[1], sp[2], sr[0], sr[1], sr[2], sr[3], cp[0], cp[1], cp[2], cr[0], cr[1], cr[2], cr[3], off[0], off[1], off[2], rel[0], rel[1], rel[2], rel[3]);
            }
            g_hook->dynamiteSyncImpl.SendCarryOffset(target, off, rel);
        }

        // --- v20: which other controller methods animate the carried soldier during a pickup ---
        // Lightweight hooks on controller methods next to vf170; they only record (no calls before forwarding, so
        // float arguments in xmm registers and return values pass through untouched).
        constexpr int slotList[] = {0x160, 0x168, 0x178, 0x180, 0x188, 0x190, 0x198, 0x1a0, 0x1a8};
        constexpr int slotCount = static_cast<int>(std::size(slotList));
        using AnyFunc = uint64_t(__fastcall *)(void *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
        AnyFunc slotOriginal[slotCount]{};
        uint64_t slotTarget[slotCount]{};
        struct SlotCall {
            uint64_t tick, ctrl, rdx, r8, r9, a5, a6, ret;
            uint32_t xmm1, xmm2, xmm3;
            int slot;
        };
        constexpr int maxSlotCalls = 256;
        SlotCall slotCalls[maxSlotCalls];
        std::atomic<int> slotCallCount{0};
        std::atomic<uint64_t> watchCtrl{0};

        template <int N>
        uint64_t __fastcall hkSlot(void *ctrl, uint64_t rdx, uint64_t r8, uint64_t r9, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8) {
            uint32_t x1, x2, x3;
            asm volatile("movd %%xmm1, %0\n\tmovd %%xmm2, %1\n\tmovd %%xmm3, %2" : "=r"(x1), "=r"(x2), "=r"(x3));
            if (reinterpret_cast<uint64_t>(ctrl) == watchCtrl.load(std::memory_order_relaxed)) {
                const auto i = slotCallCount.fetch_add(1, std::memory_order_relaxed);
                if (i < maxSlotCalls) {
                    slotCalls[i] = {__rdtsc(), reinterpret_cast<uint64_t>(ctrl), rdx, r8, r9, a5, a6, // no calls here: xmm args must survive
                        reinterpret_cast<uint64_t>(__builtin_return_address(0)), x1, x2, x3, slotList[N]};
                }
            }
            return slotOriginal[N](ctrl, rdx, r8, r9, a5, a6, a7, a8);
        }

        template <int... I>
        constexpr std::array<void *, sizeof...(I)> SlotHooks(std::integer_sequence<int, I...>) {
            return {reinterpret_cast<void *>(&hkSlot<I>)...};
        }
        const auto slotHooks = SlotHooks(std::make_integer_sequence<int, slotCount>{});

        void InstallSlotHooks(void *ctrl) {
            static bool done = false;
            if (done || ctrl == nullptr) {
                return;
            }
            done = true;
            const auto vt = *(uint64_t **)ctrl;
            for (int i = 0; i < slotCount; i++) {
                const auto fn = vt[slotList[i] / 8];
                bool dup = false;
                for (int j = 0; j < i; j++) {
                    dup |= slotTarget[j] == fn;
                }
                if (dup || !InExe(fn)) {
                    continue;
                }
                if (MH_CreateHook(reinterpret_cast<void *>(fn), slotHooks[i], reinterpret_cast<void **>(&slotOriginal[i])) == MH_OK &&
                    MH_EnableHook(reinterpret_cast<void *>(fn)) == MH_OK) {
                    slotTarget[i] = fn;
                    spdlog::info("[playerprobe] controller method {:#x} ({:#x}) hooked", slotList[i], ToExe(fn));
                } else {
                    spdlog::info("[playerprobe] cannot hook controller method {:#x} ({:#x})", slotList[i], ToExe(fn));
                }
            }
        }

        void DumpSlotCalls() {
            const auto n = std::min(slotCallCount.load(), maxSlotCalls);
            for (int i = 0; i < n; i++) {
                const auto &c = slotCalls[i];
                float f1, f2, f3;
                memcpy(&f1, &c.xmm1, 4);
                memcpy(&f2, &c.xmm2, 4);
                memcpy(&f3, &c.xmm3, 4);
                spdlog::info("[playerprobe] soldier ctrl call vf{:#x} tsc {} rdx {:#x} r8 {:#x} r9 {:#x} a5 {:#x} a6 {:#x} xmm1-3 {} {} {} from {:#x}",
                    c.slot, c.tick, c.rdx, c.r8, c.r9, c.a5, c.a6, f1, f2, f3, ToExe(c.ret));
            }
            slotCallCount = 0;
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
        // carrier side: remember what we carry, send queued carry animation requests
        if (auto st = StateArrays()) {
            const int local = g_hook->cfg.Host ? 0 : 1;
            const uint32_t target = (*(uint8_t **)(st + 0x28))[local] ? (*(uint16_t **)(st + 0xd8))[local] : 0xffff;
            if (target == 0xffff && localCarryTarget.load() != 0xffff) {
                forwardUntil = GetTickCount64() + 4000;
            }
            {
                // dump the soldier's other controller calls once the put-down is over
                static bool dumpPending = false;
                if (target != 0xffff) {
                    dumpPending = true;
                } else if (dumpPending && GetTickCount64() > forwardUntil.load()) {
                    dumpPending = false;
                    DumpSlotCalls();
                }
            }
            if (target == 0xffff && carriedID.load() != 0xffff && BodyFollow::FollowedID() == carriedID.load()) {
                forwardUntil = 0; // partner picked up the soldier we just put down
            }
            if (target != 0xffff && target != localCarryTarget.load()) {
                forwardUntil = 0;
                carryStartTick = GetTickCount64();
                carriedCtrl = 0;
                carriedIndex = 0xffffffff;
            }
            localCarryTarget = target;
            // identify the soldier's motion ctrl as soon as its local index is known, send what it played since the pickup began
            uint32_t index = 0;
            if (target != 0xffff && carriedCtrl.load() == 0) {
                // the soldier controller found by SoldierWarp is also the soldier's motion controller
                if (SoldierWarp::LocalIndex(target, index) && SoldierWarp::Controller(target) != 0) {
                    std::lock_guard lock(outMutex);
                    carriedID = target;
                    carriedIndex = index;
                    carriedCtrl = SoldierWarp::Controller(target);
                    int sent = 0;
                    for (const auto &r : recent) {
                        if (r.ctrl == carriedCtrl.load() && r.index == index && r.tick + 300 >= carryStartTick) {
                            auto m = r.m;
                            m.objectID = target;
                            outgoing.push_back(m);
                            sent++;
                        }
                    }
                    recent.clear();
                    spdlog::info("[playerprobe] carrying soldier {} (index {}, ctrl {:#x}), {} earlier requests sent", target, index, carriedCtrl.load(), sent);
                } else {
                    SoldierWarp::Capture(target);
                }
            }
            SendCarryOffset(local, now);
        }
        {
            std::vector<CarryMotionUpdate> send;
            {
                std::lock_guard lock(outMutex);
                send.swap(outgoing);
            }
            for (const auto &m : send) {
                g_hook->dynamiteSyncImpl.SendCarryMotion(m);
            }
        }
        // watcher side: replay partner's carry animation requests
        // capture downed soldiers near either player ahead of time, so a pickup's first animation is not delayed
        {
            static double nextPre = 0;
            if (now >= nextPre) {
                nextPre = now + 0.5;
                const Vector3 players[2] = {DynamiteCore::GetPlayerPosition(0), DynamiteCore::GetPlayerPosition(1)};
                for (uint32_t id = 1024; id < 1024 + 512; id++) {
                    if (FindGameObjectWithID(id) == nullptr) {
                        continue;
                    }
                    const auto life = DynamiteCore::GetSoldierLifeStatus(id);
                    if (life != ENPCLifeState::SLEEP && life != ENPCLifeState::FAINT && life != ENPCLifeState::DYING && life != ENPCLifeState::DEAD) {
                        continue;
                    }
                    uint32_t index;
                    if (SoldierWarp::LocalIndex(id, index)) {
                        continue;
                    }
                    const auto pos = DynamiteCore::GetSoldierPosition(id);
                    bool isNear = false;
                    for (const auto &pl : players) {
                        const auto dx = pos.x - pl.x, dz = pos.z - pl.z;
                        isNear |= dx * dx + dz * dz < 6.0f * 6.0f;
                    }
                    if (isNear) {
                        SoldierWarp::Capture(id); // one capture at a time, the next one on a later tick
                        break;
                    }
                }
            }
        }
        FlushPendingBody(remote);
        while (const auto m = g_hook->dynamiteSyncImpl.PopCarryMotion()) {
            // keep order: while earlier requests for this soldier wait for the capture, queue later ones behind them
            bool queued = false;
            for (const auto &p : pendingBody) {
                queued |= m->body && p.m.objectID == m->objectID;
            }
            if (queued) {
                pendingBody.push_back({GetTickCount64(), *m});
            } else {
                ApplyCarryMotion(remote, *m);
            }
        }

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

    bool PartnerRotation(float out[4]) {
        if (!CheckVersion()) {
            return false;
        }
        const auto buffer = *reinterpret_cast<int32_t *>(Exe(infoBufferIndex));
        if (buffer != 0 && buffer != 1) {
            return false;
        }
        const auto rec = Record(buffer, g_hook->cfg.Host ? 1 : 0);
        memcpy(out, rec + 0x70, 16); // rotation quaternion x y z w
        return out[3] != 0.0f || out[1] != 0.0f;
    }

    bool CarriedPlacement(const uint32_t objectID, float pos[3], float rot[4]) {
        if (!CheckVersion()) {
            return false;
        }
        float off[3], rel[4], cp[3], cr[4];
        if (!g_hook->dynamiteSyncImpl.GetCarryOffset(objectID, off, rel, 1.0)) {
            return false;
        }
        if (!RecordTransform(g_hook->cfg.Host ? 1 : 0, cp, cr)) {
            return false;
        }
        float w[3];
        QuatRotate(cr, off, w);
        pos[0] = cp[0] + w[0];
        pos[1] = cp[1] + w[1];
        pos[2] = cp[2] + w[2];
        QuatMul(cr, rel, rot);
        return true;
    }

    uint32_t LocalCarryTarget() { return localCarryTarget.load(); }
}
