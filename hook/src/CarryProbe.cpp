#include "CarryProbe.h"

#include "DynamiteCore.h"
#include "DynamiteHook.h"
#include "dynamite.h"
#include "mgsvtpp_func_typedefs.h"
#include "spdlog/spdlog.h"
#include "windows.h"
#include "MinHook.h"

#include <atomic>
#include <initializer_list>
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

        // soldier index -> pending action request block, learned from the action install write
        // (1.0.15.4: 0x141372a50 copies a request into the soldier's action slot, rbx = request block)
        constexpr uint64_t installWriteA = 0x141372b0c;
        constexpr uint64_t installWriteB = 0x141372b5b;
        std::atomic<uint64_t> requestBlock[512];
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
            const auto exeRip = ToExe(rip);
            const auto soldier = armedSoldier.load();
            if ((exeRip == installWriteA || exeRip == installWriteB) && soldier >= 1024 && soldier < 1024 + 512) {
                requestBlock[soldier - 1024] = ctx->Rbx; // rbx = request block (copy of r8) in 0x141372a50
            }

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

            // second pickup of the same soldier: watch his pending request block instead of state flags
            const auto req = requestBlock[idx].load();
            if (req != 0 && Readable(reinterpret_cast<void *>(req), 0x1a8)) {
                out[1] = req + 0x198; // flags at +0x19e, counter at +0x1a0 is +0x1a0
                out[2] = req;         // start of request
                spdlog::info("[carryprobe] soldier {} request block {:#x} known, watching it", objectID, req);
            }
            return true;
        }

        // --- soldier message log ---
        // 1.0.15.4: 0x141360f90 soldier message handler (this, int *result, uint32 soldierIndex, msg*), *(u64*)msg = 48-bit hash.
        // Pickup request reaches the soldier through it (0x141364d8e forwards to action requester 0x1415541c0).
        constexpr uint64_t soldierMessageHandler = 0x141360f90;
        constexpr int maxMessages = 48;
        struct Message {
            uint64_t hash;
            uint64_t ret;
            uint32_t count;
            uint32_t firstMs;
            uint64_t body[12];
        };
        Message messages[maxMessages];
        std::atomic<int> messageCount{0};
        std::atomic_flag messageLock = ATOMIC_FLAG_INIT;
        std::atomic<uint32_t> armTick{0};

        using MessageHandlerFunc = void *(__fastcall *)(void *self, int *result, uint32_t index, uint64_t *msg);
        MessageHandlerFunc oMessageHandler = nullptr;

        void *__fastcall hkMessageHandler(void *self, int *result, uint32_t index, uint64_t *msg) {
            const auto soldier = armedSoldier.load();
            if (soldier >= 1024 && index == static_cast<uint32_t>(soldier - 1024) && msg != nullptr) {
                const auto ret = ToExe(reinterpret_cast<uint64_t>(__builtin_return_address(0)));
                const auto hash = msg[0] & 0xffffffffffffull;
                while (messageLock.test_and_set(std::memory_order_acquire)) {
                }
                const auto n = std::min(messageCount.load(), maxMessages);
                int i = 0;
                for (; i < n; i++) {
                    if (messages[i].hash == hash && messages[i].ret == ret) {
                        messages[i].count++;
                        break;
                    }
                }
                if (i == n && n < maxMessages) {
                    auto &m = messages[n];
                    m.hash = hash;
                    m.ret = ret;
                    m.count = 1;
                    m.firstMs = GetTickCount() - armTick.load();
                    if (Readable(msg, sizeof(m.body))) {
                        memcpy(m.body, msg, sizeof(m.body));
                    } else {
                        memset(m.body, 0, sizeof(m.body));
                    }
                    messageCount = n + 1;
                }
                messageLock.clear(std::memory_order_release);
            }
            return oMessageHandler(self, result, index, msg);
        }

        void InstallMessageHook() {
            static bool done = false;
            if (done) {
                return;
            }
            done = true;
            const auto target = reinterpret_cast<uint8_t *>(soldierMessageHandler - 0x140000000 + exeBase);
            // mov rax, rsp; push rbp; push rbx; push rsi; push rdi; push r12
            const uint8_t expected[] = {0x48, 0x8b, 0xc4, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54};
            if (memcmp(target, expected, sizeof(expected)) != 0) {
                spdlog::info("[carryprobe] soldier message handler not found (game version?), message log disabled");
                return;
            }
            if (MH_CreateHook(target, reinterpret_cast<void *>(&hkMessageHandler), reinterpret_cast<void **>(&oMessageHandler)) != MH_OK ||
                MH_EnableHook(target) != MH_OK) {
                spdlog::info("[carryprobe] cannot hook soldier message handler");
                return;
            }
            spdlog::info("[carryprobe] soldier message handler hooked");
        }

        void DumpMessages(const std::string &tag) {
            while (messageLock.test_and_set(std::memory_order_acquire)) {
            }
            Message copy[maxMessages];
            const auto n = std::min(messageCount.load(), maxMessages);
            memcpy(copy, messages, sizeof(Message) * n);
            messageCount = 0;
            messageLock.clear(std::memory_order_release);

            for (int i = 0; i < n; i++) {
                const auto &m = copy[i];
                std::string body;
                for (int j = 1; j < 12; j++) {
                    body += fmt::format(" {:016x}", m.body[j]);
                }
                spdlog::info("[carryprobe] {} msg {:012x} from {:#x} count {} at +{} ms:{}", tag, m.hash, m.ret, m.count, m.firstMs, body);
            }
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

        static uint64_t armedWithRequest = 0;
        if (best == noSoldier) {
            return;
        }
        const auto knownReq = requestBlock[best - 1024].load();
        if (best == armedSoldier.load() && knownReq == armedWithRequest) {
            return;
        }
        armedWithRequest = knownReq;

        uint64_t rec[3];
        if (!StateRecords(best, rec)) {
            return;
        }

        if (vehHandle == nullptr) {
            vehHandle = AddVectoredExceptionHandler(1, Handler);
        }

        InstallMessageHook();
        InstallCarryHooks();
        traceCount = 0;
        if (best != armedSoldier.load()) {
            messageCount = 0;
        }
        armTick = GetTickCount();
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
        if (soldier >= 1024 && soldier < 1024 + 512) {
            spdlog::info("[carryprobe] {} soldier {} request block {:#x}", tag, soldier, requestBlock[soldier - 1024].load());
        }
        traceCount = 0;
        DumpMessages(tag);
    }

    // --- carry attach experiment (1.0.15.4 only) ---
    // Player carry component 0x14113bba0 (this, playerIndex, event): event 0 sends command 0x072bc35bcdbd to the
    // target soldier through the game object manager (0x140bff050()->+0x60, vf 0x38 (this, int *result, id, cmd)):
    //   +0x00 u64 hash, +0x08 u16 carrier player index, +0x0c u32 phase (0, then 2),
    //   +0x10 carrier's per-player carry block (this+0x68, 0x6c0 bytes per player), +0x18 u16 0xffff, rest zero.
    // Soldier side (0x1415541c0) pushes an action request whose first word is the carrier player index.
    namespace {
        constexpr uint64_t playerCarryEvent = 0x14113bba0;
        constexpr uint64_t gameObjectSystemGetter = 0x140bff050;
        constexpr uint64_t carryCommandHash = 0x072bc35bcdbdull;

        std::atomic<uint64_t> carryComponent{0};
        std::atomic<int> carryEventLogs{0};

        using CarryEventFunc = uint64_t(__fastcall *)(void *self, uint32_t playerIndex, uint32_t event);
        CarryEventFunc oCarryEvent = nullptr;

        uint64_t __fastcall hkCarryEvent(void *self, const uint32_t playerIndex, const uint32_t event) {
            carryComponent = reinterpret_cast<uint64_t>(self);
            if (carryEventLogs.fetch_add(1) < 400) {
                spdlog::info("[carryprobe] carry event player {} event {} component {}", playerIndex, event, self);
            }
            return oCarryEvent(self, playerIndex, event);
        }

        uint8_t *Exe(const uint64_t a) { return reinterpret_cast<uint8_t *>(a - 0x140000000 + exeBase); }

        bool CheckBytes(const uint64_t a, std::initializer_list<uint8_t> bytes) {
            auto p = Exe(a);
            for (const auto b : bytes) {
                if (*p++ != b) {
                    return false;
                }
            }
            return true;
        }
    }

    void InstallCarryHooks() {
        static bool done = false;
        if (done) {
            return;
        }
        done = true;
        if (!CheckBytes(playerCarryEvent, {0x48, 0x89, 0x5c, 0x24, 0x18, 0x55, 0x56, 0x57}) ||
            !CheckBytes(gameObjectSystemGetter, {0x48, 0x83, 0xec, 0x28, 0xe8})) {
            spdlog::info("[carryprobe] carry functions not found (game version?), carry attach disabled");
            return;
        }
        const auto target = Exe(playerCarryEvent);
        if (MH_CreateHook(target, reinterpret_cast<void *>(&hkCarryEvent), reinterpret_cast<void **>(&oCarryEvent)) != MH_OK ||
            MH_EnableHook(target) != MH_OK) {
            spdlog::info("[carryprobe] cannot hook carry event");
            return;
        }
        spdlog::info("[carryprobe] carry event hooked");
    }

    int Attach(const uint32_t soldierID, const int playerIndexArg) {
        InstallCarryHooks();
        const auto comp = reinterpret_cast<char *>(carryComponent.load());
        if (comp == nullptr) {
            spdlog::info("[carryprobe] attach {}: carry component unknown yet (pick up any body once yourself first)", soldierID);
            return 0;
        }
        const uint32_t playerIndex = playerIndexArg >= 0 ? playerIndexArg : (g_hook->cfg.Host ? 1 : 0);

        const auto info = *(char **)(comp + 0x38);
        const auto blocks = *(char **)(comp + 0x68);
        if (!Readable(info, 0x28) || blocks == nullptr) {
            spdlog::info("[carryprobe] attach {}: bad carry component", soldierID);
            return -1;
        }
        const auto base = *(uint32_t *)(info + 0x24);
        if (playerIndex < base || playerIndex - base > 7) {
            spdlog::info("[carryprobe] attach {}: player {} outside carry blocks (base {})", soldierID, playerIndex, base);
            return -1;
        }
        const auto block = blocks + (playerIndex - base) * 0x6c0;
        if (!Readable(block, 0x6c0)) {
            spdlog::info("[carryprobe] attach {}: carry block not readable", soldierID);
            return -1;
        }
        spdlog::info("[carryprobe] attach {}: player {} block {} target {:#x} idx {} flag85 {} state384 {}",
            soldierID, playerIndex, (void *)block, *(uint16_t *)(block + 0x78), *(uint8_t *)(block + 0x80), *(uint8_t *)(block + 0x85), *(uint8_t *)(block + 0x384));

        using GetterFunc = char *(__fastcall *)();
        using SendFunc = int *(__fastcall *)(void *mgr, int *result, uint32_t id, void *cmd);
        const auto sys = reinterpret_cast<GetterFunc>(Exe(gameObjectSystemGetter))();
        const auto mgr = sys ? *(void **)(sys + 0x60) : nullptr;
        if (mgr == nullptr) {
            spdlog::info("[carryprobe] attach {}: no game object manager", soldierID);
            return -1;
        }
        const auto send = reinterpret_cast<SendFunc>((*(void ***)mgr)[0x38 / 8]);

        // carrier block fields the game sets before sending
        *(uint16_t *)(block + 0x78) = static_cast<uint16_t>(soldierID);
        *(uint8_t *)(block + 0x80) = static_cast<uint8_t>(playerIndex);
        *(uint8_t *)(block + 0x85) = 0; // remote player

        alignas(16) uint8_t cmd[0x60] = {};
        *(uint64_t *)(cmd + 0x00) = carryCommandHash;
        *(uint16_t *)(cmd + 0x08) = static_cast<uint16_t>(playerIndex & 0x1ff);
        *(uint32_t *)(cmd + 0x0c) = 0;
        *(void **)(cmd + 0x10) = block;
        *(uint16_t *)(cmd + 0x18) = 0xffff;

        int result = -1;
        send(mgr, &result, soldierID, cmd);
        spdlog::info("[carryprobe] attach {}: phase 0 result {:#x} out29 {} out28 {:#x}", soldierID, (uint32_t)result, cmd[0x29], *(uint16_t *)(cmd + 0x28));
        if (result < 0) {
            return -1;
        }
        *(uint32_t *)(cmd + 0x0c) = 2;
        result = -1;
        send(mgr, &result, soldierID, cmd);
        spdlog::info("[carryprobe] attach {}: phase 2 result {:#x}", soldierID, (uint32_t)result);
        return 1;
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
