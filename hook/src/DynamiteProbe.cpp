#include "DynamiteProbe.h"

#include "DynamiteCore.h"
#include "dynamite.h"
#include "mgsvtpp_func_typedefs.h"
#include "spdlog/spdlog.h"
#include "windows.h"

#include <atomic>
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
        std::atomic<bool> watching{false};
        std::atomic<uint64_t> watchedAddress{0};
        PVOID vehHandle = nullptr;

        uint64_t ToExeAddress(const uint64_t address) {
            const auto base = reinterpret_cast<uint64_t>(GetModuleHandle(nullptr));
            return address - base + 0x140000000;
        }

        LONG WINAPI Handler(EXCEPTION_POINTERS *info) {
            if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            auto *ctx = info->ContextRecord;
            if ((ctx->Dr6 & 1) == 0) {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            ctx->Dr6 = 0;

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
}
