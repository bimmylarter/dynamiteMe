#include "dynamite.h"
#include "Overlay.h"
#include "windows.h"
#include <eh.h>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>

#include "Config.h"
#include "Messagebox.h"
#include "MinHook.h"
#include "Tpp/TppGameObject.h"
#include "Tpp/TppNPCLifeState.h"
#include "memtag.h"
#include "mgsvtpp_addresses_1_0_15_3_en.h"
#include "mgsvtpp_addresses_1_0_15_4_en.h"
#include "mgsvtpp_func_typedefs.h"
#include "patch.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/spdlog.h"
#include "util.h"

#include "DynamiteHook.h"
#include "DynamiteLua.h"

namespace Dynamite {
    GameVersion DetectGameVersion(HMODULE exe) {
        const auto base = reinterpret_cast<const uint8_t *>(exe);
        const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return GameVersion::Unknown;
        }

        const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            return GameVersion::Unknown;
        }

        switch (nt->FileHeader.TimeDateStamp) {
        case 1613108497:
            return GameVersion::V1_0_15_3;
        case 1783412888:
            return GameVersion::V1_0_15_4;
        default:
            spdlog::error("unknown game exe, PE timestamp {}", nt->FileHeader.TimeDateStamp);
            return GameVersion::Unknown;
        }
    }

    const char *GameVersionName(const GameVersion v) {
        switch (v) {
        case GameVersion::V1_0_15_3:
            return "1.0.15.3";
        case GameVersion::V1_0_15_4:
            return "1.0.15.4";
        default:
            return "unknown";
        }
    }

    void Dynamite::AbortHandler(int signal_number) {
        auto l = spdlog::get(logName);
        if (l != nullptr) {
            l->error("abort was called");
            l->flush();
        }
    }

    void TerminateHandler() {
        const auto l = spdlog::get(logName);
        if (l != nullptr) {
            l->error("terminate was called");
            l->flush();
        }

        terminate_Original();
    }

    LONG WINAPI Dynamite::UnhandledExceptionHandler(EXCEPTION_POINTERS * /*ExceptionInfo*/) {
        const auto log = spdlog::get(logName);
        if (log != nullptr) {
            log->error("Unhandled exception");
            log->flush();
        }

        // return g_showCrashDialog ? EXCEPTION_CONTINUE_SEARCH : EXCEPTION_EXECUTE_HANDLER;
        return EXCEPTION_CONTINUE_SEARCH;
    }

    void Dynamite::ReadConfig() {
        ConfigValidateResult r{};
        if (!cfg.Read(&r)) {
            spdlog::error(r.Message);
            ShowMessageBox(r.Message.c_str(), "Config error", MB_ICONERROR);
            exit(1);
        }

        cfg.Log();
    }

    void Dynamite::RebaseAddresses() {
        for (const auto &[name, addr] : addressSet) {
            const uint64_t rebasedAddr = (addr - BaseAddr) + RealBaseAddr;
            addressSet[name] = rebasedAddr;
        }
    }

    void Dynamite::SetupLogger() {
        log = spdlog::basic_logger_st(logName, logPath.string(), true);
        spdlog::set_default_logger(log);
        // using `flush_every` with multithreaded logger will result in application hang during DLL_PROCESS_DETACH
        spdlog::flush_on(spdlog::level::info);
        log->info("starting");
        log->info("dynamite {}", SOFTWARE_VERSION);
    }

    Dynamite::Dynamite() : thisModule{GetModuleHandle(nullptr)} {
        signal(SIGABRT, &AbortHandler);
        terminate_Original = std::set_terminate(TerminateHandler);
        _set_abort_behavior(1, _WRITE_ABORT_MSG);
        SetUnhandledExceptionFilter(UnhandledExceptionHandler);

        SetupLogger();

        // mgo bad
        HMODULE hExe = GetModuleHandle(nullptr);
        WCHAR fullPath[MAX_PATH]{0};
        GetModuleFileNameW(hExe, fullPath, MAX_PATH);
        std::filesystem::path path(fullPath);
        std::wstring exeName = path.filename().c_str();
        if (exeName.find(L"mgo") != std::wstring::npos) {
            return;
        }

        gameVersion = DetectGameVersion(hExe);
        log->info("game version {}", GameVersionName(gameVersion));
        switch (gameVersion) {
        case GameVersion::V1_0_15_3:
            addressSet = mgsvtpp_adresses_1_0_15_3_en;
            break;
        case GameVersion::V1_0_15_4:
            addressSet = mgsvtpp_adresses_1_0_15_4_en;
            break;
        default:
            ShowMessageBox("Unsupported game version, dynamite is disabled.\n"
                           "Supported versions: 1.0.15.3, 1.0.15.4 (Steam, regular version).",
                "Dynamite error",
                MB_ICONERROR);
            return;
        }

        MH_Initialize();
        RealBaseAddr = (size_t)GetModuleHandle(nullptr);

        RebaseAddresses();
        SetFuncPtrs();
        ReadConfig();
        CreateHooks();
        dynamiteCore.WithConfig(&cfg);
        Overlay::Start();
    }

    Dynamite::~Dynamite() {
        MH_Uninitialize();
    }


}