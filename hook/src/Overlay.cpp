#include "Overlay.h"

#include "Version.h"
#include "DynamiteHook.h"
#include "dynamite.h"

#include "MinHook.h"
#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
#include "spdlog/spdlog.h"

#include <d3d11.h>
#include <dxgi.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace Dynamite::Overlay {
    namespace {
        // IDXGISwapChain vtable
        constexpr int presentIndex = 8;
        constexpr int resizeBuffersIndex = 13;
        // IDirectInput8 / IDirectInputDevice8 vtables
        constexpr int createDeviceIndex = 3;
        constexpr int getDeviceStateIndex = 9;
        constexpr int getDeviceDataIndex = 10;

        constexpr int toggleKey = VK_F3;

        using PresentFunc = HRESULT(__stdcall *)(IDXGISwapChain *swapChain, UINT syncInterval, UINT flags);
        using ResizeBuffersFunc = HRESULT(__stdcall *)(IDXGISwapChain *swapChain, UINT count, UINT width, UINT height, DXGI_FORMAT format, UINT flags);
        using CreateDeviceFunc = HRESULT(__stdcall *)(void *directInput, const GUID &guid, void **device, void *outer);
        using GetDeviceStateFunc = HRESULT(__stdcall *)(void *device, DWORD size, void *data);
        using GetDeviceDataFunc = HRESULT(__stdcall *)(void *device, DWORD objectSize, void *data, DWORD *count, DWORD flags);
        using SetCursorPosFunc = BOOL(WINAPI *)(int x, int y);
        using ClipCursorFunc = BOOL(WINAPI *)(const RECT *rect);

        PresentFunc presentOriginal = nullptr;
        ResizeBuffersFunc resizeBuffersOriginal = nullptr;
        CreateDeviceFunc createDeviceOriginal = nullptr;
        GetDeviceStateFunc getDeviceStateOriginal = nullptr;
        GetDeviceDataFunc getDeviceDataOriginal = nullptr;
        SetCursorPosFunc setCursorPosOriginal = nullptr;
        ClipCursorFunc clipCursorOriginal = nullptr;
        WNDPROC wndProcOriginal = nullptr;

        std::atomic<bool> open{false};
        // window messages and frames may arrive on different threads; recursive because the input handler re-enters
        // the window procedure (SetCapture on a click sends WM_CAPTURECHANGED to the same window right away)
        std::recursive_mutex imguiMutex;
        std::atomic<uint32_t> mouseMessages{0}, keyMessages{0};

        bool initialized = false;
        bool initFailed = false;
        HWND window = nullptr;
        IDXGISwapChain *currentSwapChain = nullptr;
        ID3D11Device *device = nullptr;
        ID3D11DeviceContext *context = nullptr;
        ID3D11RenderTargetView *renderTarget = nullptr;

        bool keyWasDown = false;
        bool showDemo = false;

        void ReleaseRenderTarget() {
            if (renderTarget != nullptr) {
                renderTarget->Release();
                renderTarget = nullptr;
            }
        }

        bool IsInputMessage(const UINT msg) {
            return (msg >= WM_MOUSEFIRST && msg <= WM_MOUSELAST) || (msg >= WM_KEYFIRST && msg <= WM_KEYLAST) || msg == WM_INPUT;
        }

        LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
            if (open.load() && initialized) {
                if (msg >= WM_MOUSEFIRST && msg <= WM_MOUSELAST) {
                    mouseMessages++;
                } else if (msg >= WM_KEYFIRST && msg <= WM_KEYLAST) {
                    keyMessages++;
                }
                {
                    std::lock_guard lock(imguiMutex);
                    ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam);
                }
                if (msg == WM_INPUT) {
                    return DefWindowProcW(hWnd, msg, wParam, lParam); // raw input must still be cleaned up
                }
                if (IsInputMessage(msg)) {
                    return 0; // the game does not see input while the overlay is open
                }
            }
            return CallWindowProcW(wndProcOriginal, hWnd, msg, wParam, lParam);
        }

        bool Init(IDXGISwapChain *swapChain) {
            if (FAILED(swapChain->GetDevice(__uuidof(ID3D11Device), reinterpret_cast<void **>(&device)))) {
                spdlog::error("[overlay] swap chain has no D3D11 device, overlay disabled");
                return false;
            }
            device->GetImmediateContext(&context);

            DXGI_SWAP_CHAIN_DESC desc{};
            swapChain->GetDesc(&desc);
            window = desc.OutputWindow;

            IMGUI_CHECKVERSION();
            ImGui::CreateContext();
            auto &io = ImGui::GetIO();
            io.IniFilename = nullptr; // do not write imgui.ini into the game folder
            io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

            // scale with the game's resolution, base font is made for ~720p
            RECT rc{};
            GetClientRect(window, &rc);
            float scale = static_cast<float>(rc.bottom - rc.top) / 720.0f;
            scale = scale < 1.0f ? 1.0f : (scale > 3.0f ? 3.0f : scale);
            ImFontConfig font{};
            font.SizePixels = 13.0f * scale;
            io.Fonts->AddFontDefault(&font);
            ImGui::StyleColorsDark();
            ImGui::GetStyle().ScaleAllSizes(scale);
            ImGui::GetStyle().WindowRounding = 4.0f * scale;

            ImGui_ImplWin32_Init(window);
            ImGui_ImplDX11_Init(device, context);

            wndProcOriginal = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(window, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&WndProc)));
            currentSwapChain = swapChain;
            spdlog::info("[overlay] ready, window {} {}x{}, scale {:.2f}, render thread {}, window thread {}, press F3", (void *)window, rc.right - rc.left, rc.bottom - rc.top,
                scale, GetCurrentThreadId(), GetWindowThreadProcessId(window, nullptr));
            return true;
        }

        void Draw() {
            auto &io = ImGui::GetIO();
            ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.05f, io.DisplaySize.y * 0.1f), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x * 0.28f, 0), ImGuiCond_FirstUseEver);
            if (ImGui::Begin("dynamite", nullptr, ImGuiWindowFlags_NoCollapse)) {
                ImGui::Text("dynamite %s", SOFTWARE_VERSION);
                ImGui::Text("Game %s", GameVersionName(gameVersion));
                ImGui::Separator();
                const auto &cfg = g_hook->cfg;
                ImGui::Text("Role: %s", cfg.Host ? "host" : "client");
                if (!cfg.Host) {
                    ImGui::Text("Host Steam ID: %llu", static_cast<unsigned long long>(cfg.HostSteamID));
                }
                const bool connected = g_hook->dynamiteCore.GetSessionConnected();
                ImGui::TextColored(connected ? ImVec4(0.4f, 0.9f, 0.4f, 1.0f) : ImVec4(0.9f, 0.6f, 0.3f, 1.0f), "Co-op session: %s",
                    connected ? "connected" : "not connected");
                ImGui::Separator();
                ImGui::Text("%.0f FPS", io.Framerate);
                ImGui::TextDisabled("input: %u mouse, %u key messages, cursor %.0f %.0f", mouseMessages.load(), keyMessages.load(), io.MousePos.x, io.MousePos.y);
                ImGui::Checkbox("Show ImGui demo window", &showDemo);
                ImGui::TextDisabled("F3 closes this menu");
            }
            ImGui::End();
            if (showDemo) {
                ImGui::ShowDemoWindow(&showDemo);
            }
        }

        void Toggle() {
            const bool nowOpen = !open.load();
            open = nowOpen;
            ImGui::GetIO().MouseDrawCursor = nowOpen; // the game hides the system cursor
            if (nowOpen && clipCursorOriginal != nullptr) {
                clipCursorOriginal(nullptr);
            }
            spdlog::info("[overlay] {}", nowOpen ? "opened" : "closed");
        }

        HRESULT __stdcall hkPresent(IDXGISwapChain *swapChain, UINT syncInterval, UINT flags) {
            if (!initialized && !initFailed) {
                initialized = Init(swapChain);
                initFailed = !initialized;
            }
            if (!initialized) {
                return presentOriginal(swapChain, syncInterval, flags);
            }
            if (swapChain != currentSwapChain) {
                ReleaseRenderTarget(); // a new swap chain (mode change), render into its buffers from now on
                currentSwapChain = swapChain;
            }

            const bool down = (GetAsyncKeyState(toggleKey) & 0x8000) != 0;
            if (down && !keyWasDown && GetForegroundWindow() == window) {
                std::lock_guard lock(imguiMutex);
                Toggle();
            }
            keyWasDown = down;

            if (!open.load()) {
                return presentOriginal(swapChain, syncInterval, flags);
            }

            {
                std::lock_guard lock(imguiMutex);
                if (renderTarget == nullptr) {
                    ID3D11Texture2D *backBuffer = nullptr;
                    if (SUCCEEDED(swapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), reinterpret_cast<void **>(&backBuffer)))) {
                        device->CreateRenderTargetView(backBuffer, nullptr, &renderTarget);
                        backBuffer->Release();
                    }
                }
                if (renderTarget != nullptr) {
                    ImGui_ImplDX11_NewFrame();
                    ImGui_ImplWin32_NewFrame();
                    ImGui::NewFrame();
                    Draw();
                    ImGui::Render();

                    // keep the game's render targets as they were
                    ID3D11RenderTargetView *savedTargets[D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT]{};
                    ID3D11DepthStencilView *savedDepth = nullptr;
                    context->OMGetRenderTargets(D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT, savedTargets, &savedDepth);
                    context->OMSetRenderTargets(1, &renderTarget, nullptr);
                    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
                    context->OMSetRenderTargets(D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT, savedTargets, savedDepth);
                    for (auto *t : savedTargets) {
                        if (t != nullptr) {
                            t->Release();
                        }
                    }
                    if (savedDepth != nullptr) {
                        savedDepth->Release();
                    }
                }
            }
            return presentOriginal(swapChain, syncInterval, flags);
        }

        HRESULT __stdcall hkResizeBuffers(IDXGISwapChain *swapChain, UINT count, UINT width, UINT height, DXGI_FORMAT format, UINT flags) {
            {
                std::lock_guard lock(imguiMutex);
                ReleaseRenderTarget(); // buffers cannot be resized while we hold a view of them
            }
            return resizeBuffersOriginal(swapChain, count, width, height, format, flags);
        }

        // --- input blocking while open ---
        HRESULT __stdcall hkGetDeviceState(void *dev, DWORD size, void *data) {
            const auto r = getDeviceStateOriginal(dev, size, data);
            if (open.load() && SUCCEEDED(r) && data != nullptr) {
                memset(data, 0, size);
            }
            return r;
        }

        HRESULT __stdcall hkGetDeviceData(void *dev, DWORD objectSize, void *data, DWORD *count, DWORD flags) {
            const auto r = getDeviceDataOriginal(dev, objectSize, data, count, flags);
            if (open.load() && SUCCEEDED(r) && count != nullptr) {
                *count = 0; // drop buffered events
            }
            return r;
        }

        void HookVtableEntry(void *object, const int index, void *detour, void **original, const char *name) {
            if (*original != nullptr) {
                return;
            }
            const auto fn = (*reinterpret_cast<void ***>(object))[index];
            if (MH_CreateHook(fn, detour, original) == MH_OK && MH_EnableHook(fn) == MH_OK) {
                spdlog::info("[overlay] hooked {} at {}", name, fn);
            } else {
                *original = nullptr;
                spdlog::error("[overlay] cannot hook {} at {}", name, fn);
            }
        }

        HRESULT __stdcall hkCreateDevice(void *directInput, const GUID &guid, void **dev, void *outer) {
            const auto r = createDeviceOriginal(directInput, guid, dev, outer);
            if (SUCCEEDED(r) && dev != nullptr && *dev != nullptr) {
                HookVtableEntry(*dev, getDeviceStateIndex, reinterpret_cast<void *>(&hkGetDeviceState), reinterpret_cast<void **>(&getDeviceStateOriginal), "GetDeviceState");
                HookVtableEntry(*dev, getDeviceDataIndex, reinterpret_cast<void *>(&hkGetDeviceData), reinterpret_cast<void **>(&getDeviceDataOriginal), "GetDeviceData");
            }
            return r;
        }

        BOOL WINAPI hkSetCursorPos(int x, int y) {
            if (open.load()) {
                return TRUE; // the game recenters the cursor for its camera; leave it to the menu
            }
            return setCursorPosOriginal(x, y);
        }

        BOOL WINAPI hkClipCursor(const RECT *rect) {
            if (open.load() && rect != nullptr) {
                return TRUE;
            }
            return clipCursorOriginal(rect);
        }

        // Builds a throwaway device and swap chain to read the shared Present / ResizeBuffers addresses.
        bool HookSwapChain() {
            const auto d3d11 = GetModuleHandleW(L"d3d11.dll");
            using CreateFunc = HRESULT(WINAPI *)(IDXGIAdapter *, D3D_DRIVER_TYPE, HMODULE, UINT, const D3D_FEATURE_LEVEL *, UINT, UINT, const DXGI_SWAP_CHAIN_DESC *,
                IDXGISwapChain **, ID3D11Device **, D3D_FEATURE_LEVEL *, ID3D11DeviceContext **);
            const auto create = reinterpret_cast<CreateFunc>(GetProcAddress(d3d11, "D3D11CreateDeviceAndSwapChain"));
            if (create == nullptr) {
                spdlog::error("[overlay] D3D11CreateDeviceAndSwapChain not found");
                return false;
            }

            WNDCLASSEXW wc{};
            wc.cbSize = sizeof(wc);
            wc.lpfnWndProc = DefWindowProcW;
            wc.hInstance = GetModuleHandleW(nullptr);
            wc.lpszClassName = L"dynamiteOverlayDummy";
            RegisterClassExW(&wc);
            const auto hwnd = CreateWindowExW(0, wc.lpszClassName, L"", WS_OVERLAPPEDWINDOW, 0, 0, 64, 64, nullptr, nullptr, wc.hInstance, nullptr);

            DXGI_SWAP_CHAIN_DESC desc{};
            desc.BufferCount = 1;
            desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
            desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
            desc.OutputWindow = hwnd;
            desc.SampleDesc.Count = 1;
            desc.Windowed = TRUE;
            desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

            IDXGISwapChain *sc = nullptr;
            ID3D11Device *dev = nullptr;
            ID3D11DeviceContext *ctx = nullptr;
            const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
            auto hr = create(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2, D3D11_SDK_VERSION, &desc, &sc, &dev, nullptr, &ctx);
            if (FAILED(hr)) {
                hr = create(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2, D3D11_SDK_VERSION, &desc, &sc, &dev, nullptr, &ctx);
            }
            bool ok = false;
            if (SUCCEEDED(hr) && sc != nullptr) {
                HookVtableEntry(sc, presentIndex, reinterpret_cast<void *>(&hkPresent), reinterpret_cast<void **>(&presentOriginal), "Present");
                HookVtableEntry(sc, resizeBuffersIndex, reinterpret_cast<void *>(&hkResizeBuffers), reinterpret_cast<void **>(&resizeBuffersOriginal), "ResizeBuffers");
                ok = presentOriginal != nullptr;
            } else {
                spdlog::error("[overlay] cannot create a dummy D3D11 device: {:#x}", static_cast<uint32_t>(hr));
            }
            if (ctx != nullptr) ctx->Release();
            if (dev != nullptr) dev->Release();
            if (sc != nullptr) sc->Release();
            DestroyWindow(hwnd);
            UnregisterClassW(wc.lpszClassName, wc.hInstance);
            return ok;
        }
    }

    bool IsOpen() { return open.load(); }

    void OnDirectInputCreated(void *directInput) {
        if (directInput == nullptr) {
            return;
        }
        HookVtableEntry(directInput, createDeviceIndex, reinterpret_cast<void *>(&hkCreateDevice), reinterpret_cast<void **>(&createDeviceOriginal), "CreateDevice");
    }

    void Start() {
        void *target = nullptr;
        if (MH_CreateHookApiEx(L"user32", "SetCursorPos", reinterpret_cast<void *>(&hkSetCursorPos), reinterpret_cast<void **>(&setCursorPosOriginal), &target) == MH_OK) {
            MH_EnableHook(target);
        }
        if (MH_CreateHookApiEx(L"user32", "ClipCursor", reinterpret_cast<void *>(&hkClipCursor), reinterpret_cast<void **>(&clipCursorOriginal), &target) == MH_OK) {
            MH_EnableHook(target);
        }

        std::thread([] {
            // the game loads d3d11.dll when it creates its renderer
            while (GetModuleHandleW(L"d3d11.dll") == nullptr) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (!HookSwapChain()) {
                spdlog::error("[overlay] disabled");
            }
        }).detach();
    }
}
