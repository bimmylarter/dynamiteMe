#include "SteamLobby.h"

#include "DynamiteHook.h"
#include "DynamiteLua.h"
#include "dynamite.h"
#include "mgsvtpp_func_typedefs.h"
#include "Version.h"

#include "imgui.h"
#include "spdlog/spdlog.h"
#include "windows.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

// Steam is reached through the game's steam_api64.dll (Steamworks SDK 1.31 era). Interfaces are requested by exact
// version string through ISteamClient, so their layouts are known regardless of the dll; vtable indices below are
// taken from the SDK 1.31 headers. MSVC ABI notes: `this` comes first; methods returning CSteamID return it through
// a hidden pointer passed right after `this`; CSteamID arguments are passed as uint64.
namespace Dynamite::SteamLobby {
    namespace {
        constexpr const char *friendsVersion = "SteamFriends014";
        constexpr const char *utilsVersion = "SteamUtils007";
        constexpr const char *matchmakingVersion = "SteamMatchMaking009";
        constexpr const char *userVersion = "SteamUser017";

        // ISteamClient
        constexpr int clientGetUser = 5, clientGetFriends = 8, clientGetUtils = 9, clientGetMatchmaking = 10;
        // ISteamFriends014
        constexpr int friendsGetPersonaName = 0, friendsGetFriendPersonaName = 7, friendsActivateOverlay = 22, friendsActivateInviteDialog = 27,
                      friendsSetRichPresence = 37, friendsClearRichPresence = 38;
        // ISteamUtils007
        constexpr int utilsIsCallCompleted = 11, utilsGetCallResult = 13;
        // ISteamMatchmaking009
        constexpr int mmCreateLobby = 13, mmJoinLobby = 14, mmLeaveLobby = 15, mmNumMembers = 17, mmMemberByIndex = 18, mmGetData = 19, mmSetData = 20,
                      mmSetJoinable = 34, mmGetOwner = 35;
        // ISteamUser017
        constexpr int userGetSteamID = 2;

        // callbacks / call results
        constexpr int gameLobbyJoinRequestedID = 300 + 33;
        constexpr int lobbyEnterID = 500 + 4;
        constexpr int lobbyCreatedID = 500 + 13;
        constexpr int lobbyTypeFriendsOnly = 1;

        struct LobbyCreated {
            int32_t result; // EResult, 1 = OK
            uint64_t lobby;
        };
        struct LobbyEnter {
            uint64_t lobby;
            uint32_t chatPermissions;
            bool locked;
            uint32_t response; // EChatRoomEnterResponse, 1 = success
        };
        struct GameLobbyJoinRequested {
            uint64_t lobby;
            uint64_t friendID;
        };

        template <typename F>
        F Method(void *object, const int index) {
            return reinterpret_cast<F>((*reinterpret_cast<void ***>(object))[index]);
        }

        struct Api {
            bool tried = false;
            bool ok = false;
            std::string error;
            void *client = nullptr, *friends = nullptr, *utils = nullptr, *matchmaking = nullptr, *user = nullptr;
            void(__cdecl *registerCallback)(void *callback, int id) = nullptr;
        } api;

        // fake CCallbackBase: vtable {Run(param, ioFailure, call), Run(param), GetCallbackSizeBytes} (MSVC orders the
        // overloads in reverse). Both Run entries point to the same function, only the first argument is used.
        struct FakeCallback {
            void **vtable;
            uint8_t flags;
            int32_t id;
        };

        enum class State { Idle, Creating, Hosting, Joining, Member };

        std::recursive_mutex mutex;
        State state = State::Idle;
        uint64_t lobby = 0;
        uint64_t pendingCall = 0;
        std::string lastError;
        std::atomic<uint64_t> requestedJoin{0}; // from Steam (invite / Join Game) or the command line

        // values from the game's Lua update
        std::atomic<uint32_t> currentMission{0}, selectedMission{0};
        std::atomic<uint64_t> lastLuaTick{0};

        // what the host publishes, as seen by the partner
        struct HostView {
            uint64_t owner = 0;
            uint32_t selected = 0, current = 0;
            std::string version;
        } hostView;
        struct Member {
            uint64_t id;
            std::string name;
        };
        std::vector<Member> members;

        bool originalHost = false;
        uint64_t originalHostID = 0;
        bool savedConfig = false;

        // actions for the Lua thread
        std::atomic<bool> wantConnect{false}, wantReset{false};
        std::atomic<uint32_t> wantPrepare{0}; // mission to open the sortie preparation for
        bool autoConnect = true;
        bool autoPrepare = true;
        uint32_t autoConnectedFor = 0; // host mission code we already connected for
        uint32_t autoPreparedFor = 0;  // host mission code we already opened the preparation for

        uint64_t nextPublish = 0, nextRead = 0;

        void __cdecl OnJoinRequested(void *, void *param) {
            const auto r = static_cast<GameLobbyJoinRequested *>(param);
            spdlog::info("[lobby] Steam join request for lobby {} (via friend {})", r->lobby, r->friendID);
            requestedJoin = r->lobby;
        }
        int __cdecl JoinRequestedSize(void *) { return sizeof(GameLobbyJoinRequested); }
        void *joinVtable[3] = {reinterpret_cast<void *>(&OnJoinRequested), reinterpret_cast<void *>(&OnJoinRequested),
            reinterpret_cast<void *>(&JoinRequestedSize)};
        FakeCallback joinCallback{joinVtable, 0, 0};

        bool InitApi() {
            if (api.tried) {
                return api.ok;
            }
            const auto dll = GetModuleHandleW(L"steam_api64.dll");
            if (dll == nullptr) {
                return false; // not loaded yet, try again later
            }
            using SteamClientFunc = void *(__cdecl *)();
            using HandleFunc = int32_t(__cdecl *)();
            const auto steamClient = reinterpret_cast<SteamClientFunc>(GetProcAddress(dll, "SteamClient"));
            const auto getUser = reinterpret_cast<HandleFunc>(GetProcAddress(dll, "SteamAPI_GetHSteamUser"));
            const auto getPipe = reinterpret_cast<HandleFunc>(GetProcAddress(dll, "SteamAPI_GetHSteamPipe"));
            api.registerCallback = reinterpret_cast<decltype(api.registerCallback)>(GetProcAddress(dll, "SteamAPI_RegisterCallback"));
            if (steamClient == nullptr || getUser == nullptr || getPipe == nullptr || api.registerCallback == nullptr) {
                api.tried = true;
                api.error = "steam_api64.dll is missing SteamClient / SteamAPI_GetHSteamUser / SteamAPI_GetHSteamPipe / SteamAPI_RegisterCallback";
                spdlog::error("[lobby] {}", api.error);
                return false;
            }
            const auto user = getUser();
            const auto pipe = getPipe();
            api.client = steamClient();
            if (api.client == nullptr || user == 0 || pipe == 0) {
                return false; // Steam not initialized by the game yet
            }
            api.tried = true;

            using GetWithUser = void *(__cdecl *)(void *self, int32_t user, int32_t pipe, const char *version);
            using GetWithPipe = void *(__cdecl *)(void *self, int32_t pipe, const char *version);
            api.friends = Method<GetWithUser>(api.client, clientGetFriends)(api.client, user, pipe, friendsVersion);
            api.utils = Method<GetWithPipe>(api.client, clientGetUtils)(api.client, pipe, utilsVersion);
            api.matchmaking = Method<GetWithUser>(api.client, clientGetMatchmaking)(api.client, user, pipe, matchmakingVersion);
            api.user = Method<GetWithUser>(api.client, clientGetUser)(api.client, user, pipe, userVersion);
            spdlog::info("[lobby] Steam interfaces: friends {} utils {} matchmaking {} user {}", api.friends, api.utils, api.matchmaking, api.user);
            if (api.friends == nullptr || api.utils == nullptr || api.matchmaking == nullptr || api.user == nullptr) {
                api.error = "Steam did not provide the friends / matchmaking interfaces";
                spdlog::error("[lobby] {}", api.error);
                return false;
            }
            api.registerCallback(&joinCallback, gameLobbyJoinRequestedID);
            api.ok = true;

            // started by Steam "Join Game" while the game was not running: +connect_lobby <id>
            const std::wstring cmd = GetCommandLineW();
            const auto at = cmd.find(L"+connect_lobby");
            if (at != std::wstring::npos) {
                const auto id = wcstoull(cmd.c_str() + at + wcslen(L"+connect_lobby"), nullptr, 10);
                if (id != 0) {
                    spdlog::info("[lobby] started to join lobby {}", id);
                    requestedJoin = id;
                }
            }
            return true;
        }

        uint64_t MyID() {
            uint64_t id = 0;
            using F = uint64_t *(__cdecl *)(void *self, uint64_t *ret);
            Method<F>(api.user, userGetSteamID)(api.user, &id);
            return id;
        }

        std::string Name(const uint64_t id) {
            using F = const char *(__cdecl *)(void *self, uint64_t id);
            const auto n = Method<F>(api.friends, friendsGetFriendPersonaName)(api.friends, id);
            return n != nullptr ? n : "?";
        }

        uint64_t Owner(const uint64_t l) {
            uint64_t id = 0;
            using F = uint64_t *(__cdecl *)(void *self, uint64_t *ret, uint64_t lobby);
            Method<F>(api.matchmaking, mmGetOwner)(api.matchmaking, &id, l);
            return id;
        }

        std::string GetData(const uint64_t l, const char *key) {
            using F = const char *(__cdecl *)(void *self, uint64_t lobby, const char *key);
            const auto v = Method<F>(api.matchmaking, mmGetData)(api.matchmaking, l, key);
            return v != nullptr ? v : "";
        }

        void SetData(const uint64_t l, const char *key, const std::string &value) {
            using F = bool(__cdecl *)(void *self, uint64_t lobby, const char *key, const char *value);
            Method<F>(api.matchmaking, mmSetData)(api.matchmaking, l, key, value.c_str());
        }

        void SetPresence(const char *status) {
            if (status == nullptr) {
                using F = void(__cdecl *)(void *self);
                Method<F>(api.friends, friendsClearRichPresence)(api.friends);
                return;
            }
            using F = bool(__cdecl *)(void *self, const char *key, const char *value);
            Method<F>(api.friends, friendsSetRichPresence)(api.friends, "status", status);
        }

        // true when the call finished; result copied into out
        bool PollCall(const uint64_t call, void *out, const int size, const int id, bool &failed) {
            bool ioFailed = false;
            using Completed = bool(__cdecl *)(void *self, uint64_t call, bool *failed);
            if (!Method<Completed>(api.utils, utilsIsCallCompleted)(api.utils, call, &ioFailed)) {
                return false;
            }
            using Result = bool(__cdecl *)(void *self, uint64_t call, void *out, int size, int id, bool *failed);
            const bool got = Method<Result>(api.utils, utilsGetCallResult)(api.utils, call, out, size, id, &ioFailed);
            failed = !got || ioFailed;
            return true;
        }

        void SaveConfig() {
            if (!savedConfig) {
                originalHost = g_hook->cfg.Host;
                originalHostID = g_hook->cfg.HostSteamID;
                savedConfig = true;
            }
        }

        void RestoreConfig() {
            if (savedConfig) {
                g_hook->cfg.Host = originalHost;
                g_hook->cfg.HostSteamID = originalHostID;
            }
        }

        void Leave(const char *why) {
            if (lobby != 0) {
                using F = void(__cdecl *)(void *self, uint64_t lobby);
                Method<F>(api.matchmaking, mmLeaveLobby)(api.matchmaking, lobby);
                spdlog::info("[lobby] left lobby {} ({})", lobby, why);
            }
            lobby = 0;
            pendingCall = 0;
            state = State::Idle;
            members.clear();
            hostView = {};
            autoConnectedFor = 0;
            autoPreparedFor = 0;
            SetPresence(nullptr);
            RestoreConfig();
        }

        void Join(const uint64_t id) {
            if (lobby == id && (state == State::Member || state == State::Hosting)) {
                return;
            }
            if (state != State::Idle) {
                Leave("joining another lobby");
            }
            using F = uint64_t(__cdecl *)(void *self, uint64_t lobby);
            pendingCall = Method<F>(api.matchmaking, mmJoinLobby)(api.matchmaking, id);
            state = State::Joining;
            lastError.clear();
            spdlog::info("[lobby] joining lobby {}", id);
        }

        void Host() {
            if (state != State::Idle) {
                Leave("hosting a new lobby");
            }
            using F = uint64_t(__cdecl *)(void *self, int type, int maxMembers);
            pendingCall = Method<F>(api.matchmaking, mmCreateLobby)(api.matchmaking, lobbyTypeFriendsOnly, 2);
            state = State::Creating;
            lastError.clear();
            spdlog::info("[lobby] creating lobby");
        }

        void ReadMembers() {
            using CountF = int(__cdecl *)(void *self, uint64_t lobby);
            using MemberF = uint64_t *(__cdecl *)(void *self, uint64_t *ret, uint64_t lobby, int index);
            const auto count = Method<CountF>(api.matchmaking, mmNumMembers)(api.matchmaking, lobby);
            members.clear();
            for (int i = 0; i < count && i < 8; i++) {
                uint64_t id = 0;
                Method<MemberF>(api.matchmaking, mmMemberByIndex)(api.matchmaking, &id, lobby, i);
                members.push_back({id, Name(id)});
            }
        }

        bool IsHeliSpace(const uint32_t code) { return code / 10000 == 4; }
        bool IsMission(const uint32_t code) { return code / 10000 == 1 || code / 10000 == 3; }

        struct MissionName {
            uint32_t code;
            const char *name;
        };
        // episode numbers from TppUiBootInit.lua (RegistMissionEpisodeNo)
        constexpr MissionName missionNames[] = {
            {10010, "Prologue: Awakening"}, {10020, "1 Phantom Limbs"}, {10030, "2 Diamond Dogs"}, {10036, "3 A Hero's Way"}, {10043, "4 C2W"},
            {10033, "5 Over the Fence"}, {10040, "6 Where Do the Bees Sleep?"}, {10041, "7 Red Brass"}, {10044, "8 Occupation Forces"},
            {10054, "9 Backup, Back Down"}, {10052, "10 Angel with Broken Wings"}, {10050, "11 Cloaked in Silence"}, {10070, "12 Hellbound"},
            {10080, "13 Pitch Dark"}, {10086, "14 Lingua Franca"}, {10082, "15 Footprints of Phantoms"}, {10090, "16 Traitors' Caravan"},
            {10091, "17 Rescue the Intel Agents"}, {10100, "18 Blood Runs Deep"}, {10195, "19 On the Trail"}, {10110, "20 Voices"},
            {10121, "21 The War Economy"}, {10115, "22 Retake the Platform"}, {10120, "23 The White Mamba"}, {10085, "24 Close Contact"},
            {10200, "25 Aim True, Ye Vengeful"}, {10211, "26 Hunting Down"}, {10081, "27 Root Cause"}, {10130, "28 Code Talker"},
            {10140, "29 Metallic Archaea"}, {10150, "30 Skull Face"}, {10151, "31 Sahelanthropus"}, {10045, "32 To Know Too Much"},
            {11043, "33 [Subsistence] C2W"}, {11054, "34 [Extreme] Backup, Back Down"}, {10093, "35 Cursed Legacy"},
            {11082, "36 [Total Stealth] Footprints of Phantoms"}, {11090, "37 [Extreme] Traitors' Caravan"}, {10156, "38 Extraordinary"},
            {11033, "39 [Total Stealth] Over the Fence"}, {11050, "40 [Extreme] Cloaked in Silence"}, {10171, "41 Proxy War Without End"},
            {11140, "42 [Extreme] Metallic Archaea"}, {10240, "43 Shining Lights, Even in Death"}, {11080, "44 [Total Stealth] Pitch Dark"},
            {10260, "45 A Quiet Exit"}, {10280, "46 Truth: The Man Who Sold the World"}, {11121, "47 [Total Stealth] The War Economy"},
            {11130, "48 [Extreme] Code Talker"}, {11044, "49 [Subsistence] Occupation Forces"}, {11151, "50 [Extreme] Sahelanthropus"},
            {30010, "Free roam: Afghanistan"}, {30020, "Free roam: Africa"}, {30050, "Mother Base"},
        };

        std::string Describe(const uint32_t code) {
            if (code == 0) {
                return "none";
            }
            if (IsHeliSpace(code)) {
                return "ACC (helicopter)";
            }
            for (const auto &m : missionNames) {
                if (m.code == code) {
                    return std::string(m.name) + " (" + std::to_string(code) + ")";
                }
            }
            return std::to_string(code);
        }

        void Publish() {
            SetData(lobby, "dynamite", SOFTWARE_VERSION);
            SetData(lobby, "selected", std::to_string(selectedMission.load()));
            SetData(lobby, "current", std::to_string(currentMission.load()));
        }

        void ReadHost() {
            hostView.owner = Owner(lobby);
            hostView.selected = static_cast<uint32_t>(strtoul(GetData(lobby, "selected").c_str(), nullptr, 10));
            hostView.current = static_cast<uint32_t>(strtoul(GetData(lobby, "current").c_str(), nullptr, 10));
            hostView.version = GetData(lobby, "dynamite");
            if (hostView.owner != 0 && hostView.owner != MyID()) {
                SaveConfig();
                g_hook->cfg.Host = false;
                g_hook->cfg.HostSteamID = hostView.owner;
            }
        }
    }

    void Update() {
        std::lock_guard lock(mutex);
        if (!InitApi()) {
            return;
        }

        if (const auto j = requestedJoin.exchange(0); j != 0) {
            Join(j);
        }

        if (state == State::Creating && pendingCall != 0) {
            LobbyCreated r{};
            bool failed = false;
            if (PollCall(pendingCall, &r, sizeof(r), lobbyCreatedID, failed)) {
                pendingCall = 0;
                if (failed || r.result != 1) {
                    lastError = "Steam could not create the lobby (result " + std::to_string(r.result) + ")";
                    spdlog::error("[lobby] {}", lastError);
                    state = State::Idle;
                } else {
                    lobby = r.lobby;
                    state = State::Hosting;
                    SaveConfig();
                    g_hook->cfg.Host = true;
                    using F = bool(__cdecl *)(void *self, uint64_t lobby, bool joinable);
                    Method<F>(api.matchmaking, mmSetJoinable)(api.matchmaking, lobby, true);
                    Publish();
                    SetPresence("Dynamite co-op: hosting a lobby");
                    spdlog::info("[lobby] hosting lobby {}", lobby);
                }
            }
        }

        if (state == State::Joining && pendingCall != 0) {
            LobbyEnter r{};
            bool failed = false;
            if (PollCall(pendingCall, &r, sizeof(r), lobbyEnterID, failed)) {
                pendingCall = 0;
                if (failed || r.response != 1) {
                    lastError = "could not join the lobby (Steam response " + std::to_string(r.response) + ")";
                    spdlog::error("[lobby] {}", lastError);
                    state = State::Idle;
                } else {
                    lobby = r.lobby;
                    state = State::Member;
                    ReadHost();
                    SetPresence("Dynamite co-op: in a lobby");
                    spdlog::info("[lobby] joined lobby {}, host {} ({}), dynamite {}", lobby, hostView.owner, Name(hostView.owner), hostView.version);
                }
            }
        }

        const auto now = GetTickCount64();
        if ((state == State::Hosting || state == State::Member) && now >= nextRead) {
            nextRead = now + 500;
            ReadMembers();
            if (state == State::Member) {
                const auto previous = hostView.current;
                ReadHost();
                if (hostView.owner == MyID()) {
                    // Steam made us the owner: the host left
                    lastError = "the host left the lobby";
                    Leave("host left");
                } else if (previous != hostView.current) {
                    spdlog::info("[lobby] host is now in {}", Describe(hostView.current));
                }
            }
        }
        if (state == State::Hosting && now >= nextPublish) {
            nextPublish = now + 1000;
            Publish();
        }

        // partner: connect to the host's session once the host is in a mission and we are in the helicopter
        if (state == State::Member && autoConnect && IsMission(hostView.current) && autoConnectedFor != hostView.current &&
            IsHeliSpace(currentMission.load()) && !g_hook->dynamiteCore.GetSessionConnected() && now - lastLuaTick.load() < 2000) {
            autoConnectedFor = hostView.current;
            wantConnect = true;
            spdlog::info("[lobby] host is in {}, connecting", Describe(hostView.current));
        }
        // partner, once connected: open the sortie preparation with the host's mission (loadout, landing zone, deploy)
        if (state == State::Member && autoPrepare && IsMission(hostView.current) && autoPreparedFor != hostView.current &&
            IsHeliSpace(currentMission.load()) && g_hook->dynamiteCore.GetSessionConnected() && now - lastLuaTick.load() < 2000) {
            autoPreparedFor = hostView.current;
            wantPrepare = hostView.current;
            spdlog::info("[lobby] connected, opening the sortie for {}", Describe(hostView.current));
        }
        if (state == State::Member && IsHeliSpace(hostView.current)) {
            autoConnectedFor = 0; // host back in the helicopter: connect and prepare again for the next mission
            autoPreparedFor = 0;
        }
    }

    int LuaTick(lua_State *L) {
        currentMission = static_cast<uint32_t>(luaL_checkinteger(L, 1));
        selectedMission = static_cast<uint32_t>(luaL_checkinteger(L, 2));
        lastLuaTick = GetTickCount64();
        if (wantReset.exchange(false)) {
            l_ResetClientSessionStateWithNotification(L);
        }
        if (wantConnect.exchange(false)) {
            l_CreateClientSession(L);
        }
        if (const auto code = wantPrepare.exchange(0); code != 0) {
            // same as picking the mission in the helicopter: TppMission.AcceptMission(code) stores it as the next
            // mission and opens the sortie preparation screen
            if (IsHeliSpace(currentMission.load())) {
                lua_getfield(L, LUA_GLOBALSINDEX, "TppMission");
                lua_getfield(L, -1, "AcceptMission");
                lua_pushinteger(L, code);
                const auto err = lua_pcall(L, 1, 0, 0);
                spdlog::info("[lobby] TppMission.AcceptMission({}) {}", code, err == 0 ? "done" : "failed");
            }
        }
        return 0;
    }

    void Draw() {
        std::lock_guard lock(mutex);
        if (!ImGui::CollapsingHeader("Co-op lobby", ImGuiTreeNodeFlags_DefaultOpen)) {
            return;
        }
        if (!api.ok) {
            ImGui::TextDisabled("%s", api.error.empty() ? "waiting for Steam..." : api.error.c_str());
            return;
        }
        const auto me = MyID();
        const bool luaAlive = GetTickCount64() - lastLuaTick.load() < 2000;
        const bool inHeli = IsHeliSpace(currentMission.load());

        if (!luaAlive) {
            ImGui::TextColored(ImVec4(0.95f, 0.7f, 0.3f, 1.0f), "Game scripts not updated:");
            ImGui::TextWrapped("missions and connecting need this version's installer. The lobby itself works.");
        }
        if (!lastError.empty()) {
            ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.4f, 1.0f), "%s", lastError.c_str());
        }

        switch (state) {
        case State::Idle:
            ImGui::TextWrapped("Host a lobby and invite your partner, or join one with a Steam invite or \"Join Game\" in your friends list.");
            if (!inHeli && luaAlive) {
                ImGui::TextDisabled("Lobbies can be started from the ACC (helicopter).");
            }
            ImGui::BeginDisabled(luaAlive && !inHeli);
            if (ImGui::Button("Host a lobby")) {
                Host();
            }
            ImGui::EndDisabled();
            ImGui::SameLine();
            if (ImGui::Button("Open Steam friends")) {
                using F = void(__cdecl *)(void *self, const char *dialog);
                Method<F>(api.friends, friendsActivateOverlay)(api.friends, "friends");
            }
            break;
        case State::Creating:
            ImGui::Text("Creating lobby...");
            break;
        case State::Joining:
            ImGui::Text("Joining lobby...");
            break;
        case State::Hosting:
        case State::Member: {
            const bool hosting = state == State::Hosting;
            ImGui::Text("%s", hosting ? "You are hosting." : "You joined a lobby.");
            ImGui::Text("Players:");
            for (const auto &m : members) {
                const bool owner = hosting ? m.id == me : m.id == hostView.owner;
                ImGui::BulletText("%s%s%s", m.name.c_str(), owner ? "  (host)" : "", m.id == me ? "  (you)" : "");
            }
            if (members.size() < 2) {
                ImGui::TextDisabled("Waiting for your partner...");
            }
            ImGui::Separator();
            if (hosting) {
                ImGui::Text("Selected mission: %s", Describe(selectedMission.load()).c_str());
                ImGui::Text("You are in: %s", Describe(currentMission.load()).c_str());
                ImGui::TextDisabled("Pick a mission in the sortie as usual; your partner sees it here.");
                if (ImGui::Button("Invite friend")) {
                    using F = void(__cdecl *)(void *self, uint64_t lobby);
                    Method<F>(api.friends, friendsActivateInviteDialog)(api.friends, lobby);
                }
                ImGui::SameLine();
            } else {
                ImGui::Text("Host's mission: %s", Describe(hostView.selected).c_str());
                ImGui::Text("Host is in: %s", Describe(hostView.current).c_str());
                if (hostView.version != SOFTWARE_VERSION) {
                    ImGui::TextColored(ImVec4(0.95f, 0.7f, 0.3f, 1.0f), "Host runs dynamite %s, you run %s", hostView.version.c_str(), SOFTWARE_VERSION);
                }
                const bool connected = g_hook->dynamiteCore.GetSessionConnected();
                if (connected) {
                    ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "Connected to the host.");
                    ImGui::TextWrapped("Choose your loadout and landing zone in the sortie and deploy to %s.", Describe(hostView.current).c_str());
                } else if (IsMission(hostView.current)) {
                    ImGui::Text("Host is in the mission, %s", autoConnect ? "connecting..." : "press Connect.");
                } else {
                    ImGui::TextDisabled("Wait for the host to deploy; you will be connected automatically.");
                }
                ImGui::Checkbox("Connect automatically", &autoConnect);
                ImGui::Checkbox("Open the host's mission in my sortie when connected", &autoPrepare);
                ImGui::BeginDisabled(!luaAlive);
                if (ImGui::Button("Connect now")) {
                    wantConnect = true;
                }
                ImGui::SameLine();
                ImGui::BeginDisabled(!IsMission(hostView.current) || !inHeli);
                if (ImGui::Button("Open host's mission")) {
                    wantPrepare = hostView.current;
                }
                ImGui::EndDisabled();
                ImGui::SameLine();
                if (ImGui::Button("Reset connection")) {
                    wantReset = true;
                    autoConnectedFor = 0;
                }
                ImGui::EndDisabled();
            }
            if (ImGui::Button("Leave lobby")) {
                lastError.clear();
                Leave("left from the menu");
            }
            break;
        }
        }
    }
}
