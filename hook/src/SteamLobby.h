#pragma once

#include <cstdint>

struct lua_State;

// Co-op lobby over Steam: the host creates a friends-only Steam lobby from the overlay, the partner joins it with a
// Steam invite or "Join Game". The lobby lives across missions; the host publishes the mission picked in the sortie
// and whether it is in a mission, the partner connects to the host's co-op session automatically.
namespace Dynamite::SteamLobby {
    // every frame from the render hook (Steam calls are polled here)
    void Update();

    // overlay contents, inside an ImGui window
    void Draw();

    // Dynamite.LobbyTick(currentMission, selectedMission), every frame from the game's Lua update.
    // Runs queued actions that must happen on the Lua thread (connecting to the host).
    int LuaTick(lua_State *L);

    // Dynamite.LobbyPrepare(missionCode or 0): sortie preparation opened (TppMission.AcceptMission) or closed
    int LuaPrepare(lua_State *L);

    // Dynamite.LobbyDeploy(deployTime or -1, clusterId or -1) -> true when the deploy is held until the partner is
    // connected to the host (called from TppMission.OnEndMissionPreparation)
    int LuaDeploy(lua_State *L);
}
