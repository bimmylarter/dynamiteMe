#pragma once

#include <cstdint>

// Research (v26): find D-Horse's motion controller and character object while a player rides.
// Every animation request that is not for a player or a soldier is recorded by controller and index; twice a second
// the characters behind them that are near a player are logged with their position, so the horse and how its
// position differs between the rider's and the watcher's game can be read from both logs.
namespace Dynamite::HorseProbe {
    // from the motion hook (any thread); trusted = controller of a player (its vtable is known to be a motion controller)
    void OnMotion(void *ctrl, uint32_t index, uint32_t layer, uint64_t state, uint64_t caller, bool trusted);

    // from PlayerProbe::Tick (Lua thread, in co-op missions)
    void Tick();
}
