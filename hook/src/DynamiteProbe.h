#ifndef HOOK_DYNAMITEPROBE_H
#define HOOK_DYNAMITEPROBE_H

#include <cstdint>

// Research helpers for body sync: find which game code writes a soldier's position.
// A hardware write breakpoint is placed on the soldier's entry in the position table read by GetSoldierPosition;
// addresses of writing instructions are collected in an exception handler and logged by a worker thread.
namespace Dynamite::Probe {
    // address of soldier position entry (Vector3, 16 bytes), nullptr if soldier not found
    float *SoldierPositionEntry(uint32_t objectID);

    // watch writes to soldier position for `seconds`, results are written to log
    bool WatchSoldierPosition(uint32_t objectID, int seconds);

    // experiment: overwrite position table entry, read it back after a delay and log result
    void TestWriteSoldierPosition(uint32_t objectID, float x, float y, float z);

    // Soldier warp, step 1: watch soldier's position table entry until the game's per-frame update writes it,
    // remember character controller (r14) and local index (r12) used by that update (see 0x141377a83, 1.0.15.4).
    bool CaptureSoldierController(uint32_t objectID);

    // Soldier warp, step 2: once captured, move soldier using character object methods used by player warp
    // (Player2GameObjectImpl::Warp: obj = ctrl->vf[0x388](localIndex); obj->vf[0x70](&rot); obj->vf[0x68](&pos, &rot)).
    // returns 1 on success, 0 if controller is not captured yet, -1 on failure
    int WarpSoldier(uint32_t objectID, float x, float y, float z);
}

#endif // HOOK_DYNAMITEPROBE_H
