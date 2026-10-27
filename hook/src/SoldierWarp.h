#ifndef HOOK_SOLDIERWARP_H
#define HOOK_SOLDIERWARP_H

#include <cstdint>

// Moving soldiers (TppSoldier2) to an arbitrary position.
//
// Soldiers do not implement the "Warp" GameObject command, so they are moved through their character object,
// the same way Player2GameObjectImpl::Warp moves players:
//   obj = controller->vf[0x388](localIndex); obj->vf[0x70](&rot); obj->vf[0x68](&pos, &rot)
//
// Controller and local index of a soldier are not reachable from its game object id directly. They are captured
// from the per-frame soldier update ("SoldierPositionWriter" in address set): a one-shot hardware write breakpoint
// is placed on the soldier's position table entry, and registers r14 (controller) and r12 (local index) are read
// when that instruction writes it.
namespace Dynamite::SoldierWarp {
    // Start capturing controller for soldier, returns true if it is already known.
    // Capture happens on the next frame the soldier is updated (usually within one frame).
    bool Capture(uint32_t objectID);

    // Move soldier. Returns 1 on success, 0 if controller is not captured yet (call Capture and retry),
    // -1 on failure (soldier not found or captured data does not match soldier).
    int Warp(uint32_t objectID, float x, float y, float z, bool log = true, const float *rotation = nullptr);

    // current position (x y z) and rotation (4 floats) of a captured soldier's character object
    bool GetTransform(uint32_t objectID, float pos[3], float rot[4]);

    // local index of a captured soldier (true if known)
    bool LocalIndex(uint32_t objectID, uint32_t &index);

    // soldier controller of a captured soldier (also its motion controller), 0 if unknown
    uint64_t Controller(uint32_t objectID);

    // research (v29): for 300 ms, log every instruction that writes the soldier's character position (DR1 write
    // breakpoint on obj+0x20 on all game threads). Returns false if a watch is already running.
    bool WatchWrites(uint32_t objectID, const char *why);

    // research (v29): hex dump of the soldier's character object (first 0x400 bytes), to compare a body the watcher
    // put down before with a fresh one
    void DumpCharacter(uint32_t objectID, const char *why);
}

#endif // HOOK_SOLDIERWARP_H
