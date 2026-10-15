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
    int Warp(uint32_t objectID, float x, float y, float z, bool log = true);
}

#endif // HOOK_SOLDIERWARP_H
