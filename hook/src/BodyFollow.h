#ifndef HOOK_BODYFOLLOW_H
#define HOOK_BODYFOLLOW_H

#include <cstdint>

// Moving a soldier that the partner carries along with the partner.
//
// The partner's game sends the carried body's position several times a second (body sync, "carried" updates).
// Soldiers ignore the Warp command, so the body is moved here with SoldierWarp, every frame, easing toward
// the latest received position so it does not jump between updates.
namespace Dynamite::BodyFollow {
    // body update received from partner (call on game thread)
    void OnUpdate(uint32_t objectID, float x, float y, float z, bool dropped);

    // move followed body, call every frame on game thread
    void Tick();

    // forget followed body (session end)
    void Reset();
}

#endif // HOOK_BODYFOLLOW_H
