#ifndef HOOK_BODYFOLLOW_H
#define HOOK_BODYFOLLOW_H

#include <cstdint>

// Moving a soldier that the partner carries along with the partner.
//
// The partner's game sends the carried body's position several times a second (body sync, "carried" updates).
// Soldiers ignore the Warp command, so the body is moved here with SoldierWarp, every frame, easing toward
// the partner's character (held at shoulder height) so it does not jump between updates.
namespace Dynamite::BodyFollow {
    // body update received from partner (call on game thread)
    void OnUpdate(uint32_t objectID, float x, float y, float z, bool dropped);

    // move followed body, call every frame on game thread
    void Tick();

    // soldier currently followed (0xffffffff if none), and for how long (seconds)
    uint32_t FollowedID();
    double FollowedFor();

    // body plays the carried animation: place it exactly at the carrier, facing the carrier's direction
    void SetAttached(bool attached);

    // place an attached body at the carrier, call right after players are updated (every frame)
    void PlaceAttached();

    // true while the body is placed from the partner's carry (other moves of it must wait)
    bool Handles(uint32_t objectID);

    // forget followed body (session end)
    void Reset();
}

#endif // HOOK_BODYFOLLOW_H
