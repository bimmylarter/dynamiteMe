#ifndef HOOK_PLAYERPROBE_H
#define HOOK_PLAYERPROBE_H

// Research build: how is the partner's character (remote player) updated on this machine?
//  - logs which fields of the PlayerInfoService record (0xe0 bytes per player, double buffered) change, for both players
//  - catches the code that writes the remote player's record (hardware write breakpoint, call stacks)
#include <cstdint>

namespace Dynamite::PlayerProbe {
    // call every frame on game thread
    void Tick();

    // partner character rotation (quaternion x y z w) from player info, false if unknown
    bool PartnerRotation(float out[4]);

    // where the soldier partner carries should be, from partner's last carry offset (false if unknown)
    bool CarriedPlacement(uint32_t objectID, float pos[3], float rot[4]);

    // soldier the local player carries (0xffff if none)
    uint32_t LocalCarryTarget();
}

#endif // HOOK_PLAYERPROBE_H
