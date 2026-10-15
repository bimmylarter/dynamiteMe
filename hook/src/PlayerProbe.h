#ifndef HOOK_PLAYERPROBE_H
#define HOOK_PLAYERPROBE_H

// Research build: how is the partner's character (remote player) updated on this machine?
//  - logs which fields of the PlayerInfoService record (0xe0 bytes per player, double buffered) change, for both players
//  - catches the code that writes the remote player's record (hardware write breakpoint, call stacks)
namespace Dynamite::PlayerProbe {
    // call every frame on game thread
    void Tick();
}

#endif // HOOK_PLAYERPROBE_H
