#ifndef HOOK_CARRYPROBE_H
#define HOOK_CARRYPROBE_H

#include <string>

// Research build: find which game code puts a soldier into / out of "carried" state.
// The nearest downed soldier near the local player is watched with hardware write breakpoints on its state
// records (the ones read by soldier GetStatus). Every write records the instruction and a stack trace;
// Dump() writes collected traces to log.
namespace Dynamite::CarryProbe {
    // pick nearest downed soldier within reach of local player and watch it (no-op if already watching it)
    void ArmNearest();

    // write collected traces to log with a tag, clear them, keep watching
    void Dump(const std::string &tag);

    // stop watching
    void Disarm();
}

#endif // HOOK_CARRYPROBE_H
