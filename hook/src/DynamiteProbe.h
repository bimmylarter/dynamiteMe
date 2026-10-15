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
}

#endif // HOOK_DYNAMITEPROBE_H
