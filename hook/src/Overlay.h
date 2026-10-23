#pragma once

#include "windows.h"

// In-game overlay drawn with Dear ImGui on top of the game's frames (D3D11).
// F3 opens and closes it. While open, the game does not receive mouse / keyboard input.
namespace Dynamite::Overlay {
    // Starts a background thread that waits for the game's renderer and installs the hooks.
    void Start();

    bool IsOpen();

    // Called from the dinput8 proxy with the IDirectInput8 interface the game created,
    // so device input can be blocked while the overlay is open.
    void OnDirectInputCreated(void *directInput);
}
