#include "BodyFollow.h"

#include "SoldierWarp.h"
#include "DynamiteCore.h"
#include "DynamiteHook.h"
#include "dynamite.h"
#include "spdlog/spdlog.h"
#include "windows.h"

#include <algorithm>

namespace Dynamite::BodyFollow {
    namespace {
        constexpr uint32_t noBody = 0xffffffff;
        constexpr uint32_t firstSoldier = 1024;
        constexpr uint32_t soldierCount = 512;
        constexpr double timeout = 1.0;  // stop following if partner sends nothing for this long
        constexpr float easeRate = 20.0f; // fraction of remaining distance covered per second (scaled by dt)
        constexpr float snapDistance = 6.0f; // jump straight to target if further away than this
        // The carrier's game reports a carried body at the height it was picked up from, so the body is held
        // above the partner's character instead: carrier position (feet) + shoulder height.
        constexpr float shoulderHeight = 1.25f;
        constexpr float maxCarrierDistance = 4.0f; // use carrier position only if body update agrees with it

        uint32_t followID = noBody;
        bool havePos = false;
        float cur[3] = {0, 0, 0};
        float target[3] = {0, 0, 0};
        double lastUpdate = 0;
        double lastTick = 0;

        double Now() {
            static LARGE_INTEGER freq{};
            if (freq.QuadPart == 0) {
                QueryPerformanceFrequency(&freq);
            }
            LARGE_INTEGER c;
            QueryPerformanceCounter(&c);
            return static_cast<double>(c.QuadPart) / static_cast<double>(freq.QuadPart);
        }

        bool IsSoldier(const uint32_t id) { return id >= firstSoldier && id < firstSoldier + soldierCount; }
    }

    void OnUpdate(const uint32_t objectID, const float x, const float y, const float z, const bool dropped) {
        if (!IsSoldier(objectID)) {
            return;
        }

        if (dropped) {
            if (objectID == followID) {
                spdlog::info("BodyFollow, partner dropped soldier {}", objectID);
                followID = noBody;
            }
            return;
        }

        if (objectID != followID) {
            spdlog::info("BodyFollow, following soldier {} carried by partner", objectID);
            followID = objectID;
            havePos = false;
        }
        target[0] = x;
        target[1] = y;
        target[2] = z;
        lastUpdate = Now();
    }

    void Tick() {
        const auto now = Now();
        const auto dt = static_cast<float>(std::clamp(now - lastTick, 0.0, 0.1));
        lastTick = now;

        if (followID == noBody) {
            return;
        }
        if (now - lastUpdate > timeout) {
            spdlog::info("BodyFollow, no updates for soldier {}, stopped following", followID);
            followID = noBody;
            return;
        }
        if (!SoldierWarp::Capture(followID)) {
            return; // character object not found yet, retried next frame
        }
        if (dt <= 0.0f && havePos) {
            return; // already moved this frame
        }

        // partner's character, as seen here (updated every frame, smoother than 5 body updates a second)
        float aim[3] = {target[0], target[1], target[2]};
        auto carrier = DynamiteCore::GetPlayerPosition(g_hook->cfg.Host ? 1 : 0);
        if (carrier.Valid()) {
            const auto dx = carrier.x - target[0], dz = carrier.z - target[2];
            if (dx * dx + dz * dz < maxCarrierDistance * maxCarrierDistance) {
                aim[0] = carrier.x;
                aim[1] = carrier.y + shoulderHeight;
                aim[2] = carrier.z;
            }
        }

        float dist2 = 0;
        for (int i = 0; i < 3; i++) {
            const auto d = aim[i] - cur[i];
            dist2 += d * d;
        }
        if (!havePos || dist2 > snapDistance * snapDistance) {
            std::copy(std::begin(aim), std::end(aim), std::begin(cur));
            havePos = true;
        } else {
            const auto k = std::min(1.0f, dt * easeRate);
            for (int i = 0; i < 3; i++) {
                cur[i] += (aim[i] - cur[i]) * k;
            }
        }

        if (SoldierWarp::Warp(followID, cur[0], cur[1], cur[2], false) < 0) {
            havePos = false; // recapture on next frame
        }
    }

    void Reset() {
        followID = noBody;
        havePos = false;
    }
}
