#include "BodyFollow.h"

#include "SoldierWarp.h"
#include "DynamiteCore.h"
#include "PlayerProbe.h"
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
        constexpr float shoulderHeight = 0.15f; // a ragdolled soldier sinks back from shoulder height and contorts, keep it at the feet
        constexpr float maxCarrierDistance = 4.0f; // use carrier position only if body update agrees with it

        uint32_t followID = noBody;
        bool havePos = false;
        float cur[3] = {0, 0, 0};
        float target[3] = {0, 0, 0};
        double lastUpdate = 0;
        double lastTick = 0;
        double followStart = 0;
        bool attached = false;

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
                attached = false;
            }
            return;
        }

        if (objectID != followID) {
            spdlog::info("BodyFollow, following soldier {} carried by partner", objectID);
            followID = objectID;
            attached = false;
            followStart = Now();
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
        if (PlayerProbe::LocalCarryTarget() == followID) {
            spdlog::info("BodyFollow, soldier {} picked up here, stopped following partner", followID);
            followID = noBody;
            attached = false;
            return;
        }
        if (now - lastUpdate > timeout) {
            spdlog::info("BodyFollow, no updates for soldier {}, stopped following", followID);
            followID = noBody;
            attached = false;
            return;
        }
        if (!SoldierWarp::Capture(followID)) {
            return; // character object not found yet, retried next frame
        }
        if (attached) {
            return; // placed every frame right after the players are updated, see PlaceAttached
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
                aim[1] = carrier.y + (attached ? 0.0f : shoulderHeight);
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

        alignas(16) float rot[4];
        bool haveRot = false;
        if (attached) {
            // carried pose: exactly where the carrier's game has the soldier, relative to the carrier
            float placed[3];
            if (PlayerProbe::CarriedPlacement(followID, placed, rot)) {
                std::copy(std::begin(placed), std::end(placed), std::begin(cur));
                haveRot = true;
            } else {
                std::copy(std::begin(aim), std::end(aim), std::begin(cur));
                haveRot = PlayerProbe::PartnerRotation(rot);
            }
        }
        if (SoldierWarp::Warp(followID, cur[0], cur[1], cur[2], false, haveRot ? rot : nullptr) < 0) {
            havePos = false; // recapture on next frame
        }
    }

    uint32_t FollowedID() { return followID; }

    double FollowedFor() { return followID == noBody ? 0.0 : Now() - followStart; }

    void PlaceAttached() {
        if (followID == noBody || !attached || PlayerProbe::LocalCarryTarget() == followID) {
            return;
        }
        alignas(16) float rot[4];
        float placed[3];
        bool haveRot = PlayerProbe::CarriedPlacement(followID, placed, rot);
        if (!haveRot) {
            static double nextLog = 0;
            if (Now() > nextLog) {
                nextLog = Now() + 1.0;
                spdlog::info("BodyFollow, no carry offset from partner for soldier {}, holding it at partner's feet", followID);
            }
            auto carrier = DynamiteCore::GetPlayerPosition(g_hook->cfg.Host ? 1 : 0);
            if (!carrier.Valid()) {
                return;
            }
            placed[0] = carrier.x;
            placed[1] = carrier.y;
            placed[2] = carrier.z;
            haveRot = PlayerProbe::PartnerRotation(rot);
        }
        std::copy(std::begin(placed), std::end(placed), std::begin(cur));
        havePos = true;
        SoldierWarp::Warp(followID, placed[0], placed[1], placed[2], false, haveRot ? rot : nullptr);
    }

    void SetAttached(const bool a) {
        if (followID == noBody) {
            return;
        }
        if (a != attached) {
            spdlog::info("BodyFollow, soldier {} {}", followID, a ? "attached to carrier" : "detached");
        }
        attached = a;
    }

    void Reset() {
        attached = false;
        followID = noBody;
        havePos = false;
    }
}
