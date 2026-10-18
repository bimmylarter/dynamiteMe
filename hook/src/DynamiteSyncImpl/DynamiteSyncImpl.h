#ifndef HOOK_DYNAMITESYNCIMPL_H
#define HOOK_DYNAMITESYNCIMPL_H

#include "BossQuietNextActionTaskActionCondition.h"
#include "DynamiteSyncSchema_generated.h"
#include "Tpp/BossQuietActionCommand.h"
#include "Tpp/BossQuietActionControllerImplWork.h"
#include "Tpp/BossQuietActionTask.h"
#include "Tpp/BossQuietDamage.h"
#include "Tpp/TppTypes.h"

#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

const char DYNAMITE_RAW_HEADER[8] = {68, 89, 78, 65, 77, 73, 84, 69}; // DYNAMITE

namespace Dynamite {
    // Body position received from partner, applied later on the Lua (game) thread.
    struct BodyUpdate {
        uint32_t objectID;
        float x;
        float y;
        float z;
        float rotY;
        bool dropped;
    };

    // Carry animation request received from partner (see CarryMotion in schema), applied on the game thread.
    struct CarryMotionUpdate {
        bool body; // false: partner's character, true: the soldier partner carries
        uint32_t objectID;
        uint32_t layer;
        uint64_t state;
        float blend;
        int32_t flags;
    };

    class DynamiteSyncImpl {
      public:
        DynamiteSyncImpl();
        ~DynamiteSyncImpl();

        void Init();
        void Stop();
        void SyncInit();
        void WaitForSync();
        bool IsSynchronized();

        [[deprecated("use SteamUDPSocket")]] void CreateGameSocket();
        [[deprecated("use SteamUDPSocket")]] void RemoveGameSocket();
        void *gameSocket = nullptr;
        [[deprecated("use SendRaw")]] bool Send(const flatbuffers::FlatBufferBuilder *builder) const;

        bool SendRaw(const flatbuffers::FlatBufferBuilder *builder) const;
        bool RecvRaw(void *buffer, int32_t size);

        void Ping();

        void RequestVar(const std::string &catName, const std::string &varName);
        void HandleRequestVar(const DynamiteMessage::MessageWrapper *w);

        void AddFixedUserMarker(const Vector3 *pos);
        static void HandleAddFixedUserMarker(const DynamiteMessage::MessageWrapper *w);

        void AddFollowUserMarker(const Vector3 *pos, uint32_t objectID);
        static void HandleAddFollowUserMarker(const DynamiteMessage::MessageWrapper *w);

        void RemoveUserMarker(uint32_t markerID);
        static void HandleRemoveUserMarker(const DynamiteMessage::MessageWrapper *w);

        void SetSightMarker(uint32_t objectID, uint32_t duration);
        static void HandleSetSightMarker(const DynamiteMessage::MessageWrapper *w);

        void SendEmblem();
        static void HandleSendEmblem(const DynamiteMessage::MessageWrapper *w);

        void SyncVar(const std::string &catName, const std::string &varName);
        void HandleSyncVar(const DynamiteMessage::MessageWrapper *w);

        // todo replace with template?
        static bool SyncBoolVar(const DynamiteMessage::SyncVar *m, void *vars, uint32_t varIndex);
        static bool SyncInt32Var(const DynamiteMessage::SyncVar *m, void *vars, uint32_t varIndex);
        static bool SyncUint32Var(const DynamiteMessage::SyncVar *m, void *vars, uint32_t varIndex);
        static bool SyncInt16Var(const DynamiteMessage::SyncVar *m, void *vars, uint32_t varIndex);
        static bool SyncUint16Var(const DynamiteMessage::SyncVar *m, void *vars, uint32_t varIndex);
        static bool SyncInt8Var(const DynamiteMessage::SyncVar *m, void *vars, uint32_t varIndex);
        static bool SyncUint8Var(const DynamiteMessage::SyncVar *m, void *vars, uint32_t varIndex);
        static bool SyncFloatVar(const DynamiteMessage::SyncVar *m, void *vars, uint32_t varIndex);

        void SyncEnemyVars();

        void SendBossquietActionCommand(uint32_t p1, BossQuietActionCommand *command);
        static void HandleSendBossQuietActionCommand(const DynamiteMessage::MessageWrapper *w);

        void SendBossquietExtraActionCommand(uint32_t p1, BossQuietActionCommand *command);
        static void HandleSendBossQuietExtraActionCommand(const DynamiteMessage::MessageWrapper *w);

        void SendBossquietSetNextActionTask(
            uint32_t param_1, BossQuietActionTask *actionTask, BossQuietNextActionTaskActionCondition actionCondition);
        static void HandleSendBossquietSetNextActionTask(const DynamiteMessage::MessageWrapper *w);

        void SendBossquietSetActionTask(uint32_t param_1, BossQuietActionTask *task);
        static void HandleSendBossquietSetActionTask(const DynamiteMessage::MessageWrapper *w);

        void SendBossQuietDamage(BossQuietDamage *damage);
        void HandleSendBossQuietDamage(const DynamiteMessage::MessageWrapper *w);

        // Body (carried / dropped NPC) sync.
        // Packets arrive on the network thread, so updates are queued and drained from Lua.
        void SendBodyPosition(uint32_t objectID, const Vector3 *pos, float rotY, bool dropped);
        void HandleBodyPosition(const DynamiteMessage::MessageWrapper *w);
        std::optional<BodyUpdate> PopBodyUpdate();
        void ClearBodyUpdates();

        // Carry animation sync, queued like body updates
        void SendCarryMotion(const CarryMotionUpdate &m);
        void HandleCarryMotion(const DynamiteMessage::MessageWrapper *w);
        std::optional<CarryMotionUpdate> PopCarryMotion();

        // Carried soldier transform relative to the carrier: latest received value per sender
        void SendCarryOffset(uint32_t objectID, const float offset[3], const float rot[4]);
        void HandleCarryOffset(const DynamiteMessage::MessageWrapper *w);
        bool GetCarryOffset(uint32_t objectID, float offset[3], float rot[4], double maxAgeSeconds);

        void *steamUDPAddress = nullptr;
        void *steamUDPSocketInfo = nullptr;
        void *steamUDPSocket = nullptr;

        char updateBuffer[1024];
        uint32_t packetNumber = 0;
        uint32_t packetSeen = 0;
        std::jthread syncThread;
        std::map<std::string, bool> syncStatus{};

        std::mutex bodyMutex;
        std::deque<BodyUpdate> bodyUpdates{};
        static constexpr size_t maxBodyUpdates = 256;
        std::deque<CarryMotionUpdate> carryMotions{};
        uint32_t carryOffsetID = 0xffffffff;
        float carryOffset[3]{};
        float carryOffsetRot[4]{};
        uint64_t carryOffsetTick = 0;
        std::vector<std::string> enemyVars = {
            // "cpNames",
            // "cpFlags",
            // "solName",
            // "solState",
            // "solFlagAndStance",
            // "solWeapon",
            // "solLocation",
            // "solMarker",
            "solFovaSeed",
            "solFaceFova",
            "solBodyFova",
            // "solCp",
            // "solCpRoute",
            // "solScriptSneakRoute",
            // "solScriptCautionRoute",
            // "solScriptAlertRoute",
            // "solRouteNodeIndex",
            // "solRouteEventIndex",
            // "solTravelName",
            // "solTravelStepIndex",
            // "solOptName",
            // "solOptParam1",
            // "solOptParam2",
            // "passengerInfoName",
            // "passengerFlagName",
            // "passengerNameName",
            // "passengerVehicleNameName",
            // "noticeObjectType",
            // "noticeObjectPosition",
            // "noticeObjectOwnerName",
            // "noticeObjectOwnerId",
            // "noticeObjectAttachId",
            "solRandomSeed",
            // "hosName",
            // "hosState",
            // "hosFlagAndStance",
            // "hosWeapon",
            // "hosLocation",
            // "hosMarker",
            // "hosFovaSeed",
            // "hosFaceFova",
            // "hosBodyFova",
            // "hosScriptSneakRoute",
            // "hosRouteNodeIndex",
            // "hosRouteEventIndex",
            // "hosOptParam1",
            // "hosOptParam2",
            // "hosRandomSeed",
            // "enemyHeliName",
            // "enemyHeliLocation",
            // "enemyHeliCp",
            // "enemyHeliFlag",
            // "enemyHeliSneakRoute",
            // "enemyHeliCautionRoute",
            // "enemyHeliAlertRoute",
            // "enemyHeliRouteNodeIndex",
            // "enemyHeliRouteEventIndex",
            // "enemyHeliMarker",
            // "enemyHeliLife",
            // "ene_wkrg_name",
            // "ene_wkrg_life",
            // "ene_wkrg_partslife",
            // "ene_wkrg_location",
            // "ene_wkrg_bulletleft",
            // "ene_wkrg_marker",
            // "ene_holdRecoveredStateName",
            // "ene_isRecovered",
            // "ene_holdBrokenStateName",
            // "ene_isVehicleBroken",
            // "liquidLifeStatus",
            // "liquidMarker",
            // "uavName",
            // "uavIsDead",
            // "uavMarker",
            // "uavCp",
            // "uavPatrolRoute",
            // "uavCombatRoute",
            // "securityCameraCp",
            // "securityCameraMarker",
            // "securityCameraFlag",
        };
    };
}

#endif // HOOK_DYNAMITESYNCIMPL_H
