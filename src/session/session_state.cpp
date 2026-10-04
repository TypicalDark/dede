// SPDX-License-Identifier: Apache-2.0
#include "dede/session/session_state.hpp"

namespace dede {

const char* to_string(Phase p) noexcept {
    switch (p) {
        case Phase::Idle: return "idle";
        case Phase::Paused: return "paused";
        case Phase::Running: return "running";
        case Phase::Recording: return "recording";
        case Phase::Replaying: return "replaying";
    }
    return "?";
}

namespace {

template <Phase P, bool Step, bool Mutate, bool Rec>
class StateImpl final : public ISessionState {
public:
    Phase phase() const override { return P; }
    bool can_step() const override { return Step; }
    bool can_mutate() const override { return Mutate; }
    bool can_record_start() const override { return Rec; }
};

//                              phase             step   mutate record-start
StateImpl<Phase::Idle,      false, false, false> kIdle;
StateImpl<Phase::Paused,    true,  true,  true>  kPaused;
StateImpl<Phase::Running,   true,  true,  false> kRunning;
StateImpl<Phase::Recording, true,  true,  false> kRecording;
StateImpl<Phase::Replaying, false, false, false> kReplaying;

}  // namespace

const ISessionState& session_state(Phase p) {
    switch (p) {
        case Phase::Idle: return kIdle;
        case Phase::Paused: return kPaused;
        case Phase::Running: return kRunning;
        case Phase::Recording: return kRecording;
        case Phase::Replaying: return kReplaying;
    }
    return kIdle;
}

}  // namespace dede
