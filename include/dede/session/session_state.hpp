// SPDX-License-Identifier: Apache-2.0
//
// State (GoF). The session's behaviour varies by phase: you cannot step an Idle
// session (nothing is loaded), cannot start a recording while already Recording,
// and cannot mutate during a Replaying seek. Each phase is a stateless singleton
// answering those questions, so the Facade holds a pointer to the current one
// instead of branching on a mode flag everywhere.
#pragma once

namespace dede {

enum class Phase { Idle, Paused, Running, Recording, Replaying };

const char* to_string(Phase p) noexcept;

class ISessionState {
public:
    virtual ~ISessionState() = default;
    virtual Phase phase() const = 0;
    virtual bool can_step() const = 0;
    virtual bool can_mutate() const = 0;
    virtual bool can_record_start() const = 0;
    const char* name() const { return to_string(phase()); }
};

// The singleton state object for a phase.
const ISessionState& session_state(Phase p);

}  // namespace dede
