// SPDX-License-Identifier: Apache-2.0
//
// A run point is a trigger bound to a place or condition in the target's
// execution; a macro is an action bound to a run point. A macro is either a
// recorded list of Commands or an authored callback (e.g. a script function) —
// to the engine they are the same kind of thing.
#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "dede/macro/command.hpp"
#include "dede/macro/condition.hpp"

namespace dede {

struct Macro {
    std::string name;
    // A correctness distinction, not a label: an observing macro only reads state
    // or annotates, so it is safe to run on every replay; a mutating macro
    // changes guest state and so must be captured as injected events.
    bool mutating = false;

    std::vector<CommandPtr> commands;                 // recorded form
    std::function<void(IDebugController&)> callback;   // authored form (script/native)

    void run(IDebugController& c) const {
        for (const auto& cmd : commands) cmd->execute(c);
        if (callback) callback(c);
    }
};
using MacroPtr = std::shared_ptr<Macro>;

enum class RunPointType {
    Address,          // rip reached an address
    InstrCount,       // a given number of instructions retired
    MemRead,          // a data read at an address
    MemWrite,         // a data write at an address
    WrittenThenExec,  // a page written as data is now being executed (W^X)
    Condition,        // a register predicate holds
    Syscall           // guest executed a syscall (optionally a specific number)
};

const char* to_string(RunPointType t) noexcept;

struct RunPoint {
    u64 id = 0;
    RunPointType type = RunPointType::Address;
    bool enabled = true;

    Addr address = 0;                     // Address / MemRead / MemWrite
    Tick count = 0;                       // InstrCount
    std::optional<Condition> condition;   // Condition

    MacroPtr macro;        // optional action; a bare run point is a breakpoint
    bool pause = false;    // stop execution when hit (classic breakpoint)
    u64 hit_count = 0;
    std::string label;
};

}  // namespace dede
