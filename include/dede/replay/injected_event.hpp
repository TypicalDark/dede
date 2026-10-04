// SPDX-License-Identifier: Apache-2.0
//
// An injected event is a mutation that was NOT produced by the deterministic
// interpreter itself: a non-deterministic input (a syscall's result bytes), or a
// mutating macro's edit to guest state. It is logged against the tick at which
// it became visible so that replay — which does not re-run macros — reproduces
// the run exactly by re-applying these from the log. This is the rule that keeps
// macros and time-travel consistent.
#pragma once

#include <string>
#include <vector>

#include "dede/common/types.hpp"

namespace dede {

struct InjectedEvent {
    enum class Kind { RegWrite, MemWrite };

    Tick tick = 0;         // the post-step tick at which the mutation is visible
    Kind kind = Kind::RegWrite;

    // RegWrite:
    Reg reg = Reg::Rax;

    // MemWrite:
    Addr addr = 0;
    std::vector<u8> bytes;

    // Shared payload for the register case (and small mem writes):
    unsigned size = 8;
    u64 value = 0;

    std::string note;      // e.g. "decrypt-stub patch" — for the shell's trace view
};

}  // namespace dede
