// SPDX-License-Identifier: Apache-2.0
//
// Memento (GoF). A StateMemento is an opaque snapshot of the whole machine:
// the register file plus a copy-on-write memory image plus the retired-
// instruction count. Only the ExecutionCore (the Originator) can read or write
// its internals; the TimelineManager (the Caretaker, in the replay library)
// only ever stores one and hands it back to the core to restore. The one
// accessor exposed, tick(), lets the Caretaker index snapshots on the timeline
// without seeing machine state.
#pragma once

#include "dede/common/cpu_state.hpp"
#include "dede/common/memory.hpp"
#include "dede/common/types.hpp"

namespace dede {

class StateMemento {
public:
    StateMemento() = default;
    Tick tick() const noexcept { return tick_; }

private:
    friend class ExecutionCore;
    CpuState cpu_{};
    MemorySnapshot mem_{};
    Tick tick_ = 0;
};

}  // namespace dede
