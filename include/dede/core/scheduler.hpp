// SPDX-License-Identifier: Apache-2.0
//
// Deterministic multi-context scheduler (Batch 9, T9.5/T9.6): the rr / WinDbg-TTD
// model. Several execution contexts (threads) share one address space — one
// ExecutionCore's memory — each with its own register file. A cooperative
// scheduler runs ONE context at a time for a fixed instruction quantum, switches
// round-robin at the quantum boundary (or when a context halts/faults), and
// RECORDS the chosen schedule. Because execution is serialized and the schedule
// is recorded, a replay reproduces the exact interleaving bit-for-bit — so
// concurrency is modeled without giving up determinism or time-travel. (dede
// does not run contexts in true parallel on host cores; that is what keeps
// replay exact.) Adding a context models thread creation (CreateThread/clone):
// a new register file with its own stack/TLS over the shared space.
#pragma once

#include <vector>

#include "dede/common/cpu_state.hpp"
#include "dede/core/execution_core.hpp"

namespace dede {

// One recorded scheduling decision: context `ctx` ran `steps` instructions.
struct SchedSegment {
    int ctx = 0;
    u64 steps = 0;
};

class DeterministicScheduler {
public:
    // All contexts share `core`'s address space. `quantum` is the max
    // instructions a context runs before a round-robin switch.
    explicit DeterministicScheduler(ExecutionCore& core, u64 quantum = 8)
        : core_(core), quantum_(quantum) {}

    // Register a context with its initial register file; returns its id.
    int add_context(const CpuState& initial);

    // Run cooperatively until every context has halted/faulted (or the segment
    // cap is hit). Records the schedule. The first-added context runs first.
    void run(u64 max_segments = 1000000);

    // Re-run from the captured initial register files against `restore_point`
    // (a whole-machine snapshot taken before the first run). Returns true iff
    // the replay reproduced the recorded schedule and every context's final
    // register file bit-for-bit.
    bool replay(const StateMemento& restore_point);

    const std::vector<SchedSegment>& schedule() const { return schedule_; }
    int context_count() const { return static_cast<int>(ctxs_.size()); }
    const CpuState& context_cpu(int id) const { return ctxs_.at(static_cast<std::size_t>(id)).cpu; }
    bool halted(int id) const { return ctxs_.at(static_cast<std::size_t>(id)).halted; }
    bool all_halted() const;
    u64 total_steps() const;

private:
    struct Ctx { CpuState initial; CpuState cpu; bool halted = false; };
    // Run until all contexts halt or `max_segments` switches occur (the cap is a
    // runaway backstop); returns the segments produced (for replay compare).
    std::vector<SchedSegment> run_internal(u64 max_segments);

    ExecutionCore& core_;
    u64 quantum_;
    u64 max_segments_ = 1000000;
    std::vector<Ctx> ctxs_;
    std::vector<SchedSegment> schedule_;
};

}  // namespace dede
