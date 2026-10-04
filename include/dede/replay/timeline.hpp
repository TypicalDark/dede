// SPDX-License-Identifier: Apache-2.0
//
// TimelineManager is the Caretaker of the Memento pattern. It owns execution
// history and decides what to keep:
//   * a ring buffer of fine-grained per-step mementos for the recent past
//     (near-instant step-back, no replay), and
//   * a sparse set of full snapshots at fixed intervals as replay anchors.
// A step-back to an arbitrary tick restores the nearest earlier anchor and
// replays the deterministic core forward to land exactly on the target,
// re-applying injected events from the log as it goes.
//
// The Caretaker never inspects a memento's contents; it only stores one and
// hands it back to the core to restore. All it reads is memento.tick().
#pragma once

#include <cstddef>
#include <deque>
#include <map>
#include <vector>

#include "dede/core/execution_core.hpp"
#include "dede/replay/injected_event.hpp"

namespace dede {

class TimelineManager {
public:
    struct Config {
        std::size_t ring_capacity = 256;      // fine-grained recent history
        std::size_t snapshot_interval = 512;  // full snapshot every N ticks
    };

    TimelineManager(ExecutionCore& core, Config cfg);
    explicit TimelineManager(ExecutionCore& core) : TimelineManager(core, Config{}) {}

    // Capture the initial (tick 0) state. Call once after loading the target and
    // before the first step.
    void begin();

    // Step the live core forward one instruction and record history. Returns the
    // core's outcome. Does not fire macros — the Facade does that between the
    // step and this call's recording is taken afterwards via record().
    StepOutcome step_forward();

    // Record the current core state into the timeline (used by the Facade after
    // macros have run so the memento reflects their mutations).
    void record();

    // Log a mutation so replay can reproduce it without re-running the macro.
    void inject(InjectedEvent ev);

    // Replace the memento stored for the current tick (used after a manual edit
    // at the live frontier so the ring reflects the new state immediately).
    void amend();

    // Editing the past forks the timeline: drop all recorded history, anchors,
    // and injected events strictly after tick `t`.
    void truncate_after(Tick t);

    // Move the core to an absolute tick. Backwards within the explored timeline
    // is silent (observers muted); forward beyond the furthest explored tick
    // executes live.
    Result<void> seek(Tick target);

    // Convenience: step back `n` instructions from the current tick.
    Result<void> step_back(Tick n = 1);

    Tick now() const { return core_.tick(); }
    Tick max_tick() const { return max_tick_; }

    // Introspection for the shell's `timeline` command.
    std::size_t ring_size() const { return ring_.size(); }
    std::size_t snapshot_count() const { return snapshots_.size(); }
    std::size_t injected_count() const { return injected_.size(); }
    const std::vector<InjectedEvent>& injected_log() const { return injected_; }

private:
    const StateMemento* ring_lookup(Tick t) const;
    Result<void> restore_to(Tick target);  // silent backward/within-timeline
    void apply_injected(Tick t);

    ExecutionCore& core_;
    Config cfg_;
    std::deque<StateMemento> ring_;        // contiguous recent mementos
    std::map<Tick, StateMemento> snapshots_;  // sparse anchors, tick-keyed
    std::vector<InjectedEvent> injected_;  // sorted by tick (append-only here)
    Tick max_tick_ = 0;
};

}  // namespace dede
