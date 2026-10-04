// SPDX-License-Identifier: Apache-2.0
//
// The MacroEngine is an Observer on the event bus. On each event it matches
// enabled run points and *queues* the matches; the Facade fires the queue after
// the step completes, so macros see settled machine state and never run
// mid-instruction. Macros are not fired during replay (replay is silent), which
// is why a mutating macro must have been injected when it first ran.
#pragma once

#include <cstddef>
#include <vector>

#include "dede/macro/event_bus.hpp"
#include "dede/macro/run_point.hpp"

namespace dede {

class MacroEngine final : public IEventObserver {
public:
    void bind_controller(IDebugController* c) { ctrl_ = c; }

    // --- run points ----------------------------------------------------------
    u64 add_run_point(RunPoint rp);
    bool remove_run_point(u64 id);
    bool set_enabled(u64 id, bool on);
    RunPoint* find(u64 id);
    const std::vector<RunPoint>& run_points() const { return points_; }

    // --- observer ------------------------------------------------------------
    void on_event(const Event& e) override;   // match + enqueue
    void fire_pending();                       // run matched macros (post-step)
    bool has_pending() const { return !pending_ids_.empty(); }

    // True (and clears) if a pausing run point fired since the last call — the
    // run loop uses this to stop at breakpoints.
    bool consume_stop() { bool s = stop_requested_; stop_requested_ = false; return s; }

    // --- recording -----------------------------------------------------------
    void start_recording() { recording_ = true; recorded_.clear(); }
    bool recording() const { return recording_; }
    void record_command(CommandPtr cmd) { if (recording_) recorded_.push_back(std::move(cmd)); }
    MacroPtr stop_recording(std::string name);

private:
    bool matches(const RunPoint& rp, const Event& e) const;

    IDebugController* ctrl_ = nullptr;
    std::vector<RunPoint> points_;
    u64 next_id_ = 1;

    std::vector<u64> pending_ids_;  // run points matched this step, fired later
    bool firing_ = false;
    bool stop_requested_ = false;

    bool recording_ = false;
    std::vector<CommandPtr> recorded_;
};

}  // namespace dede
