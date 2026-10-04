// SPDX-License-Identifier: Apache-2.0
//
// The presenter's read-model (MVP). Panels read ONLY from a UiModel, refreshed
// once per frame, so they never make ordering-sensitive engine calls mid-frame.
// A TraceRing (an Observer on the engine) keeps a tick-indexed event history that
// survives time-travel (seek mutes the core's observers, so the UI keeps its own).
#pragma once

#include <array>
#include <deque>
#include <string>
#include <vector>

#include "dede/core/event.hpp"
#include "dede/macro/event_bus.hpp"
#include "dede/session/engine.hpp"

namespace dede::gui {

// Observer that accumulates a bounded event trace for the UI.
class TraceRing final : public IEventObserver {
public:
    explicit TraceRing(std::size_t cap = 8192) : cap_(cap) {}
    void on_event(const Event& e) override {
        ev_.push_back(e);
        if (ev_.size() > cap_) ev_.pop_front();
    }
    const std::deque<Event>& events() const { return ev_; }
    void clear() { ev_.clear(); }

private:
    std::size_t cap_;
    std::deque<Event> ev_;
};

// A once-per-frame snapshot of everything the panels display.
struct UiModel {
    std::array<u64, kNumReg> regs{};
    std::array<u64, kNumReg> prev_regs{};  // for change-highlighting
    Addr rip = 0;
    u64 rflags = 0;
    Tick now = 0;
    IAnalysisEngine::TimelineStats timeline{};
    std::string phase;
    std::string backend;
    bool transparency = false;

    // Refresh from the engine. Call once at the top of each frame.
    void refresh(const IAnalysisEngine& e) {
        prev_regs = regs;
        for (int i = 0; i < static_cast<int>(kNumReg); ++i)
            regs[i] = e.read_reg(static_cast<Reg>(i));
        rip = e.rip();
        rflags = e.rflags();
        now = e.now();
        timeline = e.timeline_stats();
        phase = e.phase_name();
        backend = e.backend_name();
        transparency = e.transparency_enabled();
    }

    bool reg_changed(Reg r) const {
        auto i = static_cast<std::size_t>(r);
        return regs[i] != prev_regs[i];
    }
};

}  // namespace dede::gui
