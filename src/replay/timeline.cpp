// SPDX-License-Identifier: Apache-2.0
#include "dede/replay/timeline.hpp"

#include <algorithm>

namespace dede {

TimelineManager::TimelineManager(ExecutionCore& core, Config cfg)
    : core_(core), cfg_(cfg) {}

void TimelineManager::begin() {
    ring_.clear();
    snapshots_.clear();
    max_tick_ = core_.tick();
    record();
}

void TimelineManager::record() {
    Tick t = core_.tick();
    // Idempotent per tick: a non-retiring step (Unsupported/Fault) leaves the tick
    // unchanged, and recording again would put two mementos at the same tick and
    // break the "one contiguous memento per tick" invariant ring_lookup relies on.
    if (!ring_.empty() && ring_.back().tick() == t) return;
    StateMemento m = core_.snapshot();
    ring_.push_back(m);
    if (ring_.size() > cfg_.ring_capacity) ring_.pop_front();
    if (t % cfg_.snapshot_interval == 0) snapshots_[t] = m;  // sparse anchor
    max_tick_ = std::max(max_tick_, t);
}

StepOutcome TimelineManager::step_forward() {
    StepOutcome o = core_.step();
    // Only retired instructions advance the timeline; the Facade records after
    // any macros have run.
    return o;
}

void TimelineManager::inject(InjectedEvent ev) {
    // Keep the log sorted by tick for ordered replay.
    auto it = std::upper_bound(injected_.begin(), injected_.end(), ev,
                               [](const InjectedEvent& a, const InjectedEvent& b) {
                                   return a.tick < b.tick;
                               });
    injected_.insert(it, std::move(ev));
}

void TimelineManager::amend() {
    Tick t = core_.tick();
    StateMemento m = core_.snapshot();
    if (!ring_.empty()) {
        Tick front = ring_.front().tick();
        Tick back = ring_.back().tick();
        if (t >= front && t <= back) {
            std::size_t idx = static_cast<std::size_t>(t - front);
            if (idx < ring_.size() && ring_[idx].tick() == t) ring_[idx] = m;
        }
    }
    if (t % cfg_.snapshot_interval == 0) snapshots_[t] = m;
}

void TimelineManager::truncate_after(Tick t) {
    while (!ring_.empty() && ring_.back().tick() > t) ring_.pop_back();
    for (auto it = snapshots_.upper_bound(t); it != snapshots_.end();) it = snapshots_.erase(it);
    injected_.erase(std::remove_if(injected_.begin(), injected_.end(),
                                   [&](const InjectedEvent& e) { return e.tick > t; }),
                    injected_.end());
    max_tick_ = t;
}

const StateMemento* TimelineManager::ring_lookup(Tick t) const {
    if (ring_.empty()) return nullptr;
    Tick front = ring_.front().tick();
    Tick back = ring_.back().tick();
    if (t < front || t > back) return nullptr;
    // The ring is contiguous in tick, one memento per tick.
    std::size_t idx = static_cast<std::size_t>(t - front);
    if (idx >= ring_.size()) return nullptr;
    const StateMemento& m = ring_[idx];
    return m.tick() == t ? &m : nullptr;
}

void TimelineManager::apply_injected(Tick t) {
    for (const auto& ev : injected_) {
        if (ev.tick != t) continue;
        if (ev.kind == InjectedEvent::Kind::RegWrite) {
            core_.cpu().set(ev.reg, ev.value);
        } else {  // MemWrite
            if (!ev.bytes.empty()) {
                core_.memory().write(ev.addr, ev.bytes);
            } else {
                core_.memory().write_int(ev.addr, ev.size, ev.value);
            }
        }
    }
}

Result<void> TimelineManager::restore_to(Tick target) {
    // Fast path: a fine-grained memento for exactly this tick is in the ring.
    if (const StateMemento* m = ring_lookup(target)) {
        core_.restore(*m);
        return {};
    }
    // Otherwise replay from the nearest earlier snapshot anchor, silently.
    auto it = snapshots_.upper_bound(target);  // first anchor strictly after target
    if (it == snapshots_.begin()) {
        return make_error("timeline: no anchor at or before tick " + std::to_string(target));
    }
    --it;  // largest anchor tick <= target
    IEventSink* saved = core_.event_sink();
    core_.set_event_sink(nullptr);  // mute observers during replay
    core_.restore(it->second);      // anchor already bakes in its own injections
    while (core_.tick() < target) {
        StepOutcome o = core_.step();
        if (o.status != StepOutcome::Status::Ok &&
            o.status != StepOutcome::Status::Halted &&
            o.status != StepOutcome::Status::Breakpoint) {
            core_.set_event_sink(saved);
            return make_error("timeline: replay diverged at tick " + std::to_string(core_.tick()));
        }
        apply_injected(core_.tick());  // re-apply mutations tagged at this tick
    }
    core_.set_event_sink(saved);
    return {};
}

Result<void> TimelineManager::seek(Tick target) {
    Tick cur = core_.tick();
    if (target == cur) return {};

    if (target > max_tick_) {
        // Beyond explored territory: continue live from the furthest point.
        if (cur != max_tick_) {
            if (auto r = restore_to(max_tick_); !r) return r;
        }
        while (core_.tick() < target) {
            StepOutcome o = core_.step();
            record();
            if (o.status != StepOutcome::Status::Ok) {
                return make_error("timeline: forward seek halted at tick " +
                                  std::to_string(core_.tick()));
            }
        }
        return {};
    }

    return restore_to(target);
}

Result<void> TimelineManager::step_back(Tick n) {
    Tick cur = core_.tick();
    if (n > cur) return make_error("timeline: cannot step back past tick 0");
    return seek(cur - n);
}

}  // namespace dede
