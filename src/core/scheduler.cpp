// SPDX-License-Identifier: Apache-2.0
#include "dede/core/scheduler.hpp"

namespace dede {

int DeterministicScheduler::add_context(const CpuState& initial) {
    ctxs_.push_back({initial, initial, false});
    return static_cast<int>(ctxs_.size()) - 1;
}

bool DeterministicScheduler::all_halted() const {
    for (const auto& c : ctxs_)
        if (!c.halted) return false;
    return true;
}

u64 DeterministicScheduler::total_steps() const {
    u64 n = 0;
    for (const auto& s : schedule_) n += s.steps;
    return n;
}

std::vector<SchedSegment> DeterministicScheduler::run_internal() {
    std::vector<SchedSegment> seg;
    if (ctxs_.empty()) return seg;
    std::size_t cur = 0;
    u64 guard = 0;
    const u64 kCap = 1000000;
    while (!all_halted() && guard++ < kCap) {
        // find the next runnable context, round-robin from `cur`
        std::size_t start = cur;
        while (ctxs_[cur].halted) {
            cur = (cur + 1) % ctxs_.size();
            if (cur == start) return seg;  // all halted
        }
        Ctx& c = ctxs_[cur];
        core_.cpu() = c.cpu;              // swap this context in over the shared memory
        u64 ran = 0;
        for (u64 q = 0; q < quantum_; ++q) {
            StepOutcome o = core_.step();
            ++ran;
            if (o.status != StepOutcome::Status::Ok) { c.halted = true; break; }
        }
        c.cpu = core_.cpu();              // save its register file back
        seg.push_back({static_cast<int>(cur), ran});
        cur = (cur + 1) % ctxs_.size();   // round-robin switch
    }
    return seg;
}

void DeterministicScheduler::run(u64 /*max_segments*/) {
    for (auto& c : ctxs_) { c.cpu = c.initial; c.halted = false; }
    schedule_ = run_internal();
}

bool DeterministicScheduler::replay(const StateMemento& restore_point) {
    // snapshot the recorded outcome to compare against
    std::vector<CpuState> recorded_final;
    for (const auto& c : ctxs_) recorded_final.push_back(c.cpu);
    std::vector<SchedSegment> recorded = schedule_;

    core_.restore(restore_point);         // reset the shared address space
    for (auto& c : ctxs_) { c.cpu = c.initial; c.halted = false; }
    auto seg = run_internal();

    if (seg.size() != recorded.size()) return false;
    for (std::size_t i = 0; i < seg.size(); ++i)
        if (seg[i].ctx != recorded[i].ctx || seg[i].steps != recorded[i].steps) return false;
    for (std::size_t i = 0; i < ctxs_.size(); ++i)
        if (!(ctxs_[i].cpu == recorded_final[i])) return false;
    return true;
}

}  // namespace dede
