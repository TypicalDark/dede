// SPDX-License-Identifier: Apache-2.0
//
// Heap allocation tracking by hooking malloc/free (via the run-point/macro
// system) and recording every alloc/free with its tick. Because the live set is
// *reconstructed* from the tick-stamped event list rather than accumulated into
// mutable state, a query is correct at ANY tick reached by time-travel: step
// back before a free and the block reads live again. Detects leaks (still live
// at the end), double-frees, and frees of never-allocated pointers.
#pragma once

#include <algorithm>
#include <vector>

#include "dede/common/types.hpp"
#include "dede/macro/controller.hpp"

namespace dede {

class AllocationTracker {
public:
    struct Block { Addr ptr; u64 size; Tick since; };

    // Bind these to run-point macros: malloc entry (reads the requested size from
    // rdi), the malloc `ret` instruction (reads the returned pointer from rax),
    // and free entry (reads the freed pointer from rdi).
    void on_malloc_entry(IDebugController& c) { pending_size_ = c.read_reg(Reg::Rdi); }
    void on_malloc_return(IDebugController& c) {
        ev_.push_back({c.now(), c.read_reg(Reg::Rax), pending_size_, false});
    }
    void on_free_entry(IDebugController& c) {
        Addr p = c.read_reg(Reg::Rdi);
        bool live = false;
        for (const auto& b : live_at(c.now())) if (b.ptr == p) { live = true; break; }
        if (!live) {
            bool ever = false;
            for (const auto& e : ev_) if (!e.is_free && e.ptr == p) { ever = true; break; }
            (ever ? double_free_ : unknown_free_) = true;  // freed twice, or never allocated
        }
        ev_.push_back({c.now(), p, 0, true});
    }

    // Blocks live at tick `t`, reconstructed from the event list (time-travel-correct).
    std::vector<Block> live_at(Tick t) const {
        std::vector<Ev> es = ev_;
        std::sort(es.begin(), es.end(), [](const Ev& a, const Ev& b) { return a.tick < b.tick; });
        std::vector<Block> live;
        for (const auto& e : es) {
            if (e.tick > t) break;
            if (!e.is_free) live.push_back({e.ptr, e.size, e.tick});
            else live.erase(std::remove_if(live.begin(), live.end(),
                                           [&](const Block& b) { return b.ptr == e.ptr; }),
                            live.end());
        }
        return live;
    }
    std::vector<Block> leaks() const { return live_at(latest_tick()); }  // still live at the end
    std::size_t peak_live() const {
        std::vector<Ev> es = ev_;
        std::sort(es.begin(), es.end(), [](const Ev& a, const Ev& b) { return a.tick < b.tick; });
        std::size_t cur = 0, peak = 0;
        for (const auto& e : es) {
            if (!e.is_free) { ++cur; peak = std::max(peak, cur); }
            else if (cur) --cur;
        }
        return peak;
    }
    bool double_free() const { return double_free_; }
    bool unknown_free() const { return unknown_free_; }
    std::size_t event_count() const { return ev_.size(); }

private:
    struct Ev { Tick tick; Addr ptr; u64 size; bool is_free; };
    Tick latest_tick() const {
        Tick t = 0;
        for (const auto& e : ev_) t = std::max(t, e.tick);
        return t;
    }
    std::vector<Ev> ev_;
    u64 pending_size_ = 0;
    bool double_free_ = false, unknown_free_ = false;
};

}  // namespace dede
