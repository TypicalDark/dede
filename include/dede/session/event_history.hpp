// SPDX-License-Identifier: Apache-2.0
//
// A bounded ring of recent execution events (an Observer on the bus). It powers
// the shell's `history` view and the signature time-travel query "who last wrote
// this address?" — answered from the recorded write events rather than by
// re-execution.
#pragma once

#include <deque>
#include <optional>

#include "dede/core/event.hpp"
#include "dede/macro/event_bus.hpp"

namespace dede {

class EventHistory final : public IEventObserver {
public:
    explicit EventHistory(std::size_t capacity = 4096) : cap_(capacity) {}

    void on_event(const Event& e) override {
        events_.push_back(e);
        if (events_.size() > cap_) events_.pop_front();
    }

    void clear() { events_.clear(); }
    const std::deque<Event>& events() const { return events_; }
    std::size_t size() const { return events_.size(); }

    // The most recent write whose range covers [addr, addr+size): returns the
    // event (its pc is the writing instruction, its tick is when). nullopt if the
    // write is older than the retained window or never happened.
    std::optional<Event> last_write(Addr addr, unsigned size = 1) const {
        for (auto it = events_.rbegin(); it != events_.rend(); ++it) {
            if (it->kind != EventKind::MemWrite) continue;
            if (addr < it->address + it->size && it->address < addr + size) return *it;
        }
        return std::nullopt;
    }

private:
    std::size_t cap_;
    std::deque<Event> events_;
};

}  // namespace dede
