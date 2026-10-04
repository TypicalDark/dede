// SPDX-License-Identifier: Apache-2.0
//
// Observer (GoF). The EventBus is the core's event sink; subscribers (the macro
// engine, the shell's trace view, the decompiler) register here. The core emits
// without knowing who listens.
#pragma once

#include <algorithm>
#include <vector>

#include "dede/core/event.hpp"

namespace dede {

class IEventObserver {
public:
    virtual ~IEventObserver() = default;
    virtual void on_event(const Event& e) = 0;
};

class EventBus final : public IEventSink {
public:
    void subscribe(IEventObserver* o) {
        if (o && std::find(obs_.begin(), obs_.end(), o) == obs_.end()) obs_.push_back(o);
    }
    void unsubscribe(IEventObserver* o) {
        obs_.erase(std::remove(obs_.begin(), obs_.end(), o), obs_.end());
    }
    void emit(const Event& e) override {
        for (auto* o : obs_) o->on_event(e);
    }
    std::size_t observer_count() const noexcept { return obs_.size(); }

private:
    std::vector<IEventObserver*> obs_;
};

}  // namespace dede
