// SPDX-License-Identifier: Apache-2.0
#include "dede/ui/commands.hpp"

#include "dede/ui/registry.hpp"
#include "dede/ui/services.hpp"

namespace dede::ui {

bool CommandBus::execute(const std::string& id, Services& s, const std::string& arg) {
    const Command* c = reg_.command(id);
    if (!c || !c->handler) return false;
    if (s.ctx && !evaluate_when(c->when, *s.ctx)) return false;
    c->handler(s, arg);
    history_.push_back(id);
    return true;
}

}  // namespace dede::ui
