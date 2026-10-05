// SPDX-License-Identifier: Apache-2.0
//
// The command bus — git-tool's kernel/commands.js. Runs a registered command's
// handler (after checking its `when` enablement), records a small history, and
// is what the toolbar, keybindings, and command palette all dispatch through.
#pragma once

#include <string>
#include <vector>

namespace dede::ui {

class Registry;
struct Services;

class CommandBus {
public:
    explicit CommandBus(const Registry& reg) : reg_(reg) {}

    // Returns true if the command existed and was enabled (and so ran).
    bool execute(const std::string& id, Services& s, const std::string& arg = "");

    const std::vector<std::string>& history() const { return history_; }

private:
    const Registry& reg_;
    std::vector<std::string> history_;
};

}  // namespace dede::ui
