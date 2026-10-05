// SPDX-License-Identifier: Apache-2.0
//
// The contribution registry — dede's port of git-tool's kernel/registry.js. A
// feature is a Manifest that contributes commands, views (panels), toolbar and
// status items, sidebar sections, inspector schemas, and keybindings. The shell
// renders purely from what is registered, so adding a feature is adding one
// module file and registering it; the shell never changes.
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "dede/ui/context.hpp"
#include "dede/ui/painter.hpp"

namespace dede::ui {

struct Services;  // forward (defined in services.hpp)

// A panel/view: drawn immediate-mode into a rect every frame.
struct View {
    std::string type;       // stable id, e.g. "disassembly"
    std::string title;      // tab label
    Color accent = 0;       // tab dot colour (0 = theme default)
    std::function<void(IPainter&, Services&, Rect)> draw;
};

struct Command {
    std::string id;         // "nav.goto", "run.step", ...
    std::string title;      // shown in the palette
    std::string category;   // palette grouping
    std::string when;       // enablement predicate (see evaluate_when)
    std::string key;        // default keybinding, for display
    std::function<void(Services&, const std::string& arg)> handler;
};

struct ToolbarItem {
    std::string command;    // command id to run on click
    std::string segment;    // "nav" | "exec" | "view" | "right"
    std::string icon;       // glyph to draw
    std::string when;       // visibility predicate
    std::string checked;    // when-clause: draw as toggled-on if true
    int order = 0;
};

struct StatusItem {
    std::string id;
    int order = 0;
    std::function<std::string(Services&)> text;
    std::function<Color(Services&)> color;  // nullable -> dim
};

// A collapsible section in the left sidebar; draw() returns the height it used.
struct SidebarSection {
    std::string id;
    std::string title;
    int order = 0;
    std::function<float(IPainter&, Services&, Rect)> draw;
};

// Drives the "Properties follows selection" inspector: the highest-priority
// schema whose match(ctx) is true renders into the inspector body.
struct InspectorSchema {
    std::string kind;
    std::string title;
    int priority = 0;
    std::function<bool(const Context&)> match;
    std::function<void(IPainter&, Services&, Rect)> render;
};

struct Keybinding {
    std::string key;
    std::string command;
    std::string when;
};

struct Manifest {
    std::string id;
    std::vector<Command> commands;
    std::vector<View> views;
    std::vector<ToolbarItem> toolbar;
    std::vector<StatusItem> status;
    std::vector<SidebarSection> sidebar;
    std::vector<InspectorSchema> schemas;
    std::vector<Keybinding> keybindings;
};

class Registry {
public:
    void register_module(Manifest m);

    const Command* command(const std::string& id) const;
    std::vector<const Command*> commands() const;  // sorted by category,title; hidden filtered

    const View* view(const std::string& type) const;
    const std::vector<View>& views() const { return views_; }

    std::vector<const ToolbarItem*> toolbar(const std::string& segment, const Context&) const;
    const std::vector<StatusItem>& status() const { return status_; }
    const std::vector<SidebarSection>& sidebar() const { return sidebar_; }  // order-sorted
    const std::vector<Keybinding>& keybindings() const { return keybindings_; }

    // Highest-priority inspector schema matching the context (nullptr if none).
    const InspectorSchema* pick_schema(const Context& ctx) const;

    // The command bound to a chord under the current context, or nullptr.
    const Keybinding* keybinding_for(const std::string& chord, const Context& ctx) const;
    std::string key_for(const std::string& command_id) const;  // "" if none

    std::size_t module_count() const { return module_ids_.size(); }

private:
    std::vector<std::string> module_ids_;
    std::map<std::string, Command> commands_;
    std::vector<View> views_;
    std::vector<ToolbarItem> toolbar_;
    std::vector<StatusItem> status_;
    std::vector<SidebarSection> sidebar_;
    std::vector<InspectorSchema> schemas_;
    std::vector<Keybinding> keybindings_;
};

}  // namespace dede::ui
