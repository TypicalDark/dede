// SPDX-License-Identifier: Apache-2.0
#include "dede/ui/registry.hpp"

#include <algorithm>

namespace dede::ui {

void Registry::register_module(Manifest m) {
    module_ids_.push_back(m.id);
    for (auto& c : m.commands) commands_[c.id] = std::move(c);
    for (auto& v : m.views) views_.push_back(std::move(v));
    for (auto& t : m.toolbar) toolbar_.push_back(std::move(t));
    for (auto& s : m.status) status_.push_back(std::move(s));
    for (auto& s : m.sidebar) sidebar_.push_back(std::move(s));
    for (auto& s : m.schemas) schemas_.push_back(std::move(s));
    for (auto& k : m.keybindings) keybindings_.push_back(std::move(k));

    auto by_order = [](const auto& a, const auto& b) { return a.order < b.order; };
    std::stable_sort(toolbar_.begin(), toolbar_.end(), by_order);
    std::stable_sort(status_.begin(), status_.end(), by_order);
    std::stable_sort(sidebar_.begin(), sidebar_.end(), by_order);
    std::stable_sort(schemas_.begin(), schemas_.end(),
                     [](const InspectorSchema& a, const InspectorSchema& b) { return a.priority > b.priority; });
}

const Command* Registry::command(const std::string& id) const {
    auto it = commands_.find(id);
    return it == commands_.end() ? nullptr : &it->second;
}

std::vector<const Command*> Registry::commands() const {
    std::vector<const Command*> out;
    for (auto& [id, c] : commands_) out.push_back(&c);
    std::sort(out.begin(), out.end(), [](const Command* a, const Command* b) {
        if (a->category != b->category) return a->category < b->category;
        return a->title < b->title;
    });
    return out;
}

const View* Registry::view(const std::string& type) const {
    for (auto& v : views_) if (v.type == type) return &v;
    return nullptr;
}

std::vector<const ToolbarItem*> Registry::toolbar(const std::string& segment, const Context& ctx) const {
    std::vector<const ToolbarItem*> out;
    for (auto& t : toolbar_)
        if (t.segment == segment && evaluate_when(t.when, ctx)) out.push_back(&t);
    return out;
}

const InspectorSchema* Registry::pick_schema(const Context& ctx) const {
    for (auto& s : schemas_)  // already sorted by priority desc
        if (s.match && s.match(ctx)) return &s;
    return nullptr;
}

const Keybinding* Registry::keybinding_for(const std::string& chord, const Context& ctx) const {
    for (auto& k : keybindings_)
        if (k.key == chord && evaluate_when(k.when, ctx)) return &k;
    return nullptr;
}

std::string Registry::key_for(const std::string& command_id) const {
    for (auto& k : keybindings_) if (k.command == command_id) return k.key;
    return "";
}

}  // namespace dede::ui
