// SPDX-License-Identifier: Apache-2.0
//
// The reactive UI state — the single source the "Properties follows selection"
// inspector and `when` clauses read, mirroring git-tool's ContextStore. What is
// selected (an instruction, a register, a block, a function, a timeline tick)
// plus a small bag of boolean/string flags for command enablement. Panels read
// it every frame (immediate mode); subscribers are notified on change for the
// few places that need to react.
#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>

#include "dede/common/types.hpp"

namespace dede::ui {

enum class SelKind { None, Insn, Reg, Block, Func, Tick };

struct Selection {
    SelKind kind = SelKind::None;
    Addr addr = 0;      // Insn / Block / Func
    Reg reg = Reg::Rax; // Reg
    Tick tick = 0;      // Tick
};

class Context {
public:
    // --- selection ----------------------------------------------------------
    const Selection& selection() const { return sel_; }
    void select_insn(Addr a) { sel_ = {SelKind::Insn, a, Reg::Rax, 0}; notify({"sel"}); }
    void select_reg(Reg r)   { sel_ = {SelKind::Reg, 0, r, 0}; notify({"sel"}); }
    void select_block(Addr a){ sel_ = {SelKind::Block, a, Reg::Rax, 0}; notify({"sel"}); }
    void select_func(Addr a) { sel_ = {SelKind::Func, a, Reg::Rax, 0}; notify({"sel"}); }
    void select_tick(Tick t) { sel_ = {SelKind::Tick, 0, Reg::Rax, t}; notify({"sel"}); }
    void clear_selection()   { sel_ = {}; notify({"sel"}); }
    bool has_selection() const { return sel_.kind != SelKind::None; }

    // --- flags / strings (for `when` and misc shell state) ------------------
    void set_flag(const std::string& k, bool v) {
        if (flags_[k] != v) { flags_[k] = v; notify({k}); }
    }
    bool flag(const std::string& k) const {
        auto it = flags_.find(k);
        return it != flags_.end() && it->second;
    }
    void set_str(const std::string& k, std::string v) {
        if (strs_[k] != v) { strs_[k] = std::move(v); notify({k}); }
    }
    const std::string& str(const std::string& k) const {
        static const std::string empty;
        auto it = strs_.find(k);
        return it == strs_.end() ? empty : it->second;
    }

    // --- active view / tab --------------------------------------------------
    const std::string& active_view() const { return active_view_; }
    void set_active_view(std::string v) { if (active_view_ != v) { active_view_ = std::move(v); notify({"activeView"}); } }

    // --- subscription -------------------------------------------------------
    using Listener = std::function<void(const std::vector<std::string>&)>;
    int subscribe(Listener fn) { int id = next_++; listeners_[id] = std::move(fn); return id; }
    void unsubscribe(int id) { listeners_.erase(id); }

private:
    void notify(std::vector<std::string> keys) {
        for (auto& [id, fn] : listeners_) fn(keys);
    }

    Selection sel_;
    std::map<std::string, bool> flags_;
    std::map<std::string, std::string> strs_;
    std::string active_view_ = "disassembly";
    std::map<int, Listener> listeners_;
    int next_ = 1;
};

// A tiny `when`-clause evaluator: a flag name, "!flag", or terms joined by
// " && " / " || " (git-tool's evaluateWhen, pared down). Empty => always true.
bool evaluate_when(const std::string& when, const Context& ctx);

}  // namespace dede::ui
