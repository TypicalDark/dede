// SPDX-License-Identifier: Apache-2.0
#include "dede/macro/macro_engine.hpp"

#include <algorithm>

namespace dede {

const char* to_string(RunPointType t) noexcept {
    switch (t) {
        case RunPointType::Address: return "address";
        case RunPointType::InstrCount: return "instr-count";
        case RunPointType::MemRead: return "mem-read";
        case RunPointType::MemWrite: return "mem-write";
        case RunPointType::WrittenThenExec: return "written-then-exec";
        case RunPointType::Condition: return "condition";
        case RunPointType::Syscall: return "syscall";
        case RunPointType::Fault: return "fault";
    }
    return "?";
}

u64 MacroEngine::add_run_point(RunPoint rp) {
    rp.id = next_id_++;
    u64 id = rp.id;
    points_.push_back(std::move(rp));
    return id;
}

bool MacroEngine::remove_run_point(u64 id) {
    auto n = points_.size();
    points_.erase(std::remove_if(points_.begin(), points_.end(),
                                 [&](const RunPoint& p) { return p.id == id; }),
                  points_.end());
    return points_.size() != n;
}

bool MacroEngine::set_enabled(u64 id, bool on) {
    if (RunPoint* p = find(id)) {
        p->enabled = on;
        return true;
    }
    return false;
}

RunPoint* MacroEngine::find(u64 id) {
    for (auto& p : points_) {
        if (p.id == id) return &p;
    }
    return nullptr;
}

bool MacroEngine::matches(const RunPoint& rp, const Event& e) const {
    switch (rp.type) {
        case RunPointType::Address:
            return e.kind == EventKind::Step && e.address == rp.address;
        case RunPointType::InstrCount:
            return e.kind == EventKind::Step && e.tick == rp.count;
        // A watchpoint fires when the access RANGE covers the watched address, so a
        // multi-byte write that straddles it is not missed.
        case RunPointType::MemRead:
            return e.kind == EventKind::MemRead &&
                   rp.address >= e.address && rp.address < e.address + (e.size ? e.size : 1);
        case RunPointType::MemWrite:
            return e.kind == EventKind::MemWrite &&
                   rp.address >= e.address && rp.address < e.address + (e.size ? e.size : 1);
        case RunPointType::WrittenThenExec:
            return e.kind == EventKind::ExecWrittenPage;
        case RunPointType::Condition:
            return e.kind == EventKind::Step && ctrl_ && rp.condition &&
                   rp.condition->evaluate(*ctrl_);
        case RunPointType::Syscall:
            // rp.address reused as an optional syscall-number filter (0 = any).
            return e.kind == EventKind::Syscall && (rp.address == 0 || e.value == rp.address);
        case RunPointType::Fault:
            // Break-on-exception: any CPU fault / malformed-instruction / bad-access.
            return e.kind == EventKind::Fault;
    }
    return false;
}

void MacroEngine::on_event(const Event& e) {
    if (firing_) return;  // never match an event produced while a macro runs
    for (const auto& rp : points_) {
        if (rp.enabled && matches(rp, e)) pending_ids_.push_back(rp.id);
    }
}

void MacroEngine::fire_pending() {
    if (pending_ids_.empty()) return;
    std::vector<u64> ids;
    ids.swap(pending_ids_);
    firing_ = true;
    for (u64 id : ids) {
        RunPoint* rp = find(id);  // by id: safe even if a macro edited the set
        if (!rp || !rp->enabled) continue;
        ++rp->hit_count;
        if (rp->macro && ctrl_) rp->macro->run(*ctrl_);
        if (rp->pause) stop_requested_ = true;
    }
    firing_ = false;
}

MacroPtr MacroEngine::stop_recording(std::string name) {
    auto m = std::make_shared<Macro>();
    m->name = std::move(name);
    m->commands = std::move(recorded_);
    for (const auto& cmd : m->commands) {
        if (cmd->mutating()) {
            m->mutating = true;
            break;
        }
    }
    recorded_.clear();
    recording_ = false;
    return m;
}

}  // namespace dede
