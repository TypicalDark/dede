// SPDX-License-Identifier: Apache-2.0
//
// Dynamic virtual-call resolution: the run-time half of C++ virtual-method
// recovery. A static vtable scan (analysis/recover.hpp) says which code
// pointers *could* be called; this observes which targets an indirect call
// *actually* reaches during a recorded run. Bound to Address run-points placed
// on indirect-call instructions, it computes the branch target from the call's
// operand against live state and records (site, target, tick). Because the
// record is a tick-stamped list, a query is correct at any tick reached by
// time-travel, like AllocationTracker.
//
// This is where dede can beat a purely static tool: an indirect `call rax`
// whose target a static scan cannot prove is resolved here from the value the
// register actually held.
#pragma once

#include <algorithm>
#include <vector>

#include "dede/common/types.hpp"
#include "dede/disasm/instruction.hpp"
#include "dede/macro/controller.hpp"

namespace dede {

class VirtualCallResolver {
public:
    struct Obs { Addr site; Addr target; Tick tick; };

    // Bind to an Address run-point placed on an indirect call. `call` is the
    // decoded instruction at that site; the target is read from its operand
    // (register, or memory [base+index*scale+disp]) against current state.
    void on_indirect_call(IDebugController& c, const DecodedInsn& call) {
        if (call.operands.empty()) return;
        const Operand& op = call.operands[0];
        Addr tgt = 0;
        bool ok = false;
        if (op.kind == OpKind::Reg) {
            tgt = c.read_reg(op.reg);
            ok = true;
        } else if (op.kind == OpKind::Mem) {
            Addr ea = static_cast<Addr>(op.mem.disp);
            if (op.mem.has_base) {
                // rip-relative addressing is computed from the END of the
                // instruction, not its start (which read_reg(Rip) returns here).
                if (op.mem.base == Reg::Rip) ea += call.addr + call.size;
                else ea += c.read_reg(op.mem.base);
            }
            if (op.mem.has_index) ea += c.read_reg(op.mem.index) * op.mem.scale;
            if (auto v = c.read_mem(ea, 8); v.ok()) {
                tgt = static_cast<Addr>(v.value());
                ok = true;
            }
        }
        if (ok) obs_.push_back({call.addr, tgt, c.now()});
    }

    // Distinct targets observed at an indirect-call site, up to tick `t`
    // (defaults to all observations). Time-travel-correct.
    std::vector<Addr> targets_at(Addr site, Tick t = ~Tick{0}) const {
        std::vector<Addr> v;
        for (const auto& o : obs_)
            if (o.site == site && o.tick <= t) v.push_back(o.target);
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
        return v;
    }

    const std::vector<Obs>& observations() const { return obs_; }
    std::size_t count() const { return obs_.size(); }

private:
    std::vector<Obs> obs_;
};

}  // namespace dede
