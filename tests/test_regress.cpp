// SPDX-License-Identifier: Apache-2.0
//
// Regression tests for the high-severity bugs the design/perf review surfaced.
#include <vector>

#include "check.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

TEST("one-operand imul computes rdx:rax and does not crash") {
    // mov rax,5 ; mov rcx,7 ; imul rcx ; hlt   (48 F7 E9 = one-operand imul)
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000,
           {0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00,  // mov rax, 5
            0x48, 0xC7, 0xC1, 0x07, 0x00, 0x00, 0x00,  // mov rcx, 7
            0x48, 0xF7, 0xE9,                          // imul rcx
            0xF4},                                     // hlt
           perm::RWX);
    s.set_entry(0x1000);
    CHECK(s.run().status == StepOutcome::Status::Halted);
    CHECK_EQ(s.read_reg(Reg::Rax), 35u);
    CHECK_EQ(s.read_reg(Reg::Rdx), 0u);
}

TEST("an unsupported instruction does not corrupt the step-back ring") {
    // mov al,0x11 ; mov bl,0x22 ; fninit (unmodelled) ; hlt
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, {0xB0, 0x11, 0xB3, 0x22, 0xDB, 0xE3, 0xF4}, perm::RWX);
    s.set_entry(0x1000);
    s.step();  // tick 1: al = 0x11
    s.step();  // tick 2: bl = 0x22
    Tick before = s.now();
    s.step();  // fninit -> Unsupported: tick must NOT advance, ring must not dup
    CHECK_EQ(s.now(), before);
    // Fast step-back must still work (ring intact), landing exactly at tick 1.
    CHECK(s.step_back(1).ok());
    CHECK_EQ(s.now(), 1u);
    CHECK_EQ(s.read_reg(Reg::Rax) & 0xff, 0x11u);
    CHECK_EQ(s.read_reg(Reg::Rbx) & 0xff, 0u);  // bl not yet set at tick 1
}

TEST("forward seek fires run-point macros (no silent skip, no leaked pending)") {
    // nop ; nop ; nop ; hlt, with a mutating macro bound at the 3rd nop.
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, {0x90, 0x90, 0x90, 0xF4}, perm::RWX);
    s.set_entry(0x1000);

    RunPoint rp;
    rp.type = RunPointType::Address;
    rp.address = 0x1002;
    u64 id = s.add_run_point(std::move(rp));
    auto m = std::make_shared<Macro>();
    m->mutating = true;
    m->callback = [](IDebugController& c) { c.write_reg(Reg::Rbx, 0xBEEF, "macro"); };
    s.bind_macro(id, m);

    // Seek forward into unexplored territory: the macro must fire during the seek.
    CHECK(s.seek(3).ok());
    CHECK_EQ(s.read_reg(Reg::Rbx), 0xBEEFu);
    // A following step must not re-fire a leaked pending match.
    u64 hits_before = s.run_points()[0].hit_count;
    s.step();
    CHECK_EQ(s.run_points()[0].hit_count, hits_before);  // 0x1003 != 0x1002
}

int main() { return dede::test::run_all(); }
