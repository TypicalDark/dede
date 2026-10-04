// SPDX-License-Identifier: Apache-2.0
#include <vector>

#include "check.hpp"
#include "dede/macro/command.hpp"
#include "dede/macro/condition.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

namespace {
// mov rax,0 ; mov rcx,3 ; loop: add rax,rcx ; dec rcx ; jnz loop ; hlt
const std::vector<u8> kLoop = {
    0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC1, 0x03, 0x00, 0x00, 0x00,
    0x48, 0x01, 0xC8, 0x48, 0xFF, 0xC9, 0x75, 0xF8, 0xF4};

AnalysisSession loaded() {
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, kLoop, perm::RWX);
    s.set_entry(0x1000);
    return s;
}
}  // namespace

TEST("command execute and undo restore register state") {
    auto s = loaded();
    s.step();  // rax = 0
    auto cmd = std::make_shared<WriteRegCommand>(Reg::Rax, 0x1234);
    CHECK(cmd->execute(s).ok());
    CHECK_EQ(s.read_reg(Reg::Rax), 0x1234u);
    CHECK(cmd->undo(s).ok());
    CHECK_EQ(s.read_reg(Reg::Rax), 0u);
}

TEST("composite command executes children and undoes in reverse") {
    auto s = loaded();
    auto comp = std::make_shared<CompositeCommand>("two writes");
    comp->add(std::make_shared<WriteRegCommand>(Reg::Rax, 1));
    comp->add(std::make_shared<WriteRegCommand>(Reg::Rbx, 2));
    CHECK(comp->execute(s).ok());
    CHECK_EQ(s.read_reg(Reg::Rax), 1u);
    CHECK_EQ(s.read_reg(Reg::Rbx), 2u);
    CHECK(comp->mutating());
    CHECK(comp->undo(s).ok());
    CHECK_EQ(s.read_reg(Reg::Rax), 0u);
    CHECK_EQ(s.read_reg(Reg::Rbx), 0u);
}

TEST("prototype clone yields an independent, unexecuted command") {
    auto orig = std::make_shared<WriteRegCommand>(Reg::Rdx, 0xAA);
    auto copy = orig->clone();
    CHECK_EQ(copy->describe(), orig->describe());
    CHECK(copy.get() != orig.get());
}

TEST("condition interpreter parses and evaluates") {
    auto s = loaded();
    s.write_reg(Reg::Rax, 0x40);
    auto c = Condition::parse("rax == 0x40");
    CHECK(c.has_value());
    CHECK(c->evaluate(s));
    auto c2 = Condition::parse("rax > 0x100");
    CHECK(c2.has_value());
    CHECK(!c2->evaluate(s));
    CHECK(!Condition::parse("garbage").has_value());
}

TEST("address breakpoint pauses a run") {
    auto s = loaded();
    u64 bp = s.add_breakpoint(0x100e);  // the loop body (add rax,rcx)
    s.run();
    CHECK_EQ(s.core().cpu().rip(), 0x100eu);  // stopped at the breakpoint
    CHECK(s.run_points()[0].hit_count >= 1);
    CHECK(s.remove_run_point(bp));
}

TEST("macro bound to a run point fires and mutates") {
    auto s = loaded();
    u64 rp = s.add_breakpoint(0x100e);
    auto m = std::make_shared<Macro>();
    m->name = "zap-rcx";
    m->mutating = true;
    m->callback = [](IDebugController& c) { c.write_reg(Reg::Rcx, 1, "macro zap"); };
    s.bind_macro(rp, m);
    s.run();  // stops at 0x100e with the macro having forced rcx = 1
    CHECK_EQ(s.read_reg(Reg::Rcx), 1u);
}

TEST("recording captures commands into a macro") {
    auto s = loaded();
    s.start_recording();
    CHECK(s.recording());
    s.run_command(std::make_shared<WriteRegCommand>(Reg::Rax, 7));
    s.run_command(std::make_shared<WriteRegCommand>(Reg::Rbx, 8));
    auto macro = s.stop_recording("rec");
    CHECK_EQ(macro->commands.size(), 2u);
    CHECK(macro->mutating);
}

int main() { return dede::test::run_all(); }
