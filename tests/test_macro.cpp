// SPDX-License-Identifier: Apache-2.0
#include <functional>
#include <vector>

#include "check.hpp"
#include "dede/macro/command.hpp"
#include "dede/macro/condition.hpp"
#include "dede/session/alloc_tracker.hpp"
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

TEST("fault run point catches a CPU exception (break on exception)") {
    // A single `add [rax], al` with rax=0 -> write to the unmapped address 0 faults.
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, {0x00, 0x00}, perm::RWX);  // add byte ptr [rax], al
    s.set_entry(0x1000);

    RunPoint rp;
    rp.type = RunPointType::Fault;
    rp.pause = true;
    u64 id = s.add_run_point(std::move(rp));

    StepOutcome o = s.run();
    CHECK(o.status == StepOutcome::Status::Fault);   // execution broke on the fault
    CHECK(s.run_points()[0].hit_count >= 1);         // the fault run point fired
    // The fault is a recorded event, so the break is time-travel visible.
    bool saw_fault = false;
    for (const auto& e : s.history().events())
        if (e.kind == EventKind::Fault) saw_fault = true;
    CHECK(saw_fault);
    CHECK(s.remove_run_point(id));
}

TEST("fault handler macro fires on the exception") {
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, {0x00, 0x00}, perm::RWX);
    s.set_entry(0x1000);

    RunPoint rp;
    rp.type = RunPointType::Fault;
    u64 id = s.add_run_point(std::move(rp));
    bool handled = false;
    auto m = std::make_shared<Macro>();
    m->name = "on-fault";
    m->callback = [&](IDebugController&) { handled = true; };
    s.bind_macro(id, m);

    s.run();
    CHECK(handled);  // the bound handler ran when the fault was raised
}

TEST("allocation tracker reconstructs a time-travel-correct live set") {
    // r15=0x50000 heap; malloc(0x10)->0x50000; malloc(0x20)->0x50010;
    // free(0x50000); free(0x50000) (double free). 0x50010 leaks.
    // malloc@0x1038: mov rax,r15; add r15,rdi; ret(@0x103e)   free@0x103f: ret
    std::vector<u8> prog = {
        0x49, 0xC7, 0xC7, 0x00, 0x00, 0x05, 0x00,  // 0x1000 mov r15,0x50000
        0x48, 0xC7, 0xC7, 0x10, 0x00, 0x00, 0x00,  // 0x1007 mov rdi,0x10
        0xE8, 0x25, 0x00, 0x00, 0x00,              // 0x100e call 0x1038
        0x48, 0xC7, 0xC7, 0x20, 0x00, 0x00, 0x00,  // 0x1013 mov rdi,0x20
        0xE8, 0x19, 0x00, 0x00, 0x00,              // 0x101a call 0x1038
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x05, 0x00,  // 0x101f mov rdi,0x50000
        0xE8, 0x14, 0x00, 0x00, 0x00,              // 0x1026 call 0x103f
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x05, 0x00,  // 0x102b mov rdi,0x50000
        0xE8, 0x08, 0x00, 0x00, 0x00,              // 0x1032 call 0x103f (double free)
        0xF4,                                      // 0x1037 hlt
        0x4C, 0x89, 0xF8, 0x49, 0x01, 0xFF, 0xC3,  // 0x1038 malloc
        0xC3};                                     // 0x103f free
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, prog, perm::RWX);
    s.map(0x70000, 0x1000, perm::RW);           // a stack for the call instructions
    s.core().cpu().set(Reg::Rsp, 0x70800);
    s.set_entry(0x1000);

    AllocationTracker tr;
    auto hook = [&](Addr a, std::function<void(IDebugController&)> fn) {
        RunPoint rp;
        rp.type = RunPointType::Address;
        rp.address = a;
        rp.pause = false;
        u64 id = s.add_run_point(std::move(rp));
        auto m = std::make_shared<Macro>();
        m->callback = std::move(fn);
        s.bind_macro(id, m);
    };
    hook(0x1038, [&](IDebugController& c) { tr.on_malloc_entry(c); });
    hook(0x103e, [&](IDebugController& c) { tr.on_malloc_return(c); });
    hook(0x103f, [&](IDebugController& c) { tr.on_free_entry(c); });
    s.run();

    CHECK_EQ(tr.peak_live(), 2u);                 // two blocks live at once
    CHECK_EQ(tr.leaks().size(), 1u);              // one block still live at the end
    CHECK_EQ(tr.leaks()[0].ptr, 0x50010u);        // the second malloc leaked
    CHECK(tr.double_free());                      // the repeated free(0x50000) is caught
    CHECK(!tr.unknown_free());                    // every freed pointer was allocated first

    // Time-travel correctness: queried at tick 0 (before any event) the live
    // set is empty, even though the final live set is not.
    CHECK_EQ(tr.live_at(0).size(), 0u);
}

int main() { return dede::test::run_all(); }
