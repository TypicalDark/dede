// SPDX-License-Identifier: Apache-2.0
//
// Verifies each tutorial tier behaves exactly as docs/TUTORIAL.md claims, so the
// walkthrough can never drift from the samples.
#include "check.hpp"
#include "dede/samples/tiers.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

namespace {
AnalysisSession load_tier(int n) {
    auto t = samples::make_tier(n);
    AnalysisSession s(Arch::X86_64);
    s.map(0x1000, 0x2000, perm::RWX);
    s.map(0x70000, 0x1000, perm::RW);
    s.core().cpu().set(Reg::Rsp, 0x70800);
    s.load(0x1000, t.image, perm::RWX);
    s.set_entry(0x1000);
    return s;
}
}  // namespace

TEST("tier 1: arithmetic loop sums to 15") {
    auto s = load_tier(1);
    CHECK(s.run().status == StepOutcome::Status::Halted);
    CHECK_EQ(s.read_reg(Reg::Rax), 15u);
}

TEST("tier 2: call doubles rax to 42") {
    auto s = load_tier(2);
    CHECK(s.run().status == StepOutcome::Status::Halted);
    CHECK_EQ(s.read_reg(Reg::Rax), 42u);
}

TEST("tier 3: self-decrypt reveals stage 2 (rax = 0xC0FFEE)") {
    auto s = load_tier(3);
    CHECK(s.disassemble(0x2000, 1)[0].text() != std::string("mov rax, 0xc0ffee"));  // encrypted first
    CHECK(s.run().status == StepOutcome::Status::Halted);
    CHECK_EQ(s.read_reg(Reg::Rax), 0xC0FFEEu);
    CHECK_EQ(s.disassemble(0x2000, 1)[0].mnemonic, std::string("mov"));  // revealed
}

TEST("tier 4: transparency defeats the anti-VM check (rax = 0x600D)") {
    auto s = load_tier(4);
    s.enable_transparency();
    CHECK(s.run().status == StepOutcome::Status::Halted);
    CHECK_EQ(s.read_reg(Reg::Rax), 0x600Du);  // took the 'ok' branch, not 'detected'
}

TEST("tier 5: decrypt + syscall captured + MITM return") {
    auto s = load_tier(5);
    s.capture_enable(true);
    // MITM: forge the syscall return.
    RunPoint rp; rp.type = RunPointType::Syscall;
    u64 id = s.add_run_point(std::move(rp));
    auto m = std::make_shared<Macro>();
    m->mutating = true;
    m->callback = [](IDebugController& c) { c.write_reg(Reg::Rax, 0x1337, "mitm"); };
    s.bind_macro(id, m);
    s.run();
    CHECK_EQ(s.read_reg(Reg::Rdi), 0xC0FFEEu);  // decrypted stage2 ran
    CHECK_EQ(s.read_reg(Reg::Rax), 0x1337u);    // syscall return forged
    bool captured = false;
    for (const auto& e : s.capture_log())
        if (e.kind == CapKind::Syscall) captured = true;
    CHECK(captured);
}

int main() { return dede::test::run_all(); }
