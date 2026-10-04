// SPDX-License-Identifier: Apache-2.0
//
// Time-travel correctness, including the path that matters most: a step-back far
// enough that it cannot use a fine-grained ring memento and must replay forward
// from a sparse snapshot, re-applying injected events.
#include <vector>

#include "check.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

namespace {
// mov rax,0 ; mov rcx,5 ; loop: add rax,rcx ; dec rcx ; jnz loop ; hlt
const std::vector<u8> kLoop = {
    0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC1, 0x05, 0x00, 0x00, 0x00,
    0x48, 0x01, 0xC8, 0x48, 0xFF, 0xC9, 0x75, 0xF8, 0xF4};

AnalysisSession make_session() {
    SessionDeps d;
    d.timeline.ring_capacity = 2;     // tiny, to force snapshot replay
    d.timeline.snapshot_interval = 4;
    AnalysisSession s(Arch::X86_64, std::move(d));
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, kLoop, perm::RWX);
    s.set_entry(0x1000);
    return s;
}
}  // namespace

TEST("run to halt then step back one instruction") {
    auto s = make_session();
    s.run();
    CHECK_EQ(s.read_reg(Reg::Rax), 15u);  // 5+4+3+2+1
    Tick end = s.now();
    CHECK(s.step_back(1).ok());
    CHECK_EQ(s.now(), end - 1);
}

TEST("seek back to 0 and forward reproduces the run via snapshot replay") {
    auto s = make_session();
    s.run();
    Tick end = s.now();
    u64 rax_end = s.read_reg(Reg::Rax);

    CHECK(s.seek(0).ok());
    CHECK_EQ(s.now(), 0u);
    CHECK_EQ(s.read_reg(Reg::Rax), 0u);

    // end is well beyond the 2-entry ring, so this replays from a snapshot anchor.
    CHECK(s.seek(end).ok());
    CHECK_EQ(s.now(), end);
    CHECK_EQ(s.read_reg(Reg::Rax), rax_end);
}

TEST("injected register edit is reproduced on replay") {
    auto s = make_session();
    // Step a few instructions, then edit a register at the live frontier.
    for (int i = 0; i < 4; ++i) s.step();
    Tick t = s.now();
    s.write_reg(Reg::Rbx, 0x99, "manual edit");
    CHECK_EQ(s.read_reg(Reg::Rbx), 0x99u);

    // Travel away and back; the edit must come back from the injected-event log.
    CHECK(s.seek(0).ok());
    CHECK_EQ(s.read_reg(Reg::Rbx), 0u);
    CHECK(s.seek(t).ok());
    CHECK_EQ(s.read_reg(Reg::Rbx), 0x99u);
}

int main() { return dede::test::run_all(); }
