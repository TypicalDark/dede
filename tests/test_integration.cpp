// SPDX-License-Identifier: Apache-2.0
//
// End-to-end tests that exercise the whole stack through the Facade: the
// decrypt/reveal/mutating-macro/time-travel scenario the design is built around,
// and the transparency layer forging a clean environment during real execution.
#include <vector>

#include "check.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

namespace {
constexpr Addr kStub = 0x1000;
constexpr Addr kStage2 = 0x2000;

const std::vector<u8> kDecryptStub = {
    0x48, 0xBE, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rsi, 0x2000
    0x48, 0xC7, 0xC1, 0x08, 0x00, 0x00, 0x00,                    // mov rcx, 8
    0x8A, 0x06, 0x34, 0x5A, 0x88, 0x06,                          // mov al,[rsi];xor al,0x5A;mov [rsi],al
    0x48, 0xFF, 0xC6, 0x48, 0xFF, 0xC9, 0x75, 0xF2,              // inc rsi; dec rcx; jnz loop
    0xE9, 0xDC, 0x0F, 0x00, 0x00};                               // jmp 0x2000

std::vector<u8> enc(std::vector<u8> v) {
    for (auto& b : v) b ^= 0x5A;
    return v;
}
}  // namespace

TEST("decrypt, reveal, mutate via macro, and reproduce on replay") {
    SessionDeps d;
    d.timeline.ring_capacity = 4;      // force snapshot-based replay later
    d.timeline.snapshot_interval = 8;
    AnalysisSession s(Arch::X86_64, std::move(d));
    s.map(0x1000, 0x2000, perm::RWX);
    s.map(0x70000, 0x1000, perm::RW);
    s.core().cpu().set(Reg::Rsp, 0x70800);
    s.load(kStub, kDecryptStub, perm::RWX);
    s.load(kStage2, enc({0x48, 0xC7, 0xC0, 0xEE, 0xFF, 0xC0, 0x00, 0xF4}), perm::RWX);  // mov rax,0xC0FFEE; hlt
    s.set_entry(kStub);

    // Before running, stage 2 does not decode to our plaintext.
    CHECK(s.disassemble(kStage2, 1)[0].text() != std::string("mov rax, 0xc0ffee"));

    // Run point at the revealed address, with a mutating macro that patches it.
    RunPoint rp;
    rp.type = RunPointType::Address;
    rp.address = kStage2;
    u64 id = s.add_run_point(std::move(rp));
    auto macro = std::make_shared<Macro>();
    macro->mutating = true;
    macro->callback = [](IDebugController& c) {
        c.write_bytes(kStage2, {0x48, 0xC7, 0xC0, 0x0D, 0xD0, 0x00, 0x00}, "fixup");  // mov rax,0xD00D
    };
    s.bind_macro(id, macro);

    StepOutcome o = s.run();
    CHECK(o.status == StepOutcome::Status::Halted);
    CHECK_EQ(s.read_reg(Reg::Rax), 0xD00Du);  // the mutating macro took effect
    // Stage 2 now decodes as real code.
    CHECK_EQ(s.disassemble(kStage2, 1)[0].mnemonic, std::string("mov"));

    Tick end = s.now();
    // Rewind to the start: stage 2 is encrypted again, rax reset.
    CHECK(s.seek(0).ok());
    CHECK_EQ(s.read_reg(Reg::Rax), 0u);

    // Replay forward from a sparse anchor; the injected patch is re-applied
    // WITHOUT re-running the macro, so the run is reproduced exactly.
    CHECK(s.seek(end).ok());
    CHECK_EQ(s.read_reg(Reg::Rax), 0xD00Du);
}

TEST("transparency forges cpuid during real execution") {
    AnalysisSession s(Arch::X86_64);
    ForgedEnvironment env;
    env.leaf1_ecx = 0x12345678;  // distinctive, hypervisor bit (31) clear
    s.enable_transparency(env);

    s.map(0x1000, 0x1000, perm::RWX);
    // mov eax, 1 ; cpuid ; hlt
    s.load(0x1000, {0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0xA2, 0xF4}, perm::RWX);
    s.set_entry(0x1000);
    s.run();

    CHECK_EQ(s.read_reg(Reg::Rcx) & 0xffffffffu, 0x12345678u);  // forged ecx propagated
    CHECK_EQ((s.read_reg(Reg::Rcx) >> 31) & 1u, 0u);            // no hypervisor bit
}

int main() { return dede::test::run_all(); }
