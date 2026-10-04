// SPDX-License-Identifier: Apache-2.0
//
// Adversarial tests: each case is a real anti-analysis / VM-detection routine in
// hand-assembled x86-64. With the transparency layer on, every one must come back
// with the "clean bare-metal" answer — i.e. the sample cannot tell it is being
// analysed. These are the checks al-khaser / pafish perform.
#include <vector>

#include "check.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

namespace {

// Run a flat code blob with transparency enabled; return the finished session.
AnalysisSession run_probe(const std::vector<u8>& code) {
    AnalysisSession s(Arch::X86_64);
    s.enable_transparency();
    s.map(0x1000, 0x1000, perm::RWX);
    s.map(0x70000, 0x1000, perm::RW);
    s.core().cpu().set(Reg::Rsp, 0x70800);
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);
    s.run();
    return s;
}

u32 lo32(u64 v) { return static_cast<u32>(v & 0xffffffffu); }

}  // namespace

TEST("cpuid hypervisor-present bit reads clear") {
    // mov eax,1 ; cpuid ; bt ecx,31 ; setc al ; movzx eax,al ; hlt
    auto s = run_probe({0xB8, 0x01, 0, 0, 0, 0x0F, 0xA2, 0x0F, 0xBA, 0xE1, 0x1F,
                        0x0F, 0x92, 0xC0, 0x0F, 0xB6, 0xC0, 0xF4});
    CHECK_EQ(lo32(s.read_reg(Reg::Rax)), 0u);  // not virtualised
}

TEST("hypervisor cpuid leaf 0x40000000 is hidden") {
    // mov eax,0x40000000 ; cpuid ; hlt  -> eax must read back 0
    auto s = run_probe({0xB8, 0x00, 0x00, 0x00, 0x40, 0x0F, 0xA2, 0xF4});
    CHECK_EQ(lo32(s.read_reg(Reg::Rax)), 0u);
}

TEST("rdtsc delta is small and deterministic (no single-step gap)") {
    // rdtsc ; mov ecx,eax ; rdtsc ; sub eax,ecx ; hlt
    auto s = run_probe({0x0F, 0x31, 0x89, 0xC1, 0x0F, 0x31, 0x29, 0xC8, 0xF4});
    u32 delta = lo32(s.read_reg(Reg::Rax));
    CHECK(delta < 1000u);   // not the enormous gap instrumentation would show
    CHECK(delta > 0u);      // but the clock does advance
    // And it is reproducible: a second run yields the same delta.
    auto s2 = run_probe({0x0F, 0x31, 0x89, 0xC1, 0x0F, 0x31, 0x29, 0xC8, 0xF4});
    CHECK_EQ(delta, lo32(s2.read_reg(Reg::Rax)));
}

TEST("SIDT (Red Pill) returns a bare-metal IDT base") {
    // sub rsp,16 ; sidt [rsp] ; mov rax,[rsp+2] ; add rsp,16 ; hlt
    auto s = run_probe({0x48, 0x83, 0xEC, 0x10, 0x0F, 0x01, 0x0C, 0x24,
                        0x48, 0x8B, 0x44, 0x24, 0x02, 0x48, 0x83, 0xC4, 0x10, 0xF4});
    CHECK_EQ(s.read_reg(Reg::Rax), 0xfffff80000000000ull);  // the forged base
}

TEST("SGDT (No Pill) returns a bare-metal GDT base") {
    auto s = run_probe({0x48, 0x83, 0xEC, 0x10, 0x0F, 0x01, 0x04, 0x24,
                        0x48, 0x8B, 0x44, 0x24, 0x02, 0xF4});
    CHECK_EQ(s.read_reg(Reg::Rax), 0xfffff80000001000ull);
}

TEST("SMSW shows protected mode (CR0.PE set)") {
    // smsw eax ; and eax,1 ; hlt
    auto s = run_probe({0x0F, 0x01, 0xE0, 0x83, 0xE0, 0x01, 0xF4});
    CHECK_EQ(lo32(s.read_reg(Reg::Rax)), 1u);
}

TEST("STR returns a plausible task-register selector") {
    // str eax ; hlt
    auto s = run_probe({0x0F, 0x00, 0xC8, 0xF4});
    CHECK_EQ(lo32(s.read_reg(Reg::Rax)), 0x40u);
}

TEST("VMware backdoor port is silent") {
    // mov eax,'VMXh' ; mov ecx,0x0A ; mov edx,0x5658 ; in eax,dx ; hlt
    auto s = run_probe({0xB8, 0x68, 0x58, 0x4D, 0x56, 0xB9, 0x0A, 0, 0, 0,
                        0xBA, 0x58, 0x56, 0, 0, 0xED, 0xF4});
    CHECK_EQ(lo32(s.read_reg(Reg::Rax)), 0u);  // no backdoor reply
}

TEST("RDTSCP reports CPU 0 in ecx") {
    auto s = run_probe({0x0F, 0x01, 0xF9, 0xF4});  // rdtscp ; hlt
    CHECK_EQ(lo32(s.read_reg(Reg::Rcx)), 0u);
}

TEST("self-modifying code: the newly written instruction executes") {
    // Escape attempt: overwrite an upcoming instruction, then run into it.
    //   0x1000: mov byte [0x100a], 0x90   ; turn the ud2 at 0x100a into a nop
    //   0x1009: (filler) ... actually place the patch target precisely:
    // Layout: C6 05 <rel32> 90   (mov byte [rip+rel], 0x90) is awkward; use abs.
    //   mov rax, 0x100d        ; 48 B8 0d 10 00 00 00 00 00 00   (addr of the ud2)
    //   mov byte [rax], 0xF4   ; C6 00 F4                        (patch -> hlt)
    //   <target 0x100d>: originally 0x0F 0x0B (ud2) -> now 0xF4 (hlt)
    std::vector<u8> code = {
        0x48, 0xB8, 0x0D, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax,0x100d
        0xC6, 0x00, 0xF4,                                            // mov byte [rax],0xF4
        0x0F, 0x0B                                                   // ud2 (patched to hlt)
    };
    AnalysisSession s(Arch::X86_64);
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);
    StepOutcome o = s.run();
    // If the decode cache were stale, we'd hit the ud2 (Unsupported); instead the
    // freshly written hlt runs, proving self-modifying code is handled.
    CHECK(o.status == StepOutcome::Status::Halted);
}

int main() { return dede::test::run_all(); }
