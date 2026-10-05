// SPDX-License-Identifier: Apache-2.0
//
// Differential execution: for each instruction, run the real interpreter one
// step and run the lifted IR through the reference evaluator from the same
// initial state, then assert identical register (and, for modelled ops, flag)
// and memory effects. This is the correctness backbone for the IR/lifter (M1).
#include <array>
#include <cstdio>
#include <map>
#include <vector>

#include "check.hpp"
#include "dede/ir/eval.hpp"
#include "dede/ir/lifter.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

namespace {

u64 fmask(ir::Flag f) {
    switch (f) {
        case ir::Flag::CF: return flags::CF;
        case ir::Flag::PF: return flags::PF;
        case ir::Flag::AF: return flags::AF;
        case ir::Flag::ZF: return flags::ZF;
        case ir::Flag::SF: return flags::SF;
        case ir::Flag::OF: return flags::OF;
    }
    return 0;
}

// Run one instruction both ways; return true if register/flag/memory effects match.
bool diff(const char* name, const std::vector<u8>& code, std::map<Reg, u64> regs, bool check_flags) {
    AnalysisSession s(Arch::X86_64);
    s.map(0x1000, 0x1000, perm::RWX);
    s.map(0x3000, 0x1000, perm::RW);
    s.map(0x60000, 0x10000, perm::RW);
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);
    // default register environment
    if (!regs.count(Reg::Rsp)) regs[Reg::Rsp] = 0x6ff80;
    for (auto& [r, v] : regs) s.core().cpu().set(r, v);
    // seed data region with a pattern so loads read something non-trivial
    std::vector<u8> pat(64);
    for (int i = 0; i < 64; ++i) pat[i] = static_cast<u8>(0x11 * (i % 15) + 1);
    s.core().memory().write(0x3000, pat);

    std::array<u64, 16> init{};
    for (int i = 0; i < 16; ++i) init[i] = s.read_reg(static_cast<Reg>(i));
    u64 init_flags = s.rflags();

    std::map<Addr, u8> mem;
    auto snap = [&](Addr base, int n) {
        for (int i = 0; i < n; ++i) { auto b = s.read_mem(base + i, 1); if (b) mem[base + i] = static_cast<u8>(b.value()); }
    };
    snap(0x3000, 64);
    snap(0x6fe00, 512);

    auto insns = s.disassemble(0x1000, 1);
    if (insns.empty()) { std::printf("  [%s] decode failed\n", name); return false; }

    s.step();  // interpreter
    std::array<u64, 16> after{};
    for (int i = 0; i < 16; ++i) after[i] = s.read_reg(static_cast<Reg>(i));
    u64 after_flags = s.rflags();

    // IR path from the snapshot
    std::array<u64, 16> rf = init;
    u64 fl = init_flags;
    std::map<Addr, u8> M = mem;
    ir::EvalEnv env;
    env.get_reg = [&](Reg r) { return rf[static_cast<int>(r)]; };
    env.set_reg = [&](Reg r, u64 v) { rf[static_cast<int>(r)] = v; };
    env.get_flag = [&](ir::Flag f) { return (fl & fmask(f)) != 0; };
    env.set_flag = [&](ir::Flag f, bool on) { if (on) fl |= fmask(f); else fl &= ~fmask(f); };
    env.load = [&](Addr a, unsigned n) { u64 v = 0; for (unsigned i = 0; i < n; ++i) v |= (u64)M[a + i] << (8 * i); return v; };
    env.store = [&](Addr a, unsigned n, u64 v) { for (unsigned i = 0; i < n; ++i) M[a + i] = (u8)(v >> (8 * i)); };

    auto irc = ir::lift_insn(insns[0]);
    ir::eval(irc, env);

    bool ok = true;
    for (int i = 0; i < 16; ++i)
        if (rf[i] != after[i]) {
            std::printf("  [%s] reg %s: ir=0x%llx interp=0x%llx\n", name,
                        std::string(reg_name((Reg)i)).c_str(), (unsigned long long)rf[i], (unsigned long long)after[i]);
            ok = false;
        }
    if (check_flags)
        for (ir::Flag f : {ir::Flag::CF, ir::Flag::PF, ir::Flag::AF, ir::Flag::ZF, ir::Flag::SF, ir::Flag::OF}) {
            bool a = (fl & fmask(f)) != 0, b = (after_flags & fmask(f)) != 0;
            if (a != b) { std::printf("  [%s] flag %d: ir=%d interp=%d\n", name, (int)f, a, b); ok = false; }
        }
    for (auto& [addr, byte] : mem) {  // compare both windows
        auto cur = s.read_mem(addr, 1);
        u8 interp_b = cur ? (u8)cur.value() : 0;
        u8 ir_b = M.count(addr) ? M[addr] : byte;
        if (ir_b != interp_b) { std::printf("  [%s] mem 0x%llx: ir=0x%02x interp=0x%02x\n", name, (unsigned long long)addr, ir_b, interp_b); ok = false; }
    }
    return ok;
}

}  // namespace

TEST("IR lift matches interpreter — data & arithmetic (differential)") {
    std::map<Reg, u64> rv{{Reg::Rax, 0x1234}, {Reg::Rbx, 0x5678}, {Reg::Rcx, 3}, {Reg::Rdx, 0xff}};
    CHECK(diff("mov rax,0x2a", {0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00}, rv, false));
    CHECK(diff("add rax,rbx", {0x48, 0x01, 0xD8}, rv, true));
    CHECK(diff("sub rax,rbx", {0x48, 0x29, 0xD8}, rv, true));
    CHECK(diff("and rax,rbx", {0x48, 0x21, 0xD8}, rv, true));
    CHECK(diff("or rax,rbx", {0x48, 0x09, 0xD8}, rv, true));
    CHECK(diff("xor rax,rbx", {0x48, 0x31, 0xD8}, rv, true));
    CHECK(diff("cmp rax,rbx", {0x48, 0x39, 0xD8}, rv, true));
    CHECK(diff("test rax,rbx", {0x48, 0x85, 0xD8}, rv, true));
    CHECK(diff("not rax", {0x48, 0xF7, 0xD0}, rv, false));
    CHECK(diff("imul rax,rbx", {0x48, 0x0F, 0xAF, 0xC3}, rv, false));
    CHECK(diff("movzx eax,bl", {0x0F, 0xB6, 0xC3}, rv, false));
    CHECK(diff("movsx eax,bl", {0x0F, 0xBE, 0xC3}, rv, false));
    CHECK(diff("lea rax,[rbx+rcx*4+8]", {0x48, 0x8D, 0x44, 0x8B, 0x08}, rv, false));
    CHECK(diff("shl rax,3", {0x48, 0xC1, 0xE0, 0x03}, rv, false));
    CHECK(diff("shr rax,3", {0x48, 0xC1, 0xE8, 0x03}, rv, false));
    CHECK(diff("sar rax,3", {0x48, 0xC1, 0xF8, 0x03}, rv, false));
}

TEST("IR lift matches interpreter — flag edge cases (carry/overflow/zero)") {
    CHECK(diff("add carry+zero", {0x48, 0x01, 0xD8}, {{Reg::Rax, 0xffffffffffffffffULL}, {Reg::Rbx, 1}}, true));
    CHECK(diff("add overflow", {0x48, 0x01, 0xD8}, {{Reg::Rax, 0x7fffffffffffffffULL}, {Reg::Rbx, 1}}, true));
    CHECK(diff("sub to zero", {0x48, 0x29, 0xD8}, {{Reg::Rax, 0x42}, {Reg::Rbx, 0x42}}, true));
    CHECK(diff("sub borrow", {0x48, 0x29, 0xD8}, {{Reg::Rax, 0}, {Reg::Rbx, 1}}, true));
    CHECK(diff("neg zero", {0x48, 0xF7, 0xD8}, {{Reg::Rax, 0}}, true));
    CHECK(diff("neg nonzero", {0x48, 0xF7, 0xD8}, {{Reg::Rax, 5}}, true));
}

TEST("IR lift matches interpreter — memory and stack") {
    std::map<Reg, u64> rv{{Reg::Rbx, 0x3010}, {Reg::Rax, 0xdeadbeefcafef00dULL}, {Reg::Rsp, 0x6ff80}};
    CHECK(diff("mov rax,[rbx]", {0x48, 0x8B, 0x03}, rv, false));
    CHECK(diff("mov [rbx],rax", {0x48, 0x89, 0x03}, rv, false));
    CHECK(diff("push rax", {0x50}, rv, false));
    CHECK(diff("pop rcx", {0x59}, rv, false));
}

int main() { return dede::test::run_all(); }
