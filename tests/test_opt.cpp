// SPDX-License-Identifier: Apache-2.0
//
// Differential validation of the IR data-flow optimizer (Batch 5, T5.2): for
// each sample basic block we lift it, run simplify_block, and evaluate BOTH the
// original and the optimized IR against the same seeded machine state. The
// optimizer is correct only if every seeded state produces bit-identical exit
// registers, flags, and memory. We also assert that redundant blocks actually
// shrink (propagation/CSE/DCE did something).
#include <array>
#include <cstdio>
#include <map>
#include <vector>

#include "check.hpp"
#include "dede/disasm/disassembler.hpp"
#include "dede/ir/eval.hpp"
#include "dede/ir/lifter.hpp"
#include "dede/ir/opt.hpp"
#include "dede/ir/ssa.hpp"

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

// Lift a straight-line byte sequence into one IR block (unique temp ids).
std::vector<ir::Insn> lift(const std::vector<u8>& code) {
    auto dis = make_disassembler(Arch::X86_64);
    auto insns = dis->decode(code.data(), code.size(), 0x1000, 0);
    BasicBlock bb;
    bb.start = 0x1000;
    bb.insns = insns;
    bb.end = 0x1000 + code.size();
    bb.terminates = false;
    return ir::lift_block(bb).code;
}

// Evaluate an IR block against a seeded state; capture exit regs/flags/mem.
struct State { std::array<u64, 20> regs{}; u64 fl = 0; std::map<Addr, u8> mem; };

State run(const std::vector<ir::Insn>& code, State s) {
    ir::EvalEnv env;
    env.get_reg = [&](Reg r) { return s.regs[static_cast<int>(r)]; };
    env.set_reg = [&](Reg r, u64 v) { s.regs[static_cast<int>(r)] = v; };
    env.get_flag = [&](ir::Flag f) { return (s.fl & fmask(f)) != 0; };
    env.set_flag = [&](ir::Flag f, bool on) { if (on) s.fl |= fmask(f); else s.fl &= ~fmask(f); };
    env.load = [&](Addr a, unsigned n) { u64 v = 0; for (unsigned i = 0; i < n; ++i) v |= (u64)s.mem[a + i] << (8 * i); return v; };
    env.store = [&](Addr a, unsigned n, u64 v) { for (unsigned i = 0; i < n; ++i) s.mem[a + i] = (u8)(v >> (8 * i)); };
    ir::eval(code, env);
    return s;
}

// A few seeded initial states to exercise the transform over many inputs.
std::vector<State> seeds() {
    std::vector<State> v;
    for (auto env : std::vector<std::array<u64, 8>>{
             {1, 2, 3, 4, 5, 6, 7, 8},
             {0, 0xffffffffffffffffULL, 0x100, 0x7fffffff, 0x80000000, 2, 0x1234, 0x5678},
             {0x3000, 0x3008, 0x3010, 0, 0x6ff80, 0x3000, 0xdeadbeef, 0x10}}) {
        State s;
        s.regs[(int)Reg::Rax] = env[0];
        s.regs[(int)Reg::Rcx] = env[1];
        s.regs[(int)Reg::Rdx] = env[2];
        s.regs[(int)Reg::Rbx] = env[3];
        s.regs[(int)Reg::Rsp] = env[4];
        s.regs[(int)Reg::Rsi] = env[5];
        s.regs[(int)Reg::Rdi] = env[6];
        s.regs[(int)Reg::Rbp] = env[7];
        // seed a little memory for load/store samples
        for (int i = 0; i < 64; ++i) s.mem[0x3000 + i] = (u8)(0x11 * (i % 15) + 1);
        v.push_back(s);
    }
    return v;
}

bool states_eq(const State& a, const State& b) {
    for (int i = 0; i < 16; ++i)
        if (a.regs[i] != b.regs[i]) { std::printf("  reg %s a=0x%llx b=0x%llx\n", std::string(reg_name((Reg)i)).c_str(), (unsigned long long)a.regs[i], (unsigned long long)b.regs[i]); return false; }
    for (ir::Flag f : {ir::Flag::CF, ir::Flag::PF, ir::Flag::AF, ir::Flag::ZF, ir::Flag::SF, ir::Flag::OF})
        if (((a.fl & fmask(f)) != 0) != ((b.fl & fmask(f)) != 0)) { std::printf("  flag %d differs\n", (int)f); return false; }
    std::map<Addr, u8> all = a.mem;
    for (auto& [k, v] : b.mem) all[k] = v;
    for (auto& [k, _] : all) {
        u8 av = a.mem.count(k) ? a.mem.at(k) : 0, bv = b.mem.count(k) ? b.mem.at(k) : 0;
        if (av != bv) { std::printf("  mem 0x%llx a=%02x b=%02x\n", (unsigned long long)k, av, bv); return false; }
    }
    return true;
}

// Lift, optimize, and assert semantics preserved over all seeds.
bool preserves(const char* name, const std::vector<u8>& code, bool cse = true) {
    auto orig = lift(code);
    auto opt = ir::simplify_block(orig, cse);
    bool ok = true;
    for (const auto& s : seeds())
        if (!states_eq(run(orig, s), run(opt, s))) { std::printf("  [%s] mismatch\n", name); ok = false; }
    return ok;
}

}  // namespace

TEST("optimizer preserves semantics across arithmetic blocks") {
    // mov rax,rdi; add rax,rsi; ret  -> should fold the copy chain
    CHECK(preserves("copychain", {0x48, 0x89, 0xF8, 0x48, 0x01, 0xF0, 0xC3}));
    // mov eax,2; add eax,3; ret  -> const fold across registers
    CHECK(preserves("constfold", {0xB8, 0x02, 0, 0, 0, 0x83, 0xC0, 0x03, 0xC3}));
    // lea rax,[rbx+rcx*4+8]; ret
    CHECK(preserves("lea", {0x48, 0x8D, 0x44, 0x8B, 0x08, 0xC3}));
    // a longer mix: mov/add/sub/and/xor/shl
    CHECK(preserves("mix", {0x48, 0x89, 0xF8, 0x48, 0x01, 0xF0, 0x48, 0x29, 0xD0,
                            0x48, 0x21, 0xC8, 0x48, 0x31, 0xD8, 0x48, 0xC1, 0xE0, 0x02, 0xC3}));
    // memory: mov rax,[rbx]; add rax,rcx; mov [rbx],rax; ret
    CHECK(preserves("mem", {0x48, 0x8B, 0x03, 0x48, 0x01, 0xC8, 0x48, 0x89, 0x03, 0xC3}));
}

TEST("optimizer preserves semantics with CSE disabled (decompiler mode)") {
    CHECK(preserves("copychain-nocse", {0x48, 0x89, 0xF8, 0x48, 0x01, 0xF0, 0xC3}, false));
    CHECK(preserves("mix-nocse", {0x48, 0x89, 0xF8, 0x48, 0x01, 0xF0, 0x48, 0x29, 0xD0, 0xC3}, false));
}

TEST("optimizer removes the redundant copy chain") {
    // mov rax,rdi; add rax,rsi  -> the intermediate `rax = rdi` copy is dead
    auto orig = lift({0x48, 0x89, 0xF8, 0x48, 0x01, 0xF0, 0xC3});
    ir::OptStats st;
    auto opt = ir::simplify_block(orig, true, &st);
    CHECK(opt.size() < orig.size());        // something was removed
    CHECK(st.after < st.before);
    // the surviving reg-writing copies should not include a pure reg<-reg alias
    int reg_reg_copies = 0;
    for (const auto& in : opt)
        if (in.op == ir::Op::Copy && in.out.kind == ir::VnKind::Reg && in.a.kind == ir::VnKind::Reg)
            ++reg_reg_copies;
    CHECK_EQ(reg_reg_copies, 0);
}

TEST("optimizer leaves call-bearing blocks unchanged") {
    // mov rax,rdi; call rel32; ret  -> conservative: returned as-is
    auto orig = lift({0x48, 0x89, 0xF8, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3});
    auto opt = ir::simplify_block(orig);
    CHECK_EQ(opt.size(), orig.size());
}

TEST("dominator tree + dominance frontier on a diamond") {
    // A -> B, A -> C, B -> D, C -> D  (classic diamond)
    std::vector<Addr> nodes = {1, 2, 3, 4};
    std::map<Addr, std::vector<Addr>> succ = {{1, {2, 3}}, {2, {4}}, {3, {4}}, {4, {}}};
    auto idom = ir::dominator_tree(nodes, 1, succ);
    CHECK_EQ(idom[1], 1u);  // entry dominates itself
    CHECK_EQ(idom[2], 1u);
    CHECK_EQ(idom[3], 1u);
    CHECK_EQ(idom[4], 1u);  // D's idom is A, not B or C (the join)
    CHECK(ir::dominates(idom, 1, 4));
    CHECK(!ir::dominates(idom, 2, 4));

    auto df = ir::dominance_frontier(nodes, idom, succ);
    CHECK(df[2].count(4) == 1);   // B's dominance ends at the join D
    CHECK(df[3].count(4) == 1);   // C's too
    CHECK(df[4].empty());

    // a variable defined in both B and C needs a phi at the join D.
    std::map<int, std::set<Addr>> defs = {{/*var*/ 7, {2, 3}}};
    auto phis = ir::place_phis(defs, df);
    CHECK(phis[4].count(7) == 1);
    CHECK(phis[2].empty());
}

TEST("dominator tree on a loop: back-edge target is on the frontier") {
    // A -> B, B -> C, C -> B (loop), C -> D
    std::vector<Addr> nodes = {1, 2, 3, 4};
    std::map<Addr, std::vector<Addr>> succ = {{1, {2}}, {2, {3}}, {3, {2, 4}}, {4, {}}};
    auto idom = ir::dominator_tree(nodes, 1, succ);
    CHECK_EQ(idom[2], 1u);
    CHECK_EQ(idom[3], 2u);
    CHECK_EQ(idom[4], 3u);
    CHECK(ir::dominates(idom, 2, 3));
    CHECK(ir::dominates(idom, 2, 4));
    auto df = ir::dominance_frontier(nodes, idom, succ);
    CHECK(df[3].count(2) == 1);   // the loop header B is on C's dominance frontier
    // a value defined inside the loop body needs a phi at the header.
    auto phis = ir::place_phis({{9, {3}}}, df);
    CHECK(phis[2].count(9) == 1);
}

int main() { return dede::test::run_all(); }
