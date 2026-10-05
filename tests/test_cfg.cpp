// SPDX-License-Identifier: Apache-2.0
#include <vector>

#include "check.hpp"
#include "dede/analysis/callstack.hpp"
#include "dede/analysis/scan.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

TEST("CFG of a loop has the expected blocks and edges") {
    // mov rax,0 ; mov rcx,3 ; loop: add rax,rcx ; dec rcx ; jnz loop ; hlt
    std::vector<u8> code = {
        0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,  // 0x1000 mov rax,0
        0x48, 0xC7, 0xC1, 0x03, 0x00, 0x00, 0x00,  // 0x1007 mov rcx,3
        0x48, 0x01, 0xC8,                          // 0x100e add rax,rcx (loop head)
        0x48, 0xFF, 0xC9,                          // 0x1011 dec rcx
        0x75, 0xF8,                                // 0x1014 jnz loop
        0xF4};                                     // 0x1016 hlt
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);

    Cfg g = s.build_cfg(0x1000);
    // Entry block, loop body, and the hlt block => 3 blocks.
    CHECK_EQ(g.blocks.size(), 3u);
    CHECK(g.block_at(0x1000) != nullptr);  // entry (falls into loop head)
    CHECK(g.block_at(0x100e) != nullptr);  // loop head
    CHECK(g.block_at(0x1016) != nullptr);  // hlt

    // The jnz produces a back-edge (taken -> loop head) and a fallthrough (-> hlt).
    bool back = false, out = false;
    for (const auto& e : g.edges) {
        if (e.kind == EdgeKind::Taken && e.to == 0x100e) back = true;
        if (e.kind == EdgeKind::NotTaken && e.to == 0x1016) out = true;
    }
    CHECK(back);
    CHECK(out);

    // Layout places the entry at row 0.
    auto pos = g.layout();
    CHECK_EQ(pos[0x1000].second, 0);

    // DOT export is non-empty and references the blocks.
    std::string dot = g.to_dot();
    CHECK(dot.find("digraph") != std::string::npos);
}

TEST("call is a reference, not an intraprocedural flow edge") {
    // mov rax,0x15 ; call 0x1010 ; hlt   (helper at 0x1010: shl rax,1 ; ret)
    std::vector<u8> code = {
        0x48, 0xC7, 0xC0, 0x15, 0x00, 0x00, 0x00,  // 0x1000 mov rax,0x15
        0xE8, 0x04, 0x00, 0x00, 0x00,              // 0x1007 call 0x1010
        0xF4,                                      // 0x100c hlt
        0x90, 0x90, 0x90,                          // padding
        0x48, 0xD1, 0xE0,                          // 0x1010 shl rax,1
        0xC3};                                     // 0x1013 ret
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);

    Cfg g = s.build_cfg(0x1000);
    // main is ONE block ending at the hlt; the call does NOT split it and does NOT
    // add a flow edge (the callee is a separate function, as in Ghidra/IDA/BN).
    CHECK_EQ(g.blocks.size(), 1u);
    CHECK_EQ(g.edges.size(), 0u);
    // The call is recorded as a reference instead.
    CHECK_EQ(g.calls.size(), 1u);
    CHECK_EQ(g.calls[0].second, 0x1010u);
    // No flow edge anywhere points at the callee entry.
    for (const auto& e : g.edges) CHECK(e.to != 0x1010u);
}

TEST("CFG recovers a jump table (switch/case reconstruction)") {
    // cmp rax,3; ja default; jmp [table+rax*8]; 4 cases; default; table(4 quads)
    std::vector<u8> code = {0x48, 0x83, 0xF8, 0x03, 0x77, 0x27, 0xFF, 0x24, 0xC5, 0x35, 0x10, 0x00, 0x00};
    // 0x100d..0x1034: five `mov rax,0xNN; ret` case bodies (4 cases + default at 0x102d).
    for (int v : {0xA0, 0xA1, 0xA2, 0xA3, 0xFF}) {
        const u8 blk[] = {0x48, 0xC7, 0xC0, (u8)v, 0x00, 0x00, 0x00, 0xC3};
        for (u8 b : blk) code.push_back(b);
    }
    // 0x1035: the jump table (4 quads) referenced by `jmp [rax*8 + 0x1035]`.
    for (Addr a : {0x100dULL, 0x1015ULL, 0x101dULL, 0x1025ULL})
        for (int i = 0; i < 8; ++i) code.push_back((u8)(a >> (8 * i)));
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);
    Cfg g = s.build_cfg(0x1000);
    // the indirect-jmp block (0x1006) must have exactly the 4 case edges
    int cases = 0;
    for (const auto& e : g.edges)
        if (e.from == 0x1006 && e.kind == EdgeKind::Jump) ++cases;
    CHECK_EQ(cases, 4);
    for (Addr t : {0x100dULL, 0x1015ULL, 0x101dULL, 0x1025ULL}) {
        bool found = false;
        for (const auto& e : g.edges) if (e.from == 0x1006 && e.to == t) found = true;
        CHECK(found);
    }
}

TEST("pointer-encryption detector flags PTR_MANGLE-style mangling") {
    // xor rax, fs:[0x30] ; ror rax, 0x11 ; hlt  (glibc pointer guard)
    std::vector<u8> code = {0x64,0x48,0x33,0x04,0x25,0x30,0,0,0, 0x48,0xC1,0xC8,0x11, 0xF4};
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);

    auto reader = [&s](Addr a) -> std::optional<u8> {
        auto b = s.read_mem(a, 1);
        if (!b) return std::nullopt;
        return static_cast<u8>(b.value());
    };
    auto findings = detect(Arch::X86_64, reader, 0x1000, 4);
    bool cookie = false, guard_rotate = false;
    for (const auto& f : findings) {
        if (f.category == "pointer-encryption" && f.detail.find("fs:") != std::string::npos) cookie = true;
        if (f.category == "pointer-encryption" && f.rule.find("rotate") != std::string::npos) guard_rotate = true;
    }
    CHECK(cookie);
    CHECK(guard_rotate);
}

TEST("exception-handler detector flags SEH frame manipulation, not the TLS cookie") {
    // mov rax, fs:[0] ; mov fs:[0], rsp ; ud2   (SEH install + deliberate fault)
    std::vector<u8> code = {0x64,0x48,0x8B,0x04,0x25,0,0,0,0, 0x64,0x48,0x89,0x24,0x25,0,0,0,0, 0x0F,0x0B};
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);
    auto reader = [&s](Addr a) -> std::optional<u8> {
        auto b = s.read_mem(a, 1);
        if (!b) return std::nullopt;
        return static_cast<u8>(b.value());
    };
    auto findings = detect(Arch::X86_64, reader, 0x1000, 3);
    bool seh = false, ud2 = false;
    for (const auto& f : findings) {
        if (f.category == "exception-handler" && f.rule.find("SEH frame") != std::string::npos) seh = true;
        if (f.category == "exception-handler" && f.rule.find("ud2") != std::string::npos) ud2 = true;
    }
    CHECK(seh);
    CHECK(ud2);

    // The stack canary / TLS cookie at fs:[0x30] (nonzero disp) must NOT be
    // mistaken for an SEH frame — it is pointer-encryption, not fs:[0].
    std::vector<u8> cookie = {0x64,0x48,0x33,0x04,0x25,0x30,0,0,0, 0xC3};  // xor rax, fs:[0x30]; ret
    AnalysisSession s2;
    s2.map(0x2000, 0x1000, perm::RWX);
    s2.load(0x2000, cookie, perm::RWX);
    s2.set_entry(0x2000);
    auto reader2 = [&s2](Addr a) -> std::optional<u8> {
        auto b = s2.read_mem(a, 1);
        if (!b) return std::nullopt;
        return static_cast<u8>(b.value());
    };
    bool false_seh = false;
    for (const auto& f : detect(Arch::X86_64, reader2, 0x2000, 2))
        if (f.category == "exception-handler") false_seh = true;
    CHECK(!false_seh);
}

TEST("lazy-init detector flags a guarded one-time init, not a bare compare") {
    // cmp [0x4000],0 ; jne skip ; mov [0x4000],1 ; skip: ret  (double-checked init)
    std::vector<u8> code = {0x48,0x83,0x3C,0x25,0x00,0x40,0x00,0x00,0x00, 0x75,0x0C,
                            0x48,0xC7,0x04,0x25,0x00,0x40,0x00,0x00,0x00,0x01,0x00,0x00,0x00, 0xC3};
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);
    auto reader = [&s](Addr a) -> std::optional<u8> {
        auto b = s.read_mem(a, 1);
        if (!b) return std::nullopt;
        return static_cast<u8>(b.value());
    };
    bool lazy = false;
    for (const auto& f : detect(Arch::X86_64, reader, 0x1000, 8))
        if (f.category == "lazy-init") lazy = true;
    CHECK(lazy);

    // A compare + branch that does NOT store back to the same global is not lazy-init.
    std::vector<u8> plain = {0x48,0x83,0x3C,0x25,0x00,0x40,0x00,0x00,0x00, 0x75,0x01, 0x90, 0xC3};
    AnalysisSession s2;
    s2.map(0x2000, 0x1000, perm::RWX);
    s2.load(0x2000, plain, perm::RWX);
    s2.set_entry(0x2000);
    auto reader2 = [&s2](Addr a) -> std::optional<u8> {
        auto b = s2.read_mem(a, 1);
        if (!b) return std::nullopt;
        return static_cast<u8>(b.value());
    };
    bool false_lazy = false;
    for (const auto& f : detect(Arch::X86_64, reader2, 0x2000, 8))
        if (f.category == "lazy-init") false_lazy = true;
    CHECK(!false_lazy);
}

TEST("anti-disassembly detector flags overlap / opaque pair / push-ret, not clean code") {
    // overlap (jmp into its own 2nd byte) + push imm32; ret + je/jne to the same target
    std::vector<u8> code = {0xEB,0xFF, 0x68,0x44,0x33,0x22,0x11, 0xC3,
                            0x0F,0x84,0x06,0,0,0, 0x0F,0x85,0,0,0,0, 0xC3};
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);
    auto reader = [&s](Addr a) -> std::optional<u8> {
        auto b = s.read_mem(a, 1);
        if (!b) return std::nullopt;
        return static_cast<u8>(b.value());
    };
    bool overlap = false, opaque = false, pushret = false;
    for (const auto& f : detect(Arch::X86_64, reader, 0x1000, 8)) {
        if (f.category != "anti-disassembly") continue;
        if (f.rule.find("overlapping") != std::string::npos) overlap = true;
        if (f.rule.find("complementary") != std::string::npos) opaque = true;
        if (f.rule.find("push imm") != std::string::npos) pushret = true;
    }
    CHECK(overlap);
    CHECK(opaque);
    CHECK(pushret);

    // Negatives: a normal backward loop branch (target on a boundary) and a
    // same-target but NON-complementary conditional pair must NOT be flagged.
    std::vector<u8> clean = {0x48,0xC7,0xC1,0x03,0,0,0, 0x48,0xFF,0xC9, 0x75,0xFB, 0xF4,  // loop: dec rcx; jnz loop; hlt
                             0x0F,0x8C,0x06,0,0,0, 0x0F,0x84,0,0,0,0, 0xC3};               // jl X; je X; ret (jle, not complementary)
    AnalysisSession s2;
    s2.map(0x3000, 0x1000, perm::RWX);
    s2.load(0x3000, clean, perm::RWX);
    s2.set_entry(0x3000);
    auto reader2 = [&s2](Addr a) -> std::optional<u8> {
        auto b = s2.read_mem(a, 1);
        if (!b) return std::nullopt;
        return static_cast<u8>(b.value());
    };
    bool false_ad = false;
    for (const auto& f : detect(Arch::X86_64, reader2, 0x3000, 8))
        if (f.category == "anti-disassembly") false_ad = true;
    CHECK(!false_ad);
}

TEST("call-stack unwinder recovers frames and flags a smashed return address") {
    // main: push rbp;mov rbp,rsp;call f;hlt | f: ...;call g;hlt | g: push rbp;mov rbp,rsp;hlt
    std::vector<u8> code = {0x55,0x48,0x89,0xE5, 0xE8,0x01,0,0,0, 0xF4,
                           0x55,0x48,0x89,0xE5, 0xE8,0x05,0,0,0, 0xF4,
                           0x90,0x90,0x90,0x90,
                           0x55,0x48,0x89,0xE5, 0xF4};
    AnalysisSession s(Arch::X86_64);
    s.map(0x1000, 0x2000, perm::RWX);
    s.map(0x70000, 0x1000, perm::RW);
    s.core().cpu().set(Reg::Rsp, 0x70800);
    s.core().cpu().set(Reg::Rbp, 0);
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);
    s.run();  // stops at g's hlt; rbp is g's frame

    auto dis = make_disassembler(Arch::X86_64);
    auto rd = [&s](Addr a) -> std::optional<u8> {
        auto b = s.read_mem(a, 1);
        if (!b) return std::nullopt;
        return static_cast<u8>(b.value());
    };
    auto rep = check_stack_integrity(*dis, rd, s.rip(), s.read_reg(Reg::Rbp));
    CHECK_EQ(rep.frames.size(), 3u);         // g, f, main
    CHECK(rep.intact());                     // all return addresses are call-preceded
    CHECK(rep.frames[0].ret_call_preceded);  // return into f
    CHECK(rep.frames[1].ret_call_preceded);  // return into main
    CHECK(rep.frames[2].is_base);            // main: chain terminates at rbp==0

    // Smash a saved return address to point into MAPPED mid-code (0x100A, f's
    // push rbp — a real instruction boundary but not a call site). The best-effort
    // call-preceded check must flag it (the value is readable, so this exercises
    // the heuristic's discrimination, not merely an unmapped read).
    s.core().memory().write(rep.frames[1].frame_ptr + 8, std::vector<u8>{0x0A,0x10,0,0,0,0,0,0});
    auto bad = check_stack_integrity(*dis, rd, s.rip(), s.read_reg(Reg::Rbp));
    CHECK(!bad.intact());
    CHECK(!bad.violations.empty());
}

int main() { return dede::test::run_all(); }
