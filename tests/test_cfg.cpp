// SPDX-License-Identifier: Apache-2.0
#include <vector>

#include "check.hpp"
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

int main() { return dede::test::run_all(); }
