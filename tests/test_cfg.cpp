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
