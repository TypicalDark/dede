// SPDX-License-Identifier: Apache-2.0
//
// Tests the native decompiler's output: expression building, constant folding,
// condition re-fusion (cmp/jcc and bt/jb), and call/return recovery over the
// tutorial samples.
#include <string>

#include "check.hpp"
#include "dede/samples/tiers.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

namespace {
std::string decompile_tier(int n) {
    auto t = samples::make_tier(n);
    AnalysisSession s(Arch::X86_64);
    s.map(0x1000, 0x10000, perm::RWX);
    s.map(0x70000, 0x10000, perm::RW);
    s.core().cpu().set(Reg::Rsp, 0x78000);
    s.load(0x1000, t.image, perm::RWX);
    s.set_entry(0x1000);
    auto r = s.decompile(0x1000, 64);
    return r ? r.value() : ("ERROR: " + r.message());
}
std::string decompile_bytes(const std::vector<u8>& code) {
    AnalysisSession s(Arch::X86_64);
    s.map(0x1000, 0x10000, perm::RWX);
    s.map(0x70000, 0x10000, perm::RW);
    s.core().cpu().set(Reg::Rsp, 0x78000);
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);
    auto r = s.decompile(0x1000, 64);
    return r ? r.value() : ("ERROR: " + r.message());
}
bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}
}  // namespace

TEST("decompiler builds expressions and re-fuses the loop condition (tier 1)") {
    std::string c = decompile_tier(1);
    CHECK(has(c, "int64_t sub_1000"));
    CHECK(has(c, "rax = rax + rcx"));   // expression building, not two ops
    CHECK(has(c, "rcx = rcx - 1"));
    CHECK(has(c, "rcx != 0"));          // dec/jne re-fused to reg-vs-0
    CHECK(has(c, "return"));
}

TEST("decompiler recovers a call and constant (tier 2)") {
    std::string c = decompile_tier(2);
    CHECK(has(c, "rax = 0x15"));        // immediate recovered
    CHECK(has(c, "sub_1010();"));       // call recovered, correct order before return
    // the call must come before the return statement
    CHECK(c.find("sub_1010();") < c.find("return"));
}

TEST("decompiler re-fuses the anti-VM bt/jb hypervisor check (tier 4)") {
    std::string c = decompile_tier(4);
    CHECK(has(c, ">> 0x1f"));           // bt ecx,0x1f -> bit-31 test
    CHECK(has(c, "if ("));              // a real condition, not a bare goto
    CHECK(has(c, "0xdead") && has(c, "0x600d"));  // both outcome constants
}

TEST("decompiler recovers and names a stack local (variable recovery)") {
    // push rbp; mov rbp,rsp; mov [rbp-8],rdi; mov rax,[rbp-8]; add rax,1; pop rbp; ret
    std::string c = decompile_bytes({0x55, 0x48, 0x89, 0xE5, 0x48, 0x89, 0x7D, 0xF8,
                                     0x48, 0x8B, 0x45, 0xF8, 0x48, 0x83, 0xC0, 0x01, 0x5D, 0xC3});
    CHECK(has(c, "var_8"));                  // [rbp-8] named as a local
    CHECK(has(c, "int64_t var_8;"));         // declared with a type
    CHECK(has(c, "var_8 = rdi"));            // the store uses the name
    CHECK(has(c, "sub_1000(int64_t rdi"));   // rdi recovered as a typed parameter
}

int main() { return dede::test::run_all(); }
