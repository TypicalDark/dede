// SPDX-License-Identifier: Apache-2.0
//
// Batch 9: the Linux user-mode environment drives a syscall-using program to
// completion under the deterministic interpreter — arch_prctl sets the fs base,
// mmap allocates in the arena, write(1,...) is captured as observable stdout,
// read() is fed via MITM, and exit records a code — with a replayable log.
#include <string>
#include <vector>

#include "check.hpp"
#include "dede/macro/command.hpp"
#include "dede/os/linux_env.hpp"
#include "dede/os/windows_env.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

namespace {
// helpers to emit mov reg,imm32 (sign-extended) and the fixed opcodes.
void mov(std::vector<u8>& o, u8 modrm, u32 imm) {
    o.insert(o.end(), {0x48, 0xC7, modrm,
                       (u8)imm, (u8)(imm >> 8), (u8)(imm >> 16), (u8)(imm >> 24)});
}
constexpr u8 RAX = 0xC0, RDI = 0xC7, RSI = 0xC6, RDX = 0xC2;
void syscall_(std::vector<u8>& o) { o.insert(o.end(), {0x0F, 0x05}); }

// Bind a Linux environment to the session's syscall interception.
void attach(AnalysisSession& s, os::LinuxEnvironment& env) {
    RunPoint rp;
    rp.type = RunPointType::Syscall;  // any syscall number
    rp.address = 0;
    rp.pause = false;
    u64 id = s.add_run_point(std::move(rp));
    auto m = std::make_shared<Macro>();
    m->mutating = true;
    m->callback = [&env](IDebugController& c) { env.on_syscall(c); };
    s.bind_macro(id, m);
}
}  // namespace

TEST("linux env: arch_prctl + mmap + write(stdout) + exit run to completion") {
    AnalysisSession s(Arch::X86_64);
    s.map(0x1000, 0x1000, perm::RWX);
    s.map(0x100000, 0x10000, perm::RWX);  // the mmap/brk arena
    s.core().cpu().set(Reg::Rsp, 0x1f00);

    std::vector<u8> code;
    // arch_prctl(ARCH_SET_FS=0x1002, 0x100000)
    mov(code, RAX, 158); mov(code, RDI, 0x1002); mov(code, RSI, 0x100000); syscall_(code);
    // mmap(0, 0x1000, ...)
    mov(code, RAX, 9); mov(code, RDI, 0); mov(code, RSI, 0x1000); syscall_(code);
    // write(1, 0x1300, 5)
    mov(code, RAX, 1); mov(code, RDI, 1); mov(code, RSI, 0x1300); mov(code, RDX, 5); syscall_(code);
    // exit(7)
    mov(code, RAX, 60); mov(code, RDI, 7); syscall_(code);
    code.push_back(0xF4);  // hlt
    s.load(0x1000, code, perm::RWX);
    s.load(0x1300, {'h', 'e', 'l', 'l', 'o'}, perm::RWX);
    s.set_entry(0x1000);

    os::LinuxEnvironment env(0x100000, 0x10000);
    attach(s, env);
    s.run();

    CHECK_EQ(env.syscall_count(), 4u);
    CHECK(env.exited());
    CHECK_EQ(env.exit_code(), 7);
    CHECK_EQ(s.core().cpu().fs_base(), 0x100000u);           // arch_prctl set the TLS base
    CHECK_EQ(env.mmap_regions().size(), 1u);                 // one mmap region tracked
    CHECK(env.mmap_regions()[0].addr >= 0x100000u);
    auto captured = env.output(1);                           // bind once (iterators into one vector)
    std::string out(captured.begin(), captured.end());
    CHECK_EQ(out, std::string("hello"));                     // observable stdout captured
    // the behavioral log is ordered and names the calls
    CHECK_EQ(env.log()[0].name, std::string("arch_prctl"));
    CHECK_EQ(env.log()[2].name, std::string("write"));
    CHECK_EQ(env.log()[3].name, std::string("exit"));
}

TEST("linux env: read() is satisfied from MITM-fed input") {
    AnalysisSession s(Arch::X86_64);
    s.map(0x1000, 0x1000, perm::RWX);
    std::vector<u8> code;
    mov(code, RAX, 0); mov(code, RDI, 0); mov(code, RSI, 0x1400); mov(code, RDX, 4); syscall_(code);
    code.push_back(0xF4);
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);

    os::LinuxEnvironment env(0x100000, 0x10000);
    env.feed_input(0, {0xDE, 0xAD, 0xBE, 0xEF});  // pre-fed stdin
    attach(s, env);
    s.run();

    CHECK_EQ(s.core().cpu().get(Reg::Rax), 4u);               // 4 bytes read
    for (unsigned i = 0; i < 4; ++i) {
        auto b = s.read_mem(0x1400 + i, 1);
        CHECK(b.ok());
    }
    CHECK_EQ(s.read_mem(0x1400, 4).value(), 0xEFBEADDEull);   // little-endian in guest memory
}

TEST("linux env: time-travel restores pre-syscall state") {
    AnalysisSession s(Arch::X86_64);
    s.map(0x1000, 0x1000, perm::RWX);
    s.map(0x100000, 0x10000, perm::RWX);
    std::vector<u8> code;
    mov(code, RAX, 9); mov(code, RDI, 0); mov(code, RSI, 0x1000); syscall_(code);  // mmap
    code.push_back(0xF4);
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);
    os::LinuxEnvironment env(0x100000, 0x10000);
    attach(s, env);
    s.run();
    u64 mmap_ret = s.core().cpu().get(Reg::Rax);
    CHECK(mmap_ret >= 0x100000u);
    Tick end = s.now();
    CHECK(s.step_back(end).ok());          // back to tick 0 (entry)
    CHECK_EQ(s.now(), 0u);
    CHECK_EQ(s.core().cpu().rip(), 0x1000u);  // rip restored to the entry
}

TEST("windows env: forged PEB reads not-debugged + shimmed VirtualAlloc") {
    AnalysisSession s(Arch::X86_64);
    s.map(0x1000, 0x1000, perm::RWX);
    s.map(0x90000, 0x2000, perm::RW);    // TEB + PEB
    s.map(0xA0000, 0x10000, perm::RWX);  // VirtualAlloc arena
    s.core().cpu().set(Reg::Rsp, 0x1f00);

    // code laid out so the VirtualAlloc stub sits at 0x1080:
    std::vector<u8> code(0x81, 0x90);  // pad with NOPs up to 0x80
    std::size_t p = 0;
    auto put = [&](std::initializer_list<u8> b) { for (u8 x : b) code[p++] = x; };
    put({0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00});  // mov rax, gs:[0x60]  (PEB)
    put({0x0F, 0xB6, 0x58, 0x02});                                // movzx ebx, byte [rax+2] (BeingDebugged)
    put({0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00});              // mov rcx, 0
    put({0x48, 0xC7, 0xC2, 0x00, 0x10, 0x00, 0x00});              // mov rdx, 0x1000
    put({0x49, 0xC7, 0xC0, 0x00, 0x30, 0x00, 0x00});              // mov r8, 0x3000
    put({0x49, 0xC7, 0xC1, 0x40, 0x00, 0x00, 0x00});              // mov r9, 0x40
    put({0xE8, 0x52, 0x00, 0x00, 0x00});                          // call 0x1080 (VirtualAlloc stub)
    put({0x49, 0x89, 0xC7});                                      // mov r15, rax (save region)
    put({0xF4});                                                  // hlt
    code[0x80] = 0xC3;                                            // the VirtualAlloc stub: ret
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);

    os::WindowsEnvironment env(0xA0000, 0x10000, /*teb=*/0x90000, /*peb=*/0x91000);
    env.install(s);                       // forge PEB/TEB + set gs base
    env.register_api("VirtualAlloc", 0x1080);
    RunPoint rp; rp.type = RunPointType::Address; rp.address = 0x1080; rp.pause = false;
    u64 id = s.add_run_point(std::move(rp));
    auto m = std::make_shared<Macro>(); m->mutating = true;
    m->callback = [&env](IDebugController& c) { env.on_api(c); };
    s.bind_macro(id, m);
    s.run();

    CHECK_EQ(s.core().cpu().get(Reg::Rbx), 0u);              // PEB.BeingDebugged == 0 (not debugged)
    CHECK(s.core().cpu().get(Reg::R15) >= 0xA0000u);         // VirtualAlloc returned an arena address
    CHECK_EQ(env.regions().size(), 1u);
    CHECK_EQ(env.regions()[0].size, 0x1000u);
    CHECK_EQ(env.log().size(), 1u);
    CHECK_EQ(env.log()[0].name, std::string("VirtualAlloc"));
}

int main() { return dede::test::run_all(); }
