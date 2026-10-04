// SPDX-License-Identifier: Apache-2.0
//
// The capture/MITM layer: recording the guest's external-interaction surface
// (syscalls) and rewriting a call's result via a run point + mutating macro.
#include <vector>

#include "check.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

namespace {
// mov rax, 1 (write) ; mov rdi, 2 ; mov rsi, 0x1000 ; syscall ; hlt
std::vector<u8> syscall_prog() {
    return {0x48, 0xC7, 0xC0, 0x01, 0, 0, 0,          // mov rax, 1
            0x48, 0xC7, 0xC7, 0x02, 0, 0, 0,          // mov rdi, 2
            0x48, 0xC7, 0xC6, 0x00, 0x10, 0, 0,       // mov rsi, 0x1000
            0x0F, 0x05,                               // syscall
            0xF4};                                    // hlt
}
AnalysisSession loaded() {
    AnalysisSession s(Arch::X86_64);
    s.map(0x1000, 0x1000, perm::RWX);
    s.load(0x1000, syscall_prog(), perm::RWX);
    s.set_entry(0x1000);
    return s;
}
}  // namespace

TEST("syscall name dissection") {
    CHECK_EQ(syscall_name(1), std::string("write"));
    CHECK_EQ(syscall_name(44), std::string("sendto"));
    CHECK_EQ(syscall_name(42), std::string("connect"));
    CHECK_EQ(syscall_name(9999), std::string("sys_9999"));
}

TEST("capture records a syscall transaction with dissected args") {
    auto s = loaded();
    s.capture_enable(true);
    s.run();
    const auto& log = s.capture_log();
    CHECK(log.size() >= 1u);
    bool found = false;
    for (const auto& e : log)
        if (e.kind == CapKind::Syscall && e.name == "write" && e.args[0] == 2) found = true;
    CHECK(found);
}

TEST("MITM: a run point + macro rewrites a syscall's return value") {
    auto s = loaded();
    RunPoint rp;
    rp.type = RunPointType::Syscall;  // any syscall
    u64 id = s.add_run_point(std::move(rp));
    auto m = std::make_shared<Macro>();
    m->mutating = true;
    m->callback = [](IDebugController& c) { c.write_reg(Reg::Rax, 0xABCD, "mitm: forge return"); };
    s.bind_macro(id, m);
    s.run();
    CHECK_EQ(s.read_reg(Reg::Rax), 0xABCDu);  // the forged "response"

    // And because the edit went through the injected-event log, replay reproduces it.
    Tick end = s.now();
    s.seek(0);
    CHECK(s.read_reg(Reg::Rax) != 0xABCDu);
    s.seek(end);
    CHECK_EQ(s.read_reg(Reg::Rax), 0xABCDu);
}

int main() { return dede::test::run_all(); }
