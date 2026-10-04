// SPDX-License-Identifier: Apache-2.0
//
// Proves the interpreter executes real x86-64 machine code and that the Memento
// snapshot/restore round-trips machine state.
#include <vector>

#include "check.hpp"
#include "dede/core/execution_core.hpp"

using namespace dede;

namespace {

// A loop summing 3+2+1 into rax, then hlt:
//   mov rax, 0 ; mov rcx, 3 ; loop: add rax,rcx ; dec rcx ; jnz loop ; hlt
const std::vector<u8> kSumLoop = {
    0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,  // mov rax, 0
    0x48, 0xC7, 0xC1, 0x03, 0x00, 0x00, 0x00,  // mov rcx, 3
    0x48, 0x01, 0xC8,                          // add rax, rcx
    0x48, 0xFF, 0xC9,                          // dec rcx
    0x75, 0xF8,                                // jnz -8
    0xF4                                       // hlt
};

constexpr Addr kBase = 0x1000;

void load(ExecutionCore& c, const std::vector<u8>& code) {
    c.memory().map(kBase, 0x1000, perm::RX);
    c.memory().write(kBase, code);
    c.cpu().set_rip(kBase);
}

StepOutcome run_to_halt(ExecutionCore& c, int budget = 1000) {
    StepOutcome o;
    for (int i = 0; i < budget; ++i) {
        o = c.step();
        if (o.status != StepOutcome::Status::Ok) return o;
    }
    return o;
}

}  // namespace

TEST("interpreter runs a real x86-64 sum loop") {
    ExecutionCore core;
    load(core, kSumLoop);
    auto o = run_to_halt(core);
    CHECK(o.status == StepOutcome::Status::Halted);
    CHECK_EQ(core.cpu().get(Reg::Rax), 6u);
    CHECK_EQ(core.cpu().get(Reg::Rcx), 0u);
}

TEST("Memento snapshot/restore round-trips the machine") {
    ExecutionCore core;
    load(core, kSumLoop);
    // Single-step past the two movs so rax=0, rcx=3.
    core.step();
    core.step();
    CHECK_EQ(core.cpu().get(Reg::Rcx), 3u);
    Tick t0 = core.tick();
    StateMemento snap = core.snapshot();

    run_to_halt(core);
    CHECK_EQ(core.cpu().get(Reg::Rax), 6u);

    core.restore(snap);
    CHECK_EQ(core.cpu().get(Reg::Rcx), 3u);
    CHECK_EQ(core.cpu().get(Reg::Rax), 0u);
    CHECK_EQ(core.tick(), t0);

    // Re-running from the restored memento reproduces the result deterministically.
    run_to_halt(core);
    CHECK_EQ(core.cpu().get(Reg::Rax), 6u);
}

TEST("cpuid default masks the hypervisor-present bit") {
    // cpuid with eax=1 ; hlt
    std::vector<u8> code = {0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
                            0x0F, 0xA2,                    // cpuid
                            0xF4};                         // hlt
    ExecutionCore core;
    load(core, code);
    run_to_halt(core);
    // ECX bit 31 (hypervisor present) must be clear in the forged default CPU.
    CHECK_EQ((core.cpu().get(Reg::Rcx) >> 31) & 1u, 0u);
}

int main() { return dede::test::run_all(); }
