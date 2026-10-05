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

TEST("div computes quotient and remainder (unsigned)") {
    // xor edx,edx; mov eax,17; mov ecx,5; div ecx; hlt  -> eax=3, edx=2
    ExecutionCore core;
    load(core, {0x31,0xD2, 0xB8,0x11,0,0,0, 0xB9,0x05,0,0,0, 0xF7,0xF1, 0xF4});
    auto o = run_to_halt(core);
    CHECK(o.status == StepOutcome::Status::Halted);
    CHECK_EQ(core.cpu().get(Reg::Rax) & 0xffffffffu, 3u);
    CHECK_EQ(core.cpu().get(Reg::Rdx) & 0xffffffffu, 2u);
}

TEST("idiv with cdq handles a negative dividend") {
    // mov eax,-17; cdq; mov ecx,5; idiv ecx; hlt  -> eax=-3 (quot), edx=-2 (rem)
    ExecutionCore core;
    load(core, {0xB8,0xEF,0xFF,0xFF,0xFF, 0x99, 0xB9,0x05,0,0,0, 0xF7,0xF9, 0xF4});
    auto o = run_to_halt(core);
    CHECK(o.status == StepOutcome::Status::Halted);
    CHECK_EQ((int)(core.cpu().get(Reg::Rax) & 0xffffffffu), -3);
    CHECK_EQ((int)(core.cpu().get(Reg::Rdx) & 0xffffffffu), -2);
}

TEST("divide by zero raises a Fault (#DE)") {
    // xor edx,edx; mov eax,10; mov ecx,0; div ecx; hlt  -> #DE at the div
    ExecutionCore core;
    load(core, {0x31,0xD2, 0xB8,0x0A,0,0,0, 0xB9,0,0,0,0, 0xF7,0xF1, 0xF4});
    auto o = run_to_halt(core);
    CHECK(o.status == StepOutcome::Status::Fault);  // caught, not executed as garbage
}

TEST("idiv quotient overflow (INT64_MIN / -1) raises a Fault, no UB") {
    // mov rdx,0x8000000000000000; xor rax,rax; mov rcx,-1; idiv rcx; hlt
    // 128-bit dividend == INT128_MIN, divisor == -1 -> #DE (overflow), not UB.
    ExecutionCore core;
    load(core, {0x48,0xBA,0,0,0,0,0,0,0,0x80, 0x48,0x31,0xC0,
                0x48,0xC7,0xC1,0xFF,0xFF,0xFF,0xFF, 0x48,0xF7,0xF9, 0xF4});
    auto o = run_to_halt(core);
    CHECK(o.status == StepOutcome::Status::Fault);
}

int main() { return dede::test::run_all(); }
