// SPDX-License-Identifier: Apache-2.0
//
// Batch 9 (T9.5/T9.6): the deterministic multi-context scheduler runs several
// threads over one shared address space, records the schedule, and replays it
// bit-for-bit.
#include <vector>

#include "check.hpp"
#include "dede/core/execution_core.hpp"
#include "dede/core/scheduler.hpp"

using namespace dede;

namespace {
constexpr Addr kCode = 0x1000;
constexpr Addr kCounter = 0x5000;

// A thread body that increments the shared qword at 0x5000, rcx times:
//   loop: inc qword [0x5000] ; dec rcx ; jnz loop ; hlt
// inc qword [abs]: 48 FF 04 25 00 50 00 00   dec rcx: 48 FF C9   jnz -13: 75 F3   hlt: F4
const std::vector<u8> kIncLoop = {
    0x48, 0xFF, 0x04, 0x25, 0x00, 0x50, 0x00, 0x00,  // inc qword ptr [0x5000]
    0x48, 0xFF, 0xC9,                                // dec rcx
    0x75, 0xF3,                                      // jnz loop (-13)
    0xF4                                             // hlt
};

CpuState thread_cpu(u64 count, u64 rsp) {
    CpuState c;
    c.set_rip(kCode);
    c.set(Reg::Rcx, count);
    c.set(Reg::Rsp, rsp);
    return c;
}
}  // namespace

TEST("two threads over shared memory: deterministic schedule + bit-identical replay") {
    ExecutionCore core;
    core.memory().map(kCode, 0x1000, perm::RX);
    core.memory().write(kCode, kIncLoop);
    core.memory().map(kCounter & ~0xfffULL, 0x1000, perm::RW);  // shared data page

    auto before = core.snapshot();  // whole-machine restore point for replay

    DeterministicScheduler sched(core, /*quantum=*/5);
    int t0 = sched.add_context(thread_cpu(10, 0x8000));  // thread 0: +10
    int t1 = sched.add_context(thread_cpu(7, 0x8100));   // thread 1: +7
    CHECK_EQ(sched.context_count(), 2);

    sched.run();
    CHECK(sched.all_halted());
    CHECK(sched.halted(t0));
    CHECK(sched.halted(t1));
    // the shared counter saw every increment from both threads (10 + 7 = 17)
    CHECK_EQ(core.memory().read_int(kCounter, 8).value(), 17u);
    // both threads finished with rcx == 0
    CHECK_EQ(sched.context_cpu(t0).get(Reg::Rcx), 0u);
    CHECK_EQ(sched.context_cpu(t1).get(Reg::Rcx), 0u);
    // the schedule actually interleaved the two contexts (more than 2 segments)
    CHECK(sched.schedule().size() > 2u);
    bool saw0 = false, saw1 = false;
    for (const auto& s : sched.schedule()) { saw0 |= s.ctx == 0; saw1 |= s.ctx == 1; }
    CHECK(saw0 && saw1);

    // replay from the same restore point reproduces the identical interleaving
    // and both threads' final register files bit-for-bit.
    CHECK(sched.replay(before));
    CHECK_EQ(core.memory().read_int(kCounter, 8).value(), 17u);  // and the shared result
}

TEST("a third thread (spawned context) joins the shared computation") {
    ExecutionCore core;
    core.memory().map(kCode, 0x1000, perm::RX);
    core.memory().write(kCode, kIncLoop);
    core.memory().map(kCounter & ~0xfffULL, 0x1000, perm::RW);

    DeterministicScheduler sched(core, 3);
    sched.add_context(thread_cpu(4, 0x8000));
    sched.add_context(thread_cpu(4, 0x8100));
    sched.add_context(thread_cpu(4, 0x8200));  // CreateThread/clone analog
    CHECK_EQ(sched.context_count(), 3);
    sched.run();
    CHECK(sched.all_halted());
    CHECK_EQ(core.memory().read_int(kCounter, 8).value(), 12u);  // 3 threads x 4
}

int main() { return dede::test::run_all(); }
