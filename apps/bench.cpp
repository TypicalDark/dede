// SPDX-License-Identifier: Apache-2.0
//
// Micro-benchmark of the per-instruction hot path: raw interpreter stepping vs.
// stepping with full time-travel recording, and the effect of a large mapped
// footprint (which the snapshot-reuse optimisation is designed to keep cheap).
#include <chrono>
#include <cstdio>
#include <vector>

#include "dede/core/execution_core.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;
using clock_t_ = std::chrono::steady_clock;

namespace {
// mov rcx, N ; loop: dec rcx ; jnz loop ; hlt   (2 instructions per iteration)
std::vector<u8> loop_prog(u32 n) {
    std::vector<u8> c = {0x48, 0xC7, 0xC1, 0, 0, 0, 0,  // mov rcx, N
                         0x48, 0xFF, 0xC9,              // dec rcx
                         0x75, 0xFB,                    // jnz loop
                         0xF4};                         // hlt
    for (int i = 0; i < 4; ++i) c[3 + i] = static_cast<u8>((n >> (8 * i)) & 0xff);
    return c;
}

double mips(u64 instrs, double secs) { return (instrs / 1e6) / secs; }
}  // namespace

int main() {
    const u32 N = 2'000'000;  // ~4M instructions
    std::printf("dede micro-benchmark (loop of %u iterations, 2 insns each)\n\n", N);

    // --- raw core, no recording --------------------------------------------
    {
        ExecutionCore core;
        core.memory().map(0x1000, 0x1000, perm::RWX);
        core.memory().write(0x1000, loop_prog(N));
        core.cpu().set_rip(0x1000);
        auto t0 = clock_t_::now();
        StepOutcome o;
        do { o = core.step(); } while (o.status == StepOutcome::Status::Ok);
        double s = std::chrono::duration<double>(clock_t_::now() - t0).count();
        std::printf("  raw interpreter (no time-travel): %8llu insns in %6.3fs = %6.1f MIPS\n",
                    (unsigned long long)core.tick(), s, mips(core.tick(), s));
    }

    // --- full session with time-travel recording, small footprint ----------
    auto run_session = [&](unsigned pages, const char* label) {
        AnalysisSession s(Arch::X86_64);
        s.map(0x1000, pages * kPageSize, perm::RWX);
        s.load(0x1000, loop_prog(N), perm::RWX);
        // Touch each extra page once so they are resident (stresses snapshotting).
        for (unsigned p = 1; p < pages; ++p) s.core().memory().write8(0x1000 + p * kPageSize, 1);
        s.set_entry(0x1000);
        auto t0 = clock_t_::now();
        s.run(10'000'000);
        double sec = std::chrono::duration<double>(clock_t_::now() - t0).count();
        auto ts = s.timeline_stats();
        std::printf("  %-38s %8llu insns in %6.3fs = %6.1f MIPS  (ring=%zu snap=%zu)\n",
                    label, (unsigned long long)s.now(), sec, mips(s.now(), sec), ts.ring, ts.snapshots);
    };
    run_session(2, "time-travel, 2 pages mapped:");
    run_session(256, "time-travel, 256 pages mapped:");

    std::printf("\n(snapshot reuse keeps the 256-page case close to the 2-page case —\n"
                " non-writing steps share one memory snapshot instead of copying the map.)\n");
    return 0;
}
