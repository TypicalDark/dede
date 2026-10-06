// SPDX-License-Identifier: Apache-2.0
//
// Batch 8: the SSE/SSE2 subset in the interpreter evaluates bit-identically to
// hand-computed float/vector results, and a small float-using sample runs.
#include <bit>
#include <cstring>
#include <vector>

#include "check.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

namespace {
u64 db(double d) { return std::bit_cast<u64>(d); }
double bd(u64 u) { return std::bit_cast<double>(u); }

// Run one SSE instruction with xmm0/xmm1 (and rax) seeded; return the session.
AnalysisSession run1(const std::vector<u8>& code, CpuState::Xmm x0, CpuState::Xmm x1, u64 rax = 0) {
    AnalysisSession s(Arch::X86_64);
    s.map(0x1000, 0x1000, perm::RWX);
    s.map(0x2000, 0x1000, perm::RW);
    s.load(0x1000, code, perm::RWX);
    s.set_entry(0x1000);
    s.core().cpu().set_xmm(0, x0);
    s.core().cpu().set_xmm(1, x1);
    s.core().cpu().set(Reg::Rax, rax);
    s.core().cpu().set(Reg::Rdi, 0x2000);
    s.step();
    return s;
}
}  // namespace

TEST("scalar double arithmetic is bit-exact") {
    CpuState::Xmm a{db(3.5), 0xdead}, b{db(2.0), 0xbeef};
    CHECK_EQ(run1({0xF2, 0x0F, 0x58, 0xC1}, a, b).core().cpu().get_xmm(0).lo, db(5.5));   // addsd
    CHECK_EQ(run1({0xF2, 0x0F, 0x5C, 0xC1}, a, b).core().cpu().get_xmm(0).lo, db(1.5));   // subsd
    CHECK_EQ(run1({0xF2, 0x0F, 0x59, 0xC1}, a, b).core().cpu().get_xmm(0).lo, db(7.0));   // mulsd
    CHECK_EQ(run1({0xF2, 0x0F, 0x5E, 0xC1}, a, b).core().cpu().get_xmm(0).lo, db(1.75));  // divsd
    // the upper quadword of the destination is preserved by a scalar op
    CHECK_EQ(run1({0xF2, 0x0F, 0x58, 0xC1}, a, b).core().cpu().get_xmm(0).hi, 0xdeadu);
}

TEST("int<->double conversions round-trip") {
    // cvtsi2sd xmm0, rax  (rax = 42) -> xmm0.lo == bits(42.0)
    auto s = run1({0xF2, 0x48, 0x0F, 0x2A, 0xC0}, {0, 0}, {0, 0}, 42);
    CHECK_EQ(s.core().cpu().get_xmm(0).lo, db(42.0));
    // cvttsd2si rax, xmm0  (xmm0 = 3.9) -> rax == 3 (truncating)
    auto s2 = run1({0xF2, 0x48, 0x0F, 0x2C, 0xC0}, {db(3.9), 0}, {0, 0});
    CHECK_EQ(s2.core().cpu().get(Reg::Rax), 3u);
}

TEST("packed-integer add and bitwise xor") {
    // paddd xmm0, xmm1 — four 32-bit lanes added independently
    CpuState::Xmm a{0x0000000200000001ull, 0x0000000400000003ull};
    CpuState::Xmm b{0x0000001000000010ull, 0x0000001000000010ull};
    auto s = run1({0x66, 0x0F, 0xFE, 0xC1}, a, b);
    CHECK_EQ(s.core().cpu().get_xmm(0).lo, 0x0000001200000011ull);
    CHECK_EQ(s.core().cpu().get_xmm(0).hi, 0x0000001400000013ull);
    // pxor xmm0, xmm1
    auto x = run1({0x66, 0x0F, 0xEF, 0xC1}, {0xffffffffffffffffull, 0x00ff00ff00ff00ffull},
                  {0x0f0f0f0f0f0f0f0full, 0xffffffffffffffffull});
    CHECK_EQ(x.core().cpu().get_xmm(0).lo, 0xf0f0f0f0f0f0f0f0ull);
    CHECK_EQ(x.core().cpu().get_xmm(0).hi, 0xff00ff00ff00ff00ull);
}

TEST("ucomisd sets EFLAGS like the hardware") {
    auto flags = [](double x, double y) {
        auto s = run1({0x66, 0x0F, 0x2E, 0xC1}, {db(x), 0}, {db(y), 0});
        const CpuState& c = s.core().cpu();
        return std::make_tuple(c.flag(flags::ZF), c.flag(flags::PF), c.flag(flags::CF));
    };
    CHECK(flags(2.0, 1.0) == std::make_tuple(false, false, false));  // a > b
    CHECK(flags(1.0, 2.0) == std::make_tuple(false, false, true));   // a < b
    CHECK(flags(2.0, 2.0) == std::make_tuple(true, false, false));   // a == b
    double nan = std::bit_cast<double>(0x7ff8000000000000ull);
    CHECK(flags(nan, 1.0) == std::make_tuple(true, true, true));     // unordered
}

TEST("movsd through memory round-trips and a float sample runs") {
    // movsd [rdi], xmm0 ; then movsd xmm1, [rdi]  -> xmm1.lo == xmm0.lo
    AnalysisSession s(Arch::X86_64);
    s.map(0x1000, 0x1000, perm::RWX);
    s.map(0x2000, 0x1000, perm::RW);
    // movsd [rdi],xmm0 (F2 0F 11 07); movsd xmm1,[rdi] (F2 0F 10 0F); hlt
    s.load(0x1000, {0xF2, 0x0F, 0x11, 0x07, 0xF2, 0x0F, 0x10, 0x0F, 0xF4}, perm::RWX);
    s.set_entry(0x1000);
    s.core().cpu().set(Reg::Rdi, 0x2000);
    s.core().cpu().set_xmm(0, {db(6.25), 0});
    s.run();
    CHECK_EQ(s.core().cpu().get_xmm(1).lo, db(6.25));
    CHECK(bd(s.core().cpu().get_xmm(1).lo) == 6.25);
}

int main() { return dede::test::run_all(); }
