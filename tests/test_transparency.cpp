// SPDX-License-Identifier: Apache-2.0
#include "check.hpp"
#include "dede/transparency/interceptor.hpp"

using namespace dede;

TEST("chain forges a clean cpuid vendor and clears the hypervisor bit") {
    auto chain = make_transparency_chain(ForgedEnvironment{});
    ProbeResult v = chain->handle(ProbeRequest{ProbeRequest::Kind::Cpuid, 0, 0, 0, 0});
    CHECK(v.handled);
    // ebx/edx/ecx spell "GenuineIntel".
    CHECK_EQ(v.b, 0x756e6547u);  // "Genu"
    CHECK_EQ(v.d, 0x49656e69u);  // "ineI"
    CHECK_EQ(v.c, 0x6c65746eu);  // "ntel"

    ProbeResult f = chain->handle(ProbeRequest{ProbeRequest::Kind::Cpuid, 1, 0, 0, 0});
    CHECK(f.handled);
    CHECK_EQ((f.c >> 31) & 1u, 0u);  // hypervisor-present bit cleared
}

TEST("hypervisor cpuid leaf range is hidden") {
    auto chain = make_transparency_chain(ForgedEnvironment{});
    ProbeResult r = chain->handle(ProbeRequest{ProbeRequest::Kind::Cpuid, 0x40000000, 0, 0, 0});
    CHECK(r.handled);
    CHECK_EQ(r.a, 0u);
    CHECK_EQ(r.b, 0u);
}

TEST("rdtsc is deterministic in the instruction count") {
    ForgedEnvironment env;
    auto chain = make_transparency_chain(env);
    ProbeResult a = chain->handle(ProbeRequest{ProbeRequest::Kind::Rdtsc, 0, 0, 0, 100});
    ProbeResult b = chain->handle(ProbeRequest{ProbeRequest::Kind::Rdtsc, 0, 0, 0, 100});
    CHECK(a.handled);
    CHECK_EQ(a.a, b.a);  // same tick -> same tsc (replay-safe), despite jitter
    CHECK_EQ(a.d, b.d);
    u64 tsc = (static_cast<u64>(a.d) << 32) | a.a;
    u64 lo = env.tsc_base + 100 * env.tsc_per_insn;
    CHECK(tsc >= lo && tsc < lo + env.tsc_jitter);  // base cost + deterministic jitter

    // Jitter makes consecutive deltas vary (defeats zero-variance checks) while
    // the clock stays strictly monotonic.
    u64 t0 = 0, prev = 0;
    bool monotonic = true, varies = false;
    for (Tick k = 1; k < 50; ++k) {
        ProbeResult r = chain->handle(ProbeRequest{ProbeRequest::Kind::Rdtsc, 0, 0, 0, k});
        u64 t = (static_cast<u64>(r.d) << 32) | r.a;
        if (k > 1) {
            u64 d = t - prev;
            if (t <= prev) monotonic = false;
            if (d != env.tsc_per_insn) varies = true;
        }
        prev = t; (void)t0;
    }
    CHECK(monotonic);
    CHECK(varies);
}

TEST("vmware backdoor port is silenced") {
    auto chain = make_transparency_chain(ForgedEnvironment{});
    ProbeResult r = chain->handle(ProbeRequest{ProbeRequest::Kind::IoIn, 0, 0, 0x5658, 0});
    CHECK(r.handled);
    CHECK_EQ(r.a, 0u);
}

TEST("unhandled probe falls through the chain") {
    auto chain = make_transparency_chain(ForgedEnvironment{});
    ProbeResult r = chain->handle(ProbeRequest{ProbeRequest::Kind::RdMsr, 0, 0, 0x1234, 0});
    CHECK(!r.handled);  // an ordinary MSR is not forged
}

int main() { return dede::test::run_all(); }
