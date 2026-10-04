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
    CHECK_EQ(a.a, b.a);  // same tick -> same tsc (replay-safe)
    CHECK_EQ(a.d, b.d);
    u64 tsc = (static_cast<u64>(a.d) << 32) | a.a;
    CHECK_EQ(tsc, env.tsc_base + 100 * env.tsc_per_insn);
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
