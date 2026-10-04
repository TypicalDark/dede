// SPDX-License-Identifier: Apache-2.0
//
// The concrete interceptors and the factory that wires them into a chain. Each
// interceptor targets one family of anti-analysis probe and forges a bare-metal
// answer; probes it does not recognise it passes along by returning false.
#include <cstring>

#include "dede/transparency/interceptor.hpp"

namespace dede {
namespace {

// cpuid: forge vendor/feature leaves with the hypervisor bit clear, and hide the
// hypervisor leaf range so a sample never learns it is virtualised.
class CpuidInterceptor final : public IInterceptor {
public:
    explicit CpuidInterceptor(const ForgedEnvironment& env) : env_(env) {}
    std::string name() const override { return "cpuid"; }

    bool handle(const ProbeRequest& req, ProbeResult& out) override {
        if (req.kind != ProbeRequest::Kind::Cpuid) return false;
        u32 leaf = static_cast<u32>(req.leaf);

        if (leaf == 0) {
            out.a = env_.max_leaf;
            pack_vendor(env_.vendor, out.b, out.d, out.c);
            return true;
        }
        if (leaf == 1) {
            out.a = env_.leaf1_eax;
            out.b = 0;
            out.c = env_.leaf1_ecx & ~(1u << 31);  // force hypervisor-present off
            out.d = env_.leaf1_edx;
            return true;
        }
        if (env_.hide_hypervisor_leaf && (leaf & 0xffff0000u) == 0x40000000u) {
            out.a = out.b = out.c = out.d = 0;  // no hypervisor interface
            return true;
        }
        return false;  // other leaves: let the core's default stand
    }

private:
    static void pack_vendor(const std::string& v, u64& b, u64& d, u64& c) {
        char buf[12] = {0};
        std::memcpy(buf, v.data(), v.size() < 12 ? v.size() : 12);
        auto rd = [&](int off) {
            u32 x;
            std::memcpy(&x, buf + off, 4);
            return static_cast<u64>(x);
        };
        b = rd(0); d = rd(4); c = rd(8);
    }
    ForgedEnvironment env_;
};

// rdtsc: a smooth deterministic clock, so single-step timing checks see normal
// small deltas instead of the huge gaps instrumentation introduces.
class RdtscInterceptor final : public IInterceptor {
public:
    explicit RdtscInterceptor(const ForgedEnvironment& env) : env_(env) {}
    std::string name() const override { return "rdtsc"; }

    bool handle(const ProbeRequest& req, ProbeResult& out) override {
        if (req.kind != ProbeRequest::Kind::Rdtsc) return false;
        u64 tsc = env_.tsc_base + req.tick * env_.tsc_per_insn;
        out.a = tsc & 0xffffffffull;  // eax
        out.d = tsc >> 32;            // edx
        return true;
    }

private:
    ForgedEnvironment env_;
};

// sidt/sgdt: hand back a believable bare-metal descriptor-table base, defeating
// the classic "red pill" that flags high VM addresses.
class DescriptorTableInterceptor final : public IInterceptor {
public:
    explicit DescriptorTableInterceptor(const ForgedEnvironment& env) : env_(env) {}
    std::string name() const override { return "sidt/sgdt"; }

    bool handle(const ProbeRequest& req, ProbeResult& out) override {
        if (req.kind != ProbeRequest::Kind::Sidt) return false;
        out.a = env_.idt_base & 0xffffffffull;
        out.d = env_.idt_base >> 32;
        out.b = env_.gdt_base & 0xffffffffull;
        out.c = env_.gdt_base >> 32;
        return true;
    }

private:
    ForgedEnvironment env_;
};

// MSR reads a sample uses to spot a hypervisor (e.g. the x2APIC/HV MSR range).
class MsrInterceptor final : public IInterceptor {
public:
    std::string name() const override { return "msr"; }

    bool handle(const ProbeRequest& req, ProbeResult& out) override {
        if (req.kind != ProbeRequest::Kind::RdMsr) return false;
        // Hypervisor synthetic MSRs (0x4000'0000+) read as zero / #GP-free here.
        if ((req.arg & 0xffff0000u) == 0x40000000u) {
            out.a = out.d = 0;
            return true;
        }
        return false;
    }
};

// I/O ports: deny the VMware backdoor so its magic handshake yields nothing.
class IoInterceptor final : public IInterceptor {
public:
    explicit IoInterceptor(const ForgedEnvironment& env) : env_(env) {}
    std::string name() const override { return "io"; }

    bool handle(const ProbeRequest& req, ProbeResult& out) override {
        if (req.kind != ProbeRequest::Kind::IoIn) return false;
        if ((req.arg & 0xffff) == env_.vmware_backdoor_port) {
            out.a = out.b = out.c = out.d = 0;  // backdoor silent
            return true;
        }
        return false;
    }

private:
    ForgedEnvironment env_;
};

}  // namespace

std::unique_ptr<TransparencyChain> make_transparency_chain(ForgedEnvironment env) {
    auto chain = std::make_unique<TransparencyChain>();
    chain->append(std::make_unique<CpuidInterceptor>(env));
    chain->append(std::make_unique<RdtscInterceptor>(env));
    chain->append(std::make_unique<DescriptorTableInterceptor>(env));
    chain->append(std::make_unique<MsrInterceptor>());
    chain->append(std::make_unique<IoInterceptor>(env));
    return chain;
}

}  // namespace dede
