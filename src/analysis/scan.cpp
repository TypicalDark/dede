// SPDX-License-Identifier: Apache-2.0
#include "dede/analysis/scan.hpp"

#include <algorithm>
#include <cmath>
#include <deque>
#include <memory>
#include <set>

namespace dede {

namespace {
std::vector<u8> read_run(const ByteReader& read, Addr a, u64 len) {
    std::vector<u8> v;
    v.reserve(len);
    for (u64 i = 0; i < len; ++i) {
        auto b = read(a + i);
        if (!b) break;
        v.push_back(*b);
    }
    return v;
}
}  // namespace

double shannon_entropy(const ByteReader& read, Addr addr, u64 len) {
    u64 counts[256] = {0};
    u64 total = 0;
    for (u64 i = 0; i < len; ++i) {
        auto b = read(addr + i);
        if (!b) continue;
        counts[*b]++;
        ++total;
    }
    if (!total) return 0.0;
    double h = 0.0;
    for (u64 c : counts) {
        if (!c) continue;
        double p = static_cast<double>(c) / total;
        h -= p * std::log2(p);
    }
    return h;  // 0 (uniform) .. 8 (max, e.g. encrypted/compressed)
}

std::vector<std::pair<std::string, u64>> opcode_histogram(Arch arch, const ByteReader& read,
                                                          Addr addr, std::size_t count) {
    auto d = make_disassembler(arch);
    auto bytes = read_run(read, addr, count * 15 + 15);
    auto insns = d->decode(bytes.data(), bytes.size(), addr, count);
    std::map<std::string, u64> freq;
    for (const auto& in : insns) freq[in.mnemonic]++;
    std::vector<std::pair<std::string, u64>> out(freq.begin(), freq.end());
    std::sort(out.begin(), out.end(), [](auto& a, auto& b) { return a.second > b.second; });
    return out;
}

std::vector<FoundString> extract_strings(const ByteReader& read, Addr addr, u64 len,
                                         std::size_t min_len) {
    std::vector<FoundString> out;
    std::string cur;
    Addr start = addr;
    for (u64 i = 0; i <= len; ++i) {
        auto b = (i < len) ? read(addr + i) : std::optional<u8>{};
        u8 c = b ? *b : 0;
        bool printable = b && c >= 0x20 && c < 0x7f;
        if (printable) {
            if (cur.empty()) start = addr + i;
            cur.push_back(static_cast<char>(c));
        } else {
            if (cur.size() >= min_len) out.push_back({start, cur});
            cur.clear();
        }
    }
    return out;
}

int cyclomatic_complexity(const Cfg& cfg) {
    int n = static_cast<int>(cfg.blocks.size());
    int e = static_cast<int>(cfg.edges.size());
    return n > 0 ? (e - n + 2) : 0;  // McCabe, single component
}

// --- detectors --------------------------------------------------------------
namespace {

bool is(const DecodedInsn& in, const char* m) { return in.mnemonic == m; }

class AntiVmDetector final : public IDetector {
public:
    std::string name() const override { return "anti-vm"; }
    void inspect(const DecodedInsn& in, std::vector<Finding>& out) const override {
        if (is(in, "cpuid")) out.push_back({"anti-vm", "cpuid (hypervisor/vendor probe)", in.addr, in.text(), "warning"});
        else if (is(in, "sidt")) out.push_back({"anti-vm", "sidt (Red Pill)", in.addr, in.text(), "warning"});
        else if (is(in, "sgdt")) out.push_back({"anti-vm", "sgdt (No Pill)", in.addr, in.text(), "warning"});
        else if (is(in, "sldt") || is(in, "str")) out.push_back({"anti-vm", "sldt/str descriptor probe", in.addr, in.text(), "notice"});
        else if (is(in, "smsw")) out.push_back({"anti-vm", "smsw (CR0 probe)", in.addr, in.text(), "notice"});
        else if (is(in, "in") || is(in, "out")) out.push_back({"anti-vm", "port I/O (VMware backdoor?)", in.addr, in.text(), "notice"});
    }
};

class TimingDetector final : public IDetector {
public:
    std::string name() const override { return "timing"; }
    void inspect(const DecodedInsn& in, std::vector<Finding>& out) const override {
        if (is(in, "rdtsc") || is(in, "rdtscp"))
            out.push_back({"timing", "rdtsc timing check", in.addr, in.text(), "warning"});
        if (is(in, "rdpmc")) out.push_back({"timing", "rdpmc perf-counter read", in.addr, in.text(), "notice"});
    }
};

class AntiDebugDetector final : public IDetector {
public:
    std::string name() const override { return "anti-debug"; }
    void inspect(const DecodedInsn& in, std::vector<Finding>& out) const override {
        if (is(in, "int3")) out.push_back({"anti-debug", "int3 (self-breakpoint / scan)", in.addr, in.text(), "notice"});
        else if (is(in, "int") && !in.operands.empty() && in.operands[0].kind == OpKind::Imm &&
                 in.operands[0].imm == 0x2d)
            out.push_back({"anti-debug", "int 0x2d (debugger probe)", in.addr, in.text(), "warning"});
        else if (is(in, "pushfq") || is(in, "pushf") || is(in, "popfq") || is(in, "popf"))
            out.push_back({"anti-debug", "flags manipulation (trap-flag trick?)", in.addr, in.text(), "info"});
        else if (is(in, "rdmsr") || is(in, "wrmsr"))
            out.push_back({"anti-debug", "MSR access (hypervisor/debug probe)", in.addr, in.text(), "notice"});
    }
};

class CryptoDetector final : public IDetector {
public:
    std::string name() const override { return "crypto"; }
    void inspect(const DecodedInsn& in, std::vector<Finding>& out) const override {
        // xor of a register/memory by a non-zero immediate is the classic in-line
        // decrypt primitive; xor reg,reg (zeroing) is excluded.
        if (is(in, "xor") && in.operands.size() == 2 && in.operands[1].kind == OpKind::Imm &&
            in.operands[1].imm != 0)
            out.push_back({"crypto", "xor by immediate (decrypt stub?)", in.addr, in.text(), "notice"});
        else if (is(in, "rol") || is(in, "ror"))
            out.push_back({"crypto", "rotate (cipher primitive?)", in.addr, in.text(), "info"});
        else if (is(in, "aesenc") || is(in, "aesdec") || is(in, "aesimc") || is(in, "aeskeygenassist"))
            out.push_back({"crypto", "AES-NI instruction", in.addr, in.text(), "warning"});
    }
};

const std::vector<std::unique_ptr<IDetector>>& detectors() {
    static std::vector<std::unique_ptr<IDetector>> d = [] {
        std::vector<std::unique_ptr<IDetector>> v;
        v.push_back(std::make_unique<AntiVmDetector>());
        v.push_back(std::make_unique<TimingDetector>());
        v.push_back(std::make_unique<AntiDebugDetector>());
        v.push_back(std::make_unique<CryptoDetector>());
        return v;
    }();
    return d;
}

}  // namespace

std::vector<Finding> detect(Arch arch, const ByteReader& read, Addr addr, std::size_t count) {
    auto d = make_disassembler(arch);
    auto bytes = read_run(read, addr, count * 15 + 15);
    auto insns = d->decode(bytes.data(), bytes.size(), addr, count);
    std::vector<Finding> out;
    for (const auto& in : insns)
        for (const auto& det : detectors()) det->inspect(in, out);
    return out;
}

std::vector<std::string> detector_names() {
    std::vector<std::string> n;
    for (const auto& d : detectors()) n.push_back(d->name());
    return n;
}

CallGraph build_call_graph(Arch arch, const ByteReader& read, Addr entry, std::size_t max_funcs) {
    auto d = make_disassembler(arch);
    CallGraph g;
    std::set<Addr> seen;
    std::deque<Addr> work{entry};
    while (!work.empty() && g.funcs.size() < max_funcs) {
        Addr f = work.front();
        work.pop_front();
        if (seen.count(f)) continue;
        seen.insert(f);
        Cfg cfg = build_cfg(*d, read, f);
        g.funcs.push_back({f, cfg.blocks.size()});
        for (const auto& e : cfg.edges)
            if (e.kind == EdgeKind::Call) {
                g.calls.emplace_back(f, e.to);
                if (!seen.count(e.to)) work.push_back(e.to);
            }
    }
    return g;
}

}  // namespace dede
