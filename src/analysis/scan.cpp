// SPDX-License-Identifier: Apache-2.0
#include "dede/analysis/scan.hpp"

#include <algorithm>
#include <cmath>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <sstream>

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

class VmDispatchDetector final : public IDetector {
public:
    std::string name() const override { return "vm-dispatch"; }
    void inspect(const DecodedInsn& in, std::vector<Finding>& out) const override {
        // An indirect jmp/call (through a register or memory/jump-table) is the
        // signature of a VM dispatcher, a switch table, or a callback.
        if ((in.cf.is_branch || in.cf.is_call) && !in.operands.empty() &&
            in.operands[0].kind != OpKind::Imm) {
            const char* what = in.cf.is_call ? "indirect call (callback / vtable?)"
                                             : "indirect jump (VM dispatch / jump table?)";
            out.push_back({"obfuscation", what, in.addr, in.text(), "notice"});
        }
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

class PointerEncryptionDetector final : public IDetector {
public:
    std::string name() const override { return "pointer-encryption"; }
    void inspect(const DecodedInsn& in, std::vector<Finding>& out) const override {
        // Pointer mangling (glibc PTR_MANGLE, Windows Encode/DecodePointer) guards a
        // code/data pointer by combining it with a per-process/TLS cookie and
        // rotating it. The giveaway is a xor/add/sub/rotate against a segment-
        // relative (fs:/gs:) cookie, or a 64-bit rotate by the classic guard
        // amount (glibc uses `ror $0x11`).
        const bool combiner = is(in, "xor") || is(in, "add") || is(in, "sub") ||
                              is(in, "ror") || is(in, "rol");
        if (!combiner) return;
        const bool tls_cookie = in.op_str.find("fs:") != std::string::npos ||
                                in.op_str.find("gs:") != std::string::npos;
        if (tls_cookie) {
            // Combining a value with a TLS/segment cookie: pointer mangling
            // (PTR_MANGLE/EncodePointer) or a stack-canary check — same primitive.
            out.push_back({"pointer-encryption",
                           "TLS-cookie combine (pointer mangling / stack canary)",
                           in.addr, in.text(), "notice"});
            return;
        }
        // 64-bit rotate by 0x11 — the glibc pointer-guard rotation amount.
        if ((is(in, "ror") || is(in, "rol")) && in.operands.size() == 2 &&
            in.operands[0].size == 8 && in.operands[1].kind == OpKind::Imm &&
            in.operands[1].imm == 0x11)
            out.push_back({"pointer-encryption", "pointer-guard rotate (ror/rol $0x11)",
                           in.addr, in.text(), "info"});
    }
};

class ExceptionHandlerDetector final : public IDetector {
public:
    std::string name() const override { return "exception-handler"; }
    void inspect(const DecodedInsn& in, std::vector<Finding>& out) const override {
        // SEH-based protection manipulates the TIB ExceptionList at fs:[0] — the
        // 32-bit structured-exception chain head. The classic prologue saves the
        // old head (`mov eax, fs:[0]`) and installs a new frame (`mov fs:[0],
        // esp`). Both touch the absolute segment slot fs:[0] (disp 0, no base/
        // index), which distinguishes it from the stack canary / TLS cookie at
        // fs:[0x28]/fs:[0x30] (nonzero disp) handled by pointer-encryption.
        if (in.op_str.find("fs:") != std::string::npos)
            for (const auto& op : in.operands)
                if (op.kind == OpKind::Mem && !op.mem.has_base && !op.mem.has_index && op.mem.disp == 0) {
                    out.push_back({"exception-handler",
                                   "SEH frame access (fs:[0] TIB ExceptionList install/save)",
                                   in.addr, in.text(), "warning"});
                    return;
                }
        // Deliberate faults that drive an installed handler to redirect control
        // flow or detect a debugger (the handler sees/eats the exception).
        if (is(in, "ud2"))
            out.push_back({"exception-handler", "ud2 (deliberate #UD; exception-driven control flow)",
                           in.addr, in.text(), "notice"});
        else if (is(in, "int") && !in.operands.empty() && in.operands[0].kind == OpKind::Imm &&
                 in.operands[0].imm == 0x29)
            out.push_back({"exception-handler", "int 0x29 (__fastfail / exception-based guard)",
                           in.addr, in.text(), "warning"});
    }
};

const std::vector<std::unique_ptr<IDetector>>& detectors() {
    static std::vector<std::unique_ptr<IDetector>> d = [] {
        std::vector<std::unique_ptr<IDetector>> v;
        v.push_back(std::make_unique<AntiVmDetector>());
        v.push_back(std::make_unique<TimingDetector>());
        v.push_back(std::make_unique<AntiDebugDetector>());
        v.push_back(std::make_unique<CryptoDetector>());
        v.push_back(std::make_unique<VmDispatchDetector>());
        v.push_back(std::make_unique<PointerEncryptionDetector>());
        v.push_back(std::make_unique<ExceptionHandlerDetector>());
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

std::vector<Addr> unreachable_insns(Arch arch, const ByteReader& read, Addr entry, u64 range) {
    auto d = make_disassembler(arch);
    // All instruction starts from a linear sweep of the range.
    std::set<Addr> linear;
    auto bytes = read_run(read, entry, range);
    for (const auto& in : d->decode(bytes.data(), bytes.size(), entry, 0)) linear.insert(in.addr);
    // Reachable instruction starts, via the CFG from entry.
    std::set<Addr> reachable;
    for (const auto& bb : build_cfg(*d, read, entry).blocks)
        for (const auto& in : bb.insns) reachable.insert(in.addr);
    std::vector<Addr> dead;
    for (Addr a : linear)
        if (!reachable.count(a)) dead.push_back(a);
    return dead;
}

u32 crc32(const ByteReader& read, Addr addr, u64 len) {
    u32 crc = 0xffffffffu;
    for (u64 i = 0; i < len; ++i) {
        auto b = read(addr + i);
        if (!b) break;
        crc ^= *b;
        for (int k = 0; k < 8; ++k) crc = (crc >> 1) ^ (0xEDB88320u & (-(crc & 1)));
    }
    return ~crc;
}

u64 fnv1a(const ByteReader& read, Addr addr, u64 len) {
    u64 h = 1469598103934665603ull;
    for (u64 i = 0; i < len; ++i) {
        auto b = read(addr + i);
        if (!b) break;
        h ^= *b;
        h *= 1099511628211ull;
    }
    return h;
}

std::vector<Addr> recursive_functions(const CallGraph& g) {
    // Build adjacency and find nodes on a cycle (incl. direct self-calls) via DFS.
    std::map<Addr, std::vector<Addr>> adj;
    for (auto& [from, to] : g.calls) adj[from].push_back(to);
    std::set<Addr> result;
    for (const auto& n : g.funcs) {
        std::set<Addr> seen;
        std::deque<Addr> st{n.entry};
        bool first = true;
        while (!st.empty()) {
            Addr c = st.back(); st.pop_back();
            if (!first && c == n.entry) { result.insert(n.entry); break; }
            first = false;
            if (seen.count(c)) continue;
            seen.insert(c);
            for (Addr t : adj[c]) st.push_back(t);
        }
    }
    return {result.begin(), result.end()};
}

std::string to_json(const Cfg& cfg) {
    std::ostringstream o;
    o << "{\"entry\":" << cfg.entry << ",\"blocks\":[";
    for (std::size_t i = 0; i < cfg.blocks.size(); ++i) {
        const auto& b = cfg.blocks[i];
        o << "{\"start\":" << b.start << ",\"end\":" << b.end << ",\"insns\":" << b.insns.size()
          << ",\"terminal\":" << (b.terminates ? "true" : "false") << "}" << (i + 1 < cfg.blocks.size() ? "," : "");
    }
    o << "],\"edges\":[";
    for (std::size_t i = 0; i < cfg.edges.size(); ++i) {
        const auto& e = cfg.edges[i];
        o << "{\"from\":" << e.from << ",\"to\":" << e.to << ",\"kind\":\"" << to_string(e.kind)
          << "\"}" << (i + 1 < cfg.edges.size() ? "," : "");
    }
    o << "],\"calls\":[";
    for (std::size_t i = 0; i < cfg.calls.size(); ++i)
        o << "{\"from\":" << cfg.calls[i].first << ",\"callee\":" << cfg.calls[i].second << "}"
          << (i + 1 < cfg.calls.size() ? "," : "");
    o << "]}";
    return o.str();
}

std::string to_json(const CallGraph& g) {
    std::ostringstream o;
    o << "{\"funcs\":[";
    for (std::size_t i = 0; i < g.funcs.size(); ++i)
        o << "{\"entry\":" << g.funcs[i].entry << ",\"blocks\":" << g.funcs[i].blocks << "}"
          << (i + 1 < g.funcs.size() ? "," : "");
    o << "],\"calls\":[";
    for (std::size_t i = 0; i < g.calls.size(); ++i)
        o << "[" << g.calls[i].first << "," << g.calls[i].second << "]"
          << (i + 1 < g.calls.size() ? "," : "");
    o << "]}";
    return o.str();
}

std::string to_json(const std::vector<Finding>& findings) {
    std::ostringstream o;
    o << "[";
    for (std::size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        o << "{\"category\":\"" << f.category << "\",\"rule\":\"" << f.rule << "\",\"addr\":" << f.addr
          << ",\"severity\":\"" << f.severity << "\"}" << (i + 1 < findings.size() ? "," : "");
    }
    o << "]";
    return o.str();
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
        for (const auto& [caller_block, callee] : cfg.calls) {
            (void)caller_block;
            g.calls.emplace_back(f, callee);
            if (!seen.count(callee)) work.push_back(callee);
        }
    }
    return g;
}

}  // namespace dede
