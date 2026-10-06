// SPDX-License-Identifier: Apache-2.0
#include "dede/analysis/recover.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <map>
#include <optional>
#include <unordered_map>

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

std::optional<u64> read_u64(const ByteReader& read, Addr a) {
    u64 v = 0;
    for (unsigned i = 0; i < 8; ++i) {
        auto b = read(a + i);
        if (!b) return std::nullopt;
        v |= static_cast<u64>(*b) << (8 * i);
    }
    return v;
}

std::optional<Addr> direct_target(const DecodedInsn& in) {
    if (!in.operands.empty() && in.operands[0].kind == OpKind::Imm)
        return static_cast<Addr>(in.operands[0].imm);
    return std::nullopt;
}

// A short description of a memory operand's effective-address form.
std::string mem_desc(const MemOperand& m) {
    std::string s = "[";
    bool first = true;
    if (m.has_base) {
        s += std::string(reg_name(m.base));
        first = false;
    }
    if (m.has_index) {
        if (!first) s += "+";
        s += std::string(reg_name(m.index));
        if (m.scale != 1) s += "*" + std::to_string(m.scale);
        first = false;
    }
    if (m.disp || first) {
        char buf[32];
        if (m.disp < 0)
            std::snprintf(buf, sizeof buf, "-0x%llx", static_cast<unsigned long long>(-m.disp));
        else
            std::snprintf(buf, sizeof buf, "%s0x%llx", first ? "" : "+",
                          static_cast<unsigned long long>(m.disp));
        s += buf;
    }
    s += "]";
    return s;
}

// The normalized token of an instruction: mnemonic + the kind of each operand.
// Register renaming leaves this unchanged; mov-reg-imm and mov-reg-mem differ.
std::string normalize(const DecodedInsn& in) {
    std::string t = in.mnemonic;
    for (const auto& op : in.operands) {
        switch (op.kind) {
            case OpKind::Reg: t += " r"; break;
            case OpKind::Imm: t += " i"; break;
            case OpKind::Mem: t += " m"; break;
            case OpKind::SegReg: t += " s"; break;
            case OpKind::Xmm: t += " x"; break;
            case OpKind::None: t += " _"; break;
        }
    }
    return t;
}

}  // namespace

std::vector<Finding> scan_stack_strings(Arch arch, const ByteReader& read, Addr lo, Addr hi) {
    std::vector<Finding> out;
    if (hi <= lo) return out;
    auto d = make_disassembler(arch);
    auto bytes = read_run(read, lo, hi - lo);
    auto insns = d->decode(bytes.data(), bytes.size(), lo, 0);

    // Index instructions by address for body scans.
    std::map<Addr, std::size_t> idx;
    for (std::size_t i = 0; i < insns.size(); ++i) idx[insns[i].addr] = i;

    for (std::size_t i = 0; i < insns.size(); ++i) {
        const DecodedInsn& in = insns[i];
        if (!in.cf.is_cond_branch) continue;
        auto tgt = direct_target(in);
        if (!tgt || *tgt >= in.addr || *tgt < lo) continue;  // must be a backward edge (a loop)
        auto it = idx.find(*tgt);
        if (it == idx.end()) continue;
        std::size_t head = it->second;

        // Examine the loop body [head, i]. Short bodies only (a decrypt stub).
        if (i - head > 16) continue;
        bool has_xor = false;
        const MemOperand* store = nullptr;
        for (std::size_t j = head; j <= i; ++j) {
            const DecodedInsn& b = insns[j];
            // the "cipher" step: xor / not / rotate is the strong decrypt signal
            if (b.mnemonic == "xor" || b.mnemonic == "not" || b.mnemonic == "rol" ||
                b.mnemonic == "ror")
                has_xor = true;
            // a memory write: the destination (first) operand is memory
            if (!store && !b.operands.empty() && b.operands[0].kind == OpKind::Mem &&
                b.mnemonic != "cmp" && b.mnemonic != "test")
                store = &b.operands[0].mem;
        }
        if (has_xor && store) {
            out.push_back({"obfuscation", "stack-string xor-decrypt loop", *tgt,
                           "in-place decrypt loop writing buffer " + mem_desc(*store), "warning"});
        }
    }
    return out;
}

std::vector<CloneCluster> find_clones(Arch arch, const ByteReader& read,
                                      const std::vector<Addr>& func_entries,
                                      std::size_t window, std::size_t max_insns_per_func) {
    std::vector<CloneCluster> clusters;
    if (window == 0) return clusters;
    auto d = make_disassembler(arch);

    // Decode each function to a normalized-token vector (mnemonic + operand
    // kinds, so register renaming is invariant), truncated at its first ret.
    struct Fn { std::vector<u64> tok; std::vector<Addr> addr; };
    std::vector<Fn> fns(func_entries.size());
    for (std::size_t f = 0; f < func_entries.size(); ++f) {
        Addr entry = func_entries[f];
        auto bytes = read_run(read, entry, max_insns_per_func * 15 + 15);
        auto insns = d->decode(bytes.data(), bytes.size(), entry, max_insns_per_func);
        std::size_t n = insns.size();
        for (std::size_t k = 0; k < insns.size(); ++k)
            if (insns[k].cf.is_ret) { n = k + 1; break; }
        for (std::size_t k = 0; k < n; ++k) {
            fns[f].tok.push_back(std::hash<std::string>{}(normalize(insns[k])));
            fns[f].addr.push_back(insns[k].addr);
        }
    }

    // Union-find over clone sites (one entry per matched region start address).
    std::map<Addr, Addr> parent;
    std::function<Addr(Addr)> find = [&](Addr x) {
        parent.emplace(x, x);
        while (parent[x] != x) { parent[x] = parent[parent[x]]; x = parent[x]; }
        return x;
    };
    auto uni = [&](Addr a, Addr b) { parent[find(a)] = find(b); };
    std::map<Addr, std::size_t> run_len;  // longest run length anchored at a site

    // For every ordered pair of distinct functions, find maximal common
    // contiguous token runs of length >= window (seed by equality, then
    // extend). Rolling-hash seeding would prune the inner loop; the function
    // streams here are short enough to compare directly.
    for (std::size_t a = 0; a < fns.size(); ++a) {
        for (std::size_t b = a + 1; b < fns.size(); ++b) {
            const auto& A = fns[a];
            const auto& B = fns[b];
            for (std::size_t i = 0; i < A.tok.size(); ++i) {
                for (std::size_t j = 0; j < B.tok.size(); ++j) {
                    if (A.tok[i] != B.tok[j]) continue;
                    if (i > 0 && j > 0 && A.tok[i - 1] == B.tok[j - 1]) continue;  // not a run start
                    std::size_t len = 0;
                    while (i + len < A.tok.size() && j + len < B.tok.size() &&
                           A.tok[i + len] == B.tok[j + len])
                        ++len;
                    if (len < window) continue;
                    Addr sa = A.addr[i], sb = B.addr[j];
                    uni(sa, sb);
                    run_len[sa] = std::max(run_len[sa], len);
                    run_len[sb] = std::max(run_len[sb], len);
                }
            }
        }
    }

    // Gather connected components; a cluster is a component with >= 2 sites.
    std::map<Addr, std::vector<Addr>> comp;
    for (const auto& [site, _] : run_len) comp[find(site)].push_back(site);
    for (auto& [root, sites] : comp) {
        if (sites.size() < 2) continue;
        std::sort(sites.begin(), sites.end());
        std::size_t rl = 0;
        for (Addr s : sites) rl = std::max(rl, run_len[s]);
        clusters.push_back({static_cast<u64>(root), rl, sites});
    }
    std::sort(clusters.begin(), clusters.end(),
              [](const CloneCluster& x, const CloneCluster& y) {
                  if (x.sites.size() != y.sites.size()) return x.sites.size() > y.sites.size();
                  return x.sites.front() < y.sites.front();
              });
    return clusters;
}

std::string itanium_demangle_name(const std::string& m) {
    if (m.empty()) return "";
    std::size_t p = 0;
    bool nested = false;
    if (m[p] == 'N') { nested = true; ++p; }  // N...E nested name
    std::string out;
    bool any = false;
    while (p < m.size() && std::isdigit(static_cast<unsigned char>(m[p]))) {
        std::size_t len = 0;
        while (p < m.size() && std::isdigit(static_cast<unsigned char>(m[p])))
            len = len * 10 + static_cast<std::size_t>(m[p++] - '0');
        if (len == 0 || p + len > m.size()) return "";
        if (any) out += "::";
        out += m.substr(p, len);
        p += len;
        any = true;
        if (!nested) break;  // a single length-prefixed component
    }
    if (nested && p < m.size() && m[p] == 'E') ++p;
    return any ? out : "";
}

std::vector<Vtable> scan_vtables(const ByteReader& read, Addr lo, Addr hi,
                                 Addr code_lo, Addr code_hi, std::size_t min_slots) {
    std::vector<Vtable> out;
    auto is_code = [&](Addr a) { return a >= code_lo && a < code_hi; };

    Addr a = lo;
    while (a + 8 <= hi) {
        auto v = read_u64(read, a);
        if (!v || !is_code(*v)) { a += 8; continue; }
        // Start of a run of code pointers.
        Addr start = a;
        std::vector<Addr> slots;
        while (a + 8 <= hi) {
            auto s = read_u64(read, a);
            if (!s || !is_code(*s)) break;
            slots.push_back(*s);
            a += 8;
        }
        if (slots.size() >= min_slots) {
            Vtable vt;
            vt.addr = start;
            vt.slots = std::move(slots);
            // Itanium: the word before the first slot is the RTTI/type_info
            // pointer; type_info+8 points at the mangled class name string.
            if (start >= lo + 8) {
                if (auto ti = read_u64(read, start - 8); ti && *ti >= lo && *ti + 16 <= hi) {
                    if (auto np = read_u64(read, *ti + 8); np && *np >= lo && *np < hi) {
                        std::string raw;
                        for (u64 k = 0; k < 64; ++k) {
                            auto c = read(*np + k);
                            if (!c || *c == 0) break;
                            raw.push_back(static_cast<char>(*c));
                        }
                        vt.type_name = itanium_demangle_name(raw);
                    }
                }
            }
            out.push_back(std::move(vt));
        } else {
            a = start + 8;  // too short; resume one slot in
        }
    }
    return out;
}

}  // namespace dede
